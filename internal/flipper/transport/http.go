package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// http.go — HTTP transport scheme.
//
// Targets jblanked/FlipperHTTP-compatible servers (or any service that
// proxies the Flipper's USB-serial CLI to HTTP). The scheme decouples
// PromptZero from the physical USB session, enabling remote engagements
// and cloud-deployed agents that drive a Flipper hosted on a remote
// gateway.
//
// # Wire protocol
//
// Two endpoints, both rooted at the configured base URL:
//
//   POST <base>/uart/send
//     Request body:    raw bytes (the bytes the agent would have written
//                      to the USB serial port).
//     Response status: 204 on success.
//
//   GET  <base>/uart/recv?max=<n>&timeout_ms=<t>
//     Returns up to n bytes of buffered output from the Flipper. The
//     server long-polls for up to timeout_ms; an empty 200 response
//     means no data within the window.
//
// Both endpoints accept an optional Bearer token in the Authorization
// header for operator-curated authentication. Implemented per the
// FlipperHTTP project's documented surface; if your bridge uses a
// different shape, configure path overrides via the URL query string:
//
//   http://host:8080/?send_path=/api/cli/send&recv_path=/api/cli/recv
//
// # Concurrency
//
// Like the other transports, http.Read / http.Write are not safe for
// concurrent use. The Flipper command layer serialises access behind
// f.mu — implementations may assume single-caller-at-a-time semantics.

const (
	defaultHTTPSendPath    = "/uart/send"
	defaultHTTPRecvPath    = "/uart/recv"
	defaultHTTPReadTimeout = 500 * time.Millisecond
	defaultHTTPRecvBatch   = 4096

	// maxHTTPRecvResponseBytes caps a single recv() body. The server
	// is asked to return at most `batch` bytes (default 4 KiB,
	// configurable via ?batch=N up to this ceiling) — but a misbehaving
	// or compromised proxy could return more. The cap is well above
	// any plausible per-chunk size while preventing an unbounded body
	// from buffering into t.pending on a single recv call.
	maxHTTPRecvResponseBytes = 16 << 20 // 16 MiB

	// maxHTTPRecvLongPollMs caps the per-recv long-poll window the
	// operator can request via ?timeout_ms=N. The Read() path waits
	// up to readTimeout + 5s for the server to respond, so an
	// uncapped value (timeout_ms=999_999_999) would block every recv
	// for hundreds of hours and starve the dispatch layer. 60 s is
	// well above any reasonable long-poll need (most reverse proxies
	// time out connections well below this) and short enough that a
	// misconfigured URL surfaces quickly at dial time rather than
	// silently wedging the transport. Mirrors the dial-time validation
	// pattern v0.139 added for ?batch=.
	maxHTTPRecvLongPollMs = 60_000
)

func init() { //nolint:gochecknoinits
	Register("http", httpDialer)
	Register("https", httpDialer)
}

// httpDialer parses a {http,https}://host:port/?send_path=…&recv_path=…&token=…
// URL and returns an undialled transport.
//
// Recognised query parameters (all optional):
//
//	send_path    overrides /uart/send
//	recv_path    overrides /uart/recv
//	token        bearer token (Authorization: Bearer <token>)
//	timeout_ms   per-recv long-poll window (default 500)
//	batch        max bytes per recv (default 4096)
func httpDialer(rawURL string) (Transport, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("transport: parsing http URL %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("transport: empty host in URL %q", rawURL)
	}
	q := u.Query()

	t := &httpTransport{
		base:        baseURLFromParsed(u),
		sendPath:    valueOr(q, "send_path", defaultHTTPSendPath),
		recvPath:    valueOr(q, "recv_path", defaultHTTPRecvPath),
		token:       q.Get("token"),
		readTimeout: defaultHTTPReadTimeout,
		batch:       defaultHTTPRecvBatch,
		client: &http.Client{
			// One client-level timeout; per-request deadlines come from ctx.
			Timeout: 0,
			Transport: &http.Transport{
				MaxIdleConns:        4,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
	if v := q.Get("timeout_ms"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil || ms < 0 {
			return nil, fmt.Errorf("transport: invalid timeout_ms=%q in URL %q", v, rawURL)
		}
		// Enforce the maxHTTPRecvLongPollMs ceiling at dial time.
		// Without it, an operator typo like `timeout_ms=999999999`
		// dialled successfully and silently wedged every recv for
		// hundreds of hours. Mirrors the v0.139 batch ceiling fix.
		if ms > maxHTTPRecvLongPollMs {
			return nil, fmt.Errorf("transport: timeout_ms=%d exceeds the %d-ms ceiling in URL %q", ms, maxHTTPRecvLongPollMs, rawURL)
		}
		t.readTimeout = time.Duration(ms) * time.Millisecond
	}
	if v := q.Get("batch"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("transport: invalid batch=%q in URL %q", v, rawURL)
		}
		// Enforce the ceiling the maxHTTPRecvResponseBytes constant
		// promises in its docstring ("configurable via ?batch=N up to
		// this ceiling"). Pre-this-fix the dialer accepted any positive
		// int, but a batch above the response cap silently broke every
		// Read with "response exceeded cap" — the transport dialled
		// successfully and then errored on every subsequent recv. Fail
		// loud at dial time so misconfigured URLs surface at startup,
		// matching the negative-batch reject above.
		if n > maxHTTPRecvResponseBytes {
			return nil, fmt.Errorf("transport: batch=%d exceeds the %d-byte ceiling in URL %q", n, maxHTTPRecvResponseBytes, rawURL)
		}
		t.batch = n
	}
	return t, nil
}

// baseURLFromParsed builds the rooted URL (scheme + host + path) without
// the query string, so we can safely append path suffixes per request.
func baseURLFromParsed(u *url.URL) string {
	root := u.Scheme + "://" + u.Host
	if p := strings.TrimSuffix(u.Path, "/"); p != "" {
		root += p
	}
	return root
}

func valueOr(q url.Values, key, def string) string {
	if v := q.Get(key); v != "" {
		return v
	}
	return def
}

// httpTransport bridges the Flipper CLI byte stream over a request/poll
// HTTP API. Each Read makes a long-polling GET; each Write makes a POST.
// Bytes pending in the recv buffer (because the Flipper produced more
// than the last Read consumed) are stored in `pending` so the next Read
// drains locally first.
type httpTransport struct {
	base        string // protocol://host[:port][/prefix]
	sendPath    string
	recvPath    string
	token       string
	readTimeout time.Duration
	batch       int

	client *http.Client

	mu      sync.Mutex
	dialled bool
	closed  bool
	pending []byte // unread bytes from prior recv
}

// Dial probes the configured base URL by issuing a zero-byte recv. The
// goal is to surface auth / connectivity errors at the same point in
// the lifecycle as the serial transport's Open. A 200 or 204 means the
// bridge is alive; any other status means we cannot proceed.
func (t *httpTransport) Dial(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dialled {
		return fmt.Errorf("transport: http already dialled (%s)", t.base)
	}
	if t.closed {
		return errors.New("transport: http already closed")
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := t.recvRequest(probeCtx, 0, 50*time.Millisecond)
	if err != nil {
		return err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("transport: http probe %s%s: %w", t.base, t.recvPath, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		// Drain probe body so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		t.dialled = true
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("transport: http probe %s rejected (HTTP %d) — check token query param", t.base, resp.StatusCode)
	default:
		return fmt.Errorf("transport: http probe %s returned HTTP %d", t.base, resp.StatusCode)
	}
}

// Reconnect is a no-op-with-validation for HTTP — there is no socket to
// reopen. We simply re-probe to confirm the bridge is still alive. Useful
// when the Flipper command layer detects unresponsiveness and wants to
// confirm the upstream is healthy before retrying.
func (t *httpTransport) Reconnect(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("transport: http closed")
	}
	t.dialled = false
	t.pending = nil
	t.mu.Unlock()
	return t.Dial(ctx)
}

// Read returns up to len(p) bytes from the Flipper. Drains any pending
// bytes from the previous recv first; otherwise issues a fresh long-poll.
func (t *httpTransport) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if !t.dialled {
		t.mu.Unlock()
		return 0, errors.New("transport: http not dialled")
	}

	// Drain pending first.
	if len(t.pending) > 0 {
		n := copy(p, t.pending)
		t.pending = t.pending[n:]
		t.mu.Unlock()
		return n, nil
	}
	timeout := t.readTimeout
	batch := t.batch
	t.mu.Unlock()

	// Long-poll a fresh chunk.
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()
	req, err := t.recvRequest(ctx, batch, timeout)
	if err != nil {
		return 0, err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("transport: http recv: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPRecvResponseBytes+1))
	if err != nil {
		return 0, fmt.Errorf("transport: http recv body: %w", err)
	}
	if int64(len(body)) > maxHTTPRecvResponseBytes {
		return 0, fmt.Errorf("transport: http recv response exceeded %d-byte cap; refusing to buffer", maxHTTPRecvResponseBytes)
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		// fine
	default:
		return 0, fmt.Errorf("transport: http recv returned HTTP %d: %s", resp.StatusCode, snippet(body))
	}
	if len(body) == 0 {
		// No data within the long-poll window — return (0, nil) to
		// match the serial.Port idiom; callers should loop.
		return 0, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	n := copy(p, body)
	if n < len(body) {
		t.pending = append(t.pending, body[n:]...)
	}
	return n, nil
}

// Write streams len(p) bytes to the Flipper via POST. Returns once the
// server acknowledges (201/204) or fails.
func (t *httpTransport) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if !t.dialled {
		t.mu.Unlock()
		return 0, errors.New("transport: http not dialled")
	}
	t.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := t.sendRequest(ctx, p)
	if err != nil {
		return 0, err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("transport: http send: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
		_, _ = io.Copy(io.Discard, resp.Body)
		return len(p), nil
	default:
		// snippet() will trim to 256 bytes anyway; cap the read at
		// 8 KiB so a hostile / misbehaving server returning a giant
		// error page can't blow memory just to produce an error
		// message we then truncate.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return 0, fmt.Errorf("transport: http send returned HTTP %d: %s", resp.StatusCode, snippet(body))
	}
}

// Close marks the transport as closed; future Read/Write fail with
// io.ErrClosedPipe. The HTTP client itself has no socket to close —
// it pools idle connections that the runtime will reap on idle timeout.
func (t *httpTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.dialled = false
	t.pending = nil
	t.client.CloseIdleConnections()
	return nil
}

// SetReadTimeout reconfigures how long the next recv will long-poll
// before returning empty.
func (t *httpTransport) SetReadTimeout(d time.Duration) error {
	if d < 0 {
		return fmt.Errorf("transport: negative timeout %v", d)
	}
	t.mu.Lock()
	t.readTimeout = d
	t.mu.Unlock()
	return nil
}

func (t *httpTransport) Identity() string            { return t.base }
func (t *httpTransport) DrainTimeout() time.Duration { return 200 * time.Millisecond }
func (t *httpTransport) Kind() string                { return "http" }

func (t *httpTransport) sendRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+t.sendPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("transport: build send request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	return req, nil
}

func (t *httpTransport) recvRequest(ctx context.Context, max int, timeout time.Duration) (*http.Request, error) {
	q := url.Values{}
	if max > 0 {
		q.Set("max", strconv.Itoa(max))
	}
	if timeout > 0 {
		q.Set("timeout_ms", strconv.FormatInt(timeout.Milliseconds(), 10))
	}
	u := t.base + t.recvPath
	if encoded := q.Encode(); encoded != "" {
		u += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("transport: build recv request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	return req, nil
}

func snippet(b []byte) string {
	const max = 256
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...[truncated]"
}

// HTTPHealthResponse is the optional JSON payload an operator's HTTP
// bridge MAY return at GET /health for diagnostic UIs. PromptZero does
// not consume it — callers that want richer health checks should issue
// a manual probe through the agent's flipper_raw_cli passthrough.
type HTTPHealthResponse struct {
	Bridge       string    `json:"bridge"`
	FlipperPort  string    `json:"flipper_port"`
	Connected    bool      `json:"connected"`
	LastActivity time.Time `json:"last_activity,omitempty"`
}

// MarshalJSON forces a stable shape on the response (in case future
// fields are added — JSON tag stability is part of the contract).
func (h HTTPHealthResponse) MarshalJSON() ([]byte, error) {
	type alias HTTPHealthResponse
	return json.Marshal(alias(h))
}
