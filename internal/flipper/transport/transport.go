// Package transport defines the byte-channel substrate the Flipper CLI layer
// operates over.
//
// The command layer in internal/flipper (serial.go, commands.go) used to
// talk to a *go.bug.st/serial.Port directly. That made adding BLE (or any
// non-USB transport) a rewrite of the prompt framing / reconnect code. The
// Transport interface defined here is the seam that lets the CLI layer
// stay ignorant of the physical medium.
//
// Three implementations live in this package today:
//
//   - serialTransport  — USB CDC-ACM via go.bug.st/serial. The only
//     production transport.
//   - mockTransport    — raw pty slave via os.OpenFile. Used by the test
//     harness in internal/flipper/mock.
//   - bleDialer        — reserved scheme; returns ErrNotImplemented until
//     the Phase-B BLE work lands.
//
// Transports are identified by URL. A Dialer registered under a scheme
// name parses the URL and produces a fresh (not-yet-dialled) Transport.
// Open is the public entry point: it looks up the scheme and returns the
// Transport; callers then invoke Transport.Dial to establish the link.
//
// Concurrency: Transport methods are NOT safe for concurrent use by
// themselves — the Flipper command layer serialises all access behind
// f.mu. Implementations may assume single-caller-at-a-time semantics.
package transport

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"context"
)

// Transport is a bidirectional byte stream with best-effort reconnect
// semantics.
//
// Read returns available bytes, blocking up to the transport's internal
// read timeout (for serial, ~500 ms; set via go.bug.st/serial). A zero
// return with nil error means "no bytes yet" — callers should loop, the
// same pattern serial.Port.Read follows. This mirrors the current
// prompt-polling logic in serial.go unchanged.
//
// Close is idempotent; subsequent calls return nil or an error describing
// why the close already happened.
type Transport interface {
	io.ReadWriteCloser

	// Dial establishes the connection. Blocking; must honour ctx
	// cancellation. On success the Transport is ready for Read/Write.
	// On failure the Transport is left unusable — do not call Dial
	// twice on the same instance; use Reconnect for that.
	Dial(ctx context.Context) error

	// Reconnect tears down the current link and re-establishes it.
	// Used by the flipper command layer's recovery path when the
	// remote prompt stops responding or the fd returns a disconnect-
	// class error. ctx governs the whole operation.
	Reconnect(ctx context.Context) error

	// Identity returns a stable, human-readable identifier for logging
	// and /status output (e.g. "/dev/ttyACM0" or
	// "ble://AA:BB:CC:DD:EE:FF"). Must not contain newlines.
	Identity() string

	// DrainTimeout is the transport's preferred "wait for remote
	// silence" interval used by the flipper drain loop. Serial uses
	// ~100 ms between post-command drain reads; BLE will likely need
	// longer because notifications batch.
	DrainTimeout() time.Duration

	// Kind returns a short telemetry tag — one of "serial", "ble",
	// "mock". Used for metrics labelling and /status output.
	Kind() string

	// SetReadTimeout reconfigures how long the next Read will block
	// before returning (0, nil). Preserves the existing serial.Port
	// SetReadTimeout surface that serial.go's drain() and handshake()
	// rely on to poll ctx without indefinite blocking.
	SetReadTimeout(d time.Duration) error
}

// Dialer parses a URL and produces a fresh (not-yet-dialled) Transport.
//
// Supported URL schemes:
//
//	serial:///dev/ttyACM0?baud=230400   — USB CDC-ACM
//	mock:///dev/pts/5                   — test harness pty slave
//	ble://AA:BB:CC:DD:EE:FF             — reserved; Phase-B follow-up
//
// A Dialer must NOT block; network I/O belongs in Transport.Dial. Dialer
// failure indicates a malformed URL, not a connection problem.
type Dialer func(rawURL string) (Transport, error)

// ErrNotImplemented is returned by reserved-scheme Dialers (currently
// "ble") until their real implementation lands. Callers can use
// errors.Is to detect "the scheme exists but the work to make it go
// hasn't been done yet" versus a genuine unknown-scheme error.
var ErrNotImplemented = errors.New("transport: not implemented")

var (
	registryMu sync.RWMutex
	registry   = map[string]Dialer{}
)

// Register associates a scheme with its Dialer. Calling Register with
// the same scheme twice overwrites the first registration — this is
// intentional so tests can stub a scheme in place, and also so init()
// ordering between siblings in this package is not load-bearing.
func Register(scheme string, d Dialer) {
	if scheme == "" || d == nil {
		panic("transport.Register: scheme and dialer must be non-empty")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[scheme] = d
}

// Open looks up the scheme in rawURL and invokes its registered Dialer.
// The returned Transport is NOT yet dialled — callers follow up with
// Transport.Dial(ctx).
//
// rawURL may be either a URL with an explicit scheme or a bare file
// path (e.g. "/dev/ttyACM0"); a bare path is implicitly treated as
// "serial://<path>" so existing call sites that pass a device node
// keep working.
func Open(rawURL string) (Transport, error) {
	scheme, _ := splitScheme(rawURL)
	if scheme == "" {
		// Bare path → default to serial. Keeps legacy callers
		// (and the test harness which passes /dev/pts/N) working
		// unchanged.
		scheme = "serial"
		rawURL = "serial://" + rawURL
	}
	registryMu.RLock()
	d, ok := registry[scheme]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("transport: unknown scheme %q in URL %q", scheme, rawURL)
	}
	return d(rawURL)
}

// splitScheme returns the scheme prefix of rawURL (everything before
// "://"), or "" if no scheme is present. We don't use net/url.Parse for
// this because device paths like "/dev/ttyACM0" are valid but parse to
// an empty scheme, and we want a single helper that treats them the
// same way regardless.
func splitScheme(rawURL string) (string, string) {
	idx := strings.Index(rawURL, "://")
	if idx <= 0 {
		return "", rawURL
	}
	return rawURL[:idx], rawURL[idx+3:]
}

// parseURL is a shared helper used by the built-in dialers to extract
// path + query from a "<scheme>://<path>?k=v" URL. It tolerates the
// path containing an absolute device node like "/dev/ttyACM0".
func parseURL(rawURL string) (path string, q url.Values, err error) {
	_, rest := splitScheme(rawURL)
	if rest == "" {
		return "", nil, fmt.Errorf("transport: empty path in URL %q", rawURL)
	}
	// Split off the query string (if any). net/url.Parse mangles
	// device paths because "/dev/..." looks like a network path.
	if qi := strings.Index(rest, "?"); qi >= 0 {
		qs := rest[qi+1:]
		rest = rest[:qi]
		q, err = url.ParseQuery(qs)
		if err != nil {
			return "", nil, fmt.Errorf("transport: parsing query %q: %w", qs, err)
		}
	} else {
		q = url.Values{}
	}
	return rest, q, nil
}
