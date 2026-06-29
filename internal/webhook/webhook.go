// Package webhook dispatches PromptZero lifecycle events as outbound HTTP
// POSTs. Operators configure per-event subscriptions in config.yaml
// (`webhooks:`) and events fire non-blocking from the agent's callbacks —
// tool completion, risk prompts, workflow completion, audit-critical rows,
// session lifecycle.
//
// The dispatcher queues events to a bounded buffer, retries 5xx/transport
// errors with exponential backoff, and signs the body with HMAC-SHA256
// when a per-subscription secret is set. Close(ctx) drains the queue so
// shutdown doesn't lose the trailing session_ended payload.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xunholy/promptzero/internal/obs"
)

// Event is one of the seven lifecycle hooks a subscription can filter on.
// An empty Events list on a subscription means "all events".
type Event string

const (
	EventToolFinished      Event = "tool_finished"
	EventRiskPrompted      Event = "risk_prompted"
	EventRiskDenied        Event = "risk_denied"
	EventWorkflowCompleted Event = "workflow_completed"
	EventAuditCritical     Event = "audit_critical"
	EventSessionStarted    Event = "session_started"
	EventSessionEnded      Event = "session_ended"
)

// knownEvents lists every value Event may take. Used by
// ValidateSubscription to reject typos in YAML config (e.g.
// `events: [tool_finsished]`) at load time rather than letting
// the subscription silently never fire.
var knownEvents = map[Event]struct{}{
	EventToolFinished:      {},
	EventRiskPrompted:      {},
	EventRiskDenied:        {},
	EventWorkflowCompleted: {},
	EventAuditCritical:     {},
	EventSessionStarted:    {},
	EventSessionEnded:      {},
	EventRuleFired:         {},
}

// KnownEventNames returns the canonical list of event names sorted
// alphabetically. Useful for error messages and `/webhooks` help
// output so operators don't have to grep the source.
func KnownEventNames() []string {
	out := make([]string, 0, len(knownEvents))
	for e := range knownEvents {
		out = append(out, string(e))
	}
	sort.Strings(out)
	return out
}

// Subscription is one configured HTTP webhook target. A zero Events slice
// opts into every event; a non-empty slice is an allowlist.
type Subscription struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Events  []Event           `yaml:"events"`
	Headers map[string]string `yaml:"headers"`
	Secret  string            `yaml:"secret"`
}

// SendResult is the outcome of a single delivery attempt — used by /webhooks
// to render a short history per subscription.
type SendResult struct {
	Event      Event
	At         time.Time
	StatusCode int
	Err        error
}

// Dispatcher is the fire-and-forget interface the rest of the app sees.
// Fire never blocks (drops with a warning when the queue overflows).
type Dispatcher interface {
	Fire(ev Event, payload any)
	// FireByName delivers a payload to a single subscription identified
	// by its `name:` field, bypassing the Events allowlist filter that
	// Fire applies. Used by the rules engine where the operator's intent
	// (`webhook: ops-pager` in a rule's then-block) is "deliver to this
	// specific subscription" rather than "broadcast on this event type".
	// Subscriptions without a matching name are silent — the call is
	// fire-and-forget like Fire. The synthesised event tag is "rule_fired"
	// so the receiver can still distinguish rule-driven deliveries from
	// natural lifecycle events.
	FireByName(name string, payload any)
	Close(ctx context.Context) error
	Subscriptions() []Subscription
	RecentResults(name string) []SendResult
	TestSubscription(ctx context.Context, name string) error
}

// dispatcher is the production Dispatcher backed by a worker pool.
type dispatcher struct {
	subs    []Subscription
	client  *http.Client
	queue   chan job
	wg      sync.WaitGroup
	closed  chan struct{}
	closeMu sync.Mutex

	resultsMu sync.Mutex
	results   map[string][]SendResult
}

type job struct {
	ev      Event
	payload any
	ts      time.Time
	// targetName, when non-empty, restricts delivery to the single
	// subscription with that exact name and bypasses the Events
	// allowlist filter. Set by FireByName for rule-driven deliveries.
	targetName string
}

// EventRuleFired is the synthetic event tag the worker stamps on
// envelopes produced by FireByName. Receivers use it to distinguish
// rule-driven deliveries (one specific subscription) from natural
// lifecycle events (fan-out by Events filter).
const EventRuleFired Event = "rule_fired"

// queueCapacity is the buffered channel size. Bursts beyond this drop with
// a logged warning — keeps agent callbacks non-blocking under webhook
// outages.
const queueCapacity = 256

// recentResultLimit is the rolling window of per-subscription results kept
// in memory for /webhooks introspection.
const recentResultLimit = 3

// workerCount controls parallelism of outbound POSTs. Four is ample for the
// event rates PromptZero produces (dominated by tool calls, typically
// << 1/s).
const workerCount = 4

// ValidateSubscription rejects subscription URLs that point at
// loopback, link-local, or RFC1918 destinations — webhook payloads
// carry tool inputs/outputs (potentially including captured
// credentials), so SSRF into the cloud-metadata endpoint
// (169.254.169.254), local Kubernetes API, or peer services on the
// host network is in scope.
//
// To target an internal endpoint deliberately, set
// PROMPTZERO_WEBHOOK_ALLOW_INTERNAL=1 — the rejection becomes a warning.
//
// Validation runs at config-load time so a misconfigured URL fails
// loudly instead of leaking on first event.
func ValidateSubscription(s Subscription) error {
	if s.URL == "" {
		return fmt.Errorf("webhook %q: URL is required", s.Name)
	}
	u, err := url.Parse(s.URL)
	if err != nil {
		return fmt.Errorf("webhook %q: invalid URL: %w", s.Name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook %q: scheme must be http or https, got %q", s.Name, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("webhook %q: missing host", s.Name)
	}
	// Refuse private destinations unless explicitly allowed.
	if isInternalHost(host) && !internalAllowed() {
		return fmt.Errorf(
			"webhook %q: refusing internal/loopback target %q "+
				"(set PROMPTZERO_WEBHOOK_ALLOW_INTERNAL=1 to override)",
			s.Name, host)
	}
	// Validate the events allowlist. An empty Events slice means
	// "every event" (existing semantics). A non-empty slice with an
	// unknown member would silently never fire — better to fail loud
	// at load time so the operator can fix the typo.
	for _, e := range s.Events {
		if _, ok := knownEvents[e]; !ok {
			return fmt.Errorf("webhook %q: unknown event %q (allowed: %s)",
				s.Name, e, strings.Join(KnownEventNames(), ", "))
		}
	}
	return nil
}

// isInternalHost returns true when host is a literal IP in a private,
// loopback, or link-local range, OR a name that resolves only to such
// addresses. Hostnames that resolve to a public IP pass — operators
// regularly point webhooks at SaaS receivers via DNS.
func isInternalHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return isInternalIP(ip)
	}
	// Hostname: resolve and check every result. If any single answer
	// is public, allow — DNS rebinding via mid-flight repointing is
	// out of scope (config-load-time check).
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		// Unresolvable at config time; defer to runtime — better to
		// fail open here than reject a valid name during a
		// transient DNS hiccup.
		return false
	}
	for _, a := range addrs {
		if !isInternalIP(a) {
			return false
		}
	}
	return true
}

// cgnatRange is RFC 6598's carrier-grade NAT block (100.64.0.0/10).
// Go's net.IP.IsPrivate covers RFC1918 only — not CGNAT, which some
// on-prem deployments route to internal services. A webhook pointed
// at 100.64.x.x would otherwise bypass the SSRF guard.
var cgnatRange = net.IPNet{
	IP:   net.IPv4(100, 64, 0, 0),
	Mask: net.CIDRMask(10, 32),
}

// ipv6SiteLocalRange is RFC 3879's deprecated site-local IPv6 prefix
// (fec0::/10). Officially deprecated but some legacy systems still
// route it to internal services; defense-in-depth includes it in
// the internal-IP block-list. Go's IsPrivate / IsLinkLocalUnicast
// helpers don't flag fec0::*.
var ipv6SiteLocalRange = net.IPNet{
	IP:   net.IP{0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	Mask: net.CIDRMask(10, 128),
}

func isInternalIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		// IsMulticast covers every multicast scope — link-local
		// (ff02::), site-local (ff05::), org-local (ff08::), and
		// IPv4 multicast 224.0.0.0/4. The narrower
		// IsLinkLocalMulticast used pre-v0.170 caught only
		// ff02::, leaving ff05:: and ff08:: as bypass vectors
		// for LAN-multicast SSRF.
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		// IsPrivate doesn't currently flag the AWS / GCP / Azure
		// metadata link-local /32. IsLinkLocalUnicast covers
		// 169.254.0.0/16 which includes 169.254.169.254 — defensive
		// double-check for clarity.
		ip.Equal(net.IPv4(169, 254, 169, 254)) ||
		cgnatRange.Contains(ip) ||
		ipv6SiteLocalRange.Contains(ip)
}

func internalAllowed() bool {
	v := strings.TrimSpace(strings.ToLower(getenv("PROMPTZERO_WEBHOOK_ALLOW_INTERNAL")))
	return v == "1" || v == "true" || v == "yes"
}

// getenv is var-stored so tests can swap. Production reads os.Getenv.
var getenv = os.Getenv

// New constructs a dispatcher. When subs is empty it returns a no-op
// dispatcher so callers don't branch on nil.
func New(subs []Subscription) Dispatcher {
	d := &dispatcher{
		subs: subs,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Re-apply the SSRF guard on every redirect hop. ValidateSubscription
			// only vets the configured URL; without this, a configured receiver
			// (compromised, or an open-redirect endpoint) could 30x the
			// credential-bearing envelope to an internal/loopback/metadata target
			// like 169.254.169.254. CheckRedirect fires BEFORE the redirected
			// request is sent, so a rejected hop never reaches the internal host.
			// Mirrors signal_import's allowlist re-check; honours the same
			// internalAllowed() opt-out as config-time validation. We supply our
			// own redirect cap because setting CheckRedirect replaces net/http's
			// default 10-hop limit.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return fmt.Errorf("webhook redirect to non-http(s) scheme %q refused", req.URL.Scheme)
				}
				if isInternalHost(req.URL.Hostname()) && !internalAllowed() {
					return fmt.Errorf("webhook redirect to internal/loopback target %q refused", req.URL.Hostname())
				}
				return nil
			},
		},
		queue:   make(chan job, queueCapacity),
		closed:  make(chan struct{}),
		results: map[string][]SendResult{},
	}
	for i := 0; i < workerCount; i++ {
		d.wg.Add(1)
		go d.worker()
	}
	return d
}

// Fire enqueues an event for delivery. Payload is marshaled to JSON by the
// worker; pass any structure with a natural JSON shape.
//
// Safe to call concurrently with Close. closeMu serialises the closed-check
// and the channel send so a late Fire racing past `<-d.closed` cannot
// observe an open `d.queue` and then panic on a `send on closed channel`
// once Close completes. Each critical section is bounded — the inner select
// has a `default` so a saturated queue drops rather than blocks.
func (d *dispatcher) Fire(ev Event, payload any) {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	select {
	case <-d.closed:
		return
	default:
	}
	select {
	case d.queue <- job{ev: ev, payload: payload, ts: time.Now().UTC()}:
	default:
		obs.Default().Warn("webhook_queue_overflow", "capacity", queueCapacity, "event", ev)
	}
}

// FireByName enqueues a delivery targeting the single subscription
// whose name matches. The Events allowlist on that subscription is
// bypassed — the rule's intent IS the filter. Subscriptions without
// a matching name are silent (the call is fire-and-forget).
//
// Same closeMu discipline as Fire — protects against the
// `send on closed channel` panic when Close runs concurrently.
func (d *dispatcher) FireByName(name string, payload any) {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	select {
	case <-d.closed:
		return
	default:
	}
	select {
	case d.queue <- job{ev: EventRuleFired, payload: payload, ts: time.Now().UTC(), targetName: name}:
	default:
		obs.Default().Warn("webhook_queue_overflow", "capacity", queueCapacity, "target", name)
	}
}

// Close drains the queue and waits for workers to finish. The ctx bounds
// the drain — a stuck endpoint won't block shutdown forever.
func (d *dispatcher) Close(ctx context.Context) error {
	d.closeMu.Lock()
	select {
	case <-d.closed:
		d.closeMu.Unlock()
		return nil
	default:
		close(d.closed)
		close(d.queue)
	}
	d.closeMu.Unlock()
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Subscriptions returns a copy of the configured subscription list —
// intended for /webhooks rendering.
func (d *dispatcher) Subscriptions() []Subscription {
	out := make([]Subscription, len(d.subs))
	copy(out, d.subs)
	return out
}

// RecentResults returns the rolling result window for one subscription.
func (d *dispatcher) RecentResults(name string) []SendResult {
	d.resultsMu.Lock()
	defer d.resultsMu.Unlock()
	if r, ok := d.results[name]; ok {
		out := make([]SendResult, len(r))
		copy(out, r)
		return out
	}
	return nil
}

// TestSubscription fires a synthetic session_started payload to the named
// subscription and blocks until the POST completes or ctx fires. Used by
// /webhooks test.
func (d *dispatcher) TestSubscription(ctx context.Context, name string) error {
	for _, s := range d.subs {
		if s.Name != name {
			continue
		}
		payload := map[string]interface{}{"test": true, "note": "synthetic from /webhooks test"}
		body := Envelope{Event: EventSessionStarted, Timestamp: time.Now().UTC(), Payload: payload}
		return d.postWithRetry(ctx, s, body)
	}
	return fmt.Errorf("no subscription named %q", name)
}

// Envelope is the JSON body shape every subscription receives.
type Envelope struct {
	Event     Event     `json:"event"`
	Timestamp time.Time `json:"ts"`
	Payload   any       `json:"payload"`
}

func (d *dispatcher) worker() {
	defer d.wg.Done()
	for j := range d.queue {
		body := Envelope{Event: j.ev, Timestamp: j.ts, Payload: j.payload}
		for _, s := range d.subs {
			// Targeted delivery (FireByName) bypasses the Events
			// allowlist and matches by subscription name only.
			// Untargeted (Fire) keeps the historic broadcast-with-
			// Events-filter semantics.
			if j.targetName != "" {
				if s.Name != j.targetName {
					continue
				}
			} else if !subscribed(s, j.ev) {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			err := d.postWithRetry(ctx, s, body)
			cancel()
			if err != nil {
				obs.Default().Warn("webhook_delivery_failed", "subscription", s.Name, "event", j.ev, "err", err)
			}
		}
	}
}

// subscribed returns true when the subscription wants this event (either
// no filter or explicitly listed).
func subscribed(s Subscription, ev Event) bool {
	if len(s.Events) == 0 {
		return true
	}
	for _, e := range s.Events {
		if e == ev {
			return true
		}
	}
	return false
}

// postWithRetry does the POST with up to 3 attempts: 1s, 2s, 4s backoff on
// 5xx or transport errors. 4xx is terminal (we trust the endpoint's no).
func (d *dispatcher) postWithRetry(ctx context.Context, s Subscription, env Envelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		status, err := d.postOnce(ctx, s, raw)
		d.recordResult(s.Name, env.Event, status, err)
		if err == nil && status < 500 {
			if status >= 400 {
				return fmt.Errorf("POST %s: status %d", s.URL, status)
			}
			return nil
		}
		lastErr = err
		if err == nil {
			lastErr = fmt.Errorf("POST %s: status %d", s.URL, status)
		}
		if attempt == 2 {
			break
		}
		select {
		case <-time.After(delays[attempt]):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return lastErr
}

// postOnce sends a single request and returns the status code. A non-nil
// err implies an underlying transport error (no HTTP status).
func (d *dispatcher) postOnce(ctx context.Context, s Subscription, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PromptZero/webhook")
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	if s.Secret != "" {
		req.Header.Set("X-PromptZero-Signature", "sha256="+sign(s.Secret, body))
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// sign returns hex-encoded HMAC-SHA256(body, secret).
func sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// recordResult pushes to the per-subscription rolling window.
func (d *dispatcher) recordResult(name string, ev Event, status int, err error) {
	d.resultsMu.Lock()
	defer d.resultsMu.Unlock()
	list := d.results[name]
	list = append(list, SendResult{Event: ev, At: time.Now().UTC(), StatusCode: status, Err: err})
	if len(list) > recentResultLimit {
		list = list[len(list)-recentResultLimit:]
	}
	d.results[name] = list
}
