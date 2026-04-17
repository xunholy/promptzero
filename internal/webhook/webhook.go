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
	"log"
	"net/http"
	"sync"
	"time"
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
}

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

// New constructs a dispatcher. When subs is empty it returns a no-op
// dispatcher so callers don't branch on nil.
func New(subs []Subscription) Dispatcher {
	d := &dispatcher{
		subs:    subs,
		client:  &http.Client{Timeout: 10 * time.Second},
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
func (d *dispatcher) Fire(ev Event, payload any) {
	select {
	case <-d.closed:
		return
	default:
	}
	select {
	case d.queue <- job{ev: ev, payload: payload, ts: time.Now().UTC()}:
	default:
		log.Printf("webhook: queue overflow (%d), dropping event %s", queueCapacity, ev)
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
			if !subscribed(s, j.ev) {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			err := d.postWithRetry(ctx, s, body)
			cancel()
			if err != nil {
				log.Printf("webhook: %s %s: %v", s.Name, j.ev, err)
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
