package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls until fn returns true or the deadline elapses. Cheaper
// than racing a time.After against channel sends.
func waitFor(t *testing.T, deadline time.Duration, fn func() bool) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition never satisfied within %s", deadline)
}

// TestDispatcher_Subscriptions_ReturnsCopy pins that Subscriptions
// returns a defensive copy of the configured list — callers mutating
// the returned slice (e.g. the /webhooks page sorting it for display)
// must not corrupt the dispatcher's internal state.
func TestDispatcher_Subscriptions_ReturnsCopy(t *testing.T) {
	subs := []Subscription{
		{Name: "a", URL: "https://example.com/a"},
		{Name: "b", URL: "https://example.com/b"},
	}
	d := New(subs).(*dispatcher)
	defer func() { _ = d.Close(context.Background()) }()

	got := d.Subscriptions()
	if len(got) != 2 {
		t.Fatalf("Subscriptions len=%d, want 2", len(got))
	}
	if got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("Subscriptions out of order: %+v", got)
	}

	// Mutate the returned slice; the dispatcher must not observe it.
	got[0].Name = "__sentinel__"
	again := d.Subscriptions()
	if again[0].Name == "__sentinel__" {
		t.Error("Subscriptions returns internal slice (mutation leaked)")
	}
}

// TestDispatcher_RecentResults_TracksSuccessfulSends pins that the
// recent-results rolling buffer is populated after a successful POST
// and that RecentResults returns a defensive copy.
func TestDispatcher_RecentResults_TracksSuccessfulSends(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	subs := []Subscription{{
		Name:   "primary",
		URL:    srv.URL,
		Events: []Event{EventSessionStarted},
	}}
	d := New(subs).(*dispatcher)
	defer func() { _ = d.Close(context.Background()) }()

	d.Fire(EventSessionStarted, map[string]any{"ok": true})
	waitFor(t, 2*time.Second, func() bool {
		return len(d.RecentResults("primary")) >= 1
	})

	got := d.RecentResults("primary")
	if len(got) == 0 {
		t.Fatal("RecentResults empty after a successful Fire")
	}
	if got[0].StatusCode < 200 || got[0].StatusCode >= 300 {
		t.Errorf("first result Status = %d; want 2xx", got[0].StatusCode)
	}

	// Defensive-copy contract.
	if len(got) > 0 {
		got[0].StatusCode = -1
		again := d.RecentResults("primary")
		if again[0].StatusCode == -1 {
			t.Error("RecentResults returns internal slice (mutation leaked)")
		}
	}

	// Unknown subscription → nil (not an empty slice; the API
	// distinguishes "no such sub" from "no results yet").
	if r := d.RecentResults("does-not-exist"); r != nil {
		t.Errorf("RecentResults(unknown) = %v; want nil", r)
	}
}

func TestDispatcher_FireAndBodyShape(t *testing.T) {
	var bodies [][]byte
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New([]Subscription{{Name: "test", URL: srv.URL}})
	d.Fire(EventToolFinished, map[string]interface{}{"tool": "rfid_read", "ok": true})

	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(bodies) == 1
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var env Envelope
	if err := json.Unmarshal(bodies[0], &env); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if env.Event != EventToolFinished {
		t.Fatalf("event: %s", env.Event)
	}
	m, ok := env.Payload.(map[string]interface{})
	if !ok || m["tool"] != "rfid_read" {
		t.Fatalf("payload shape wrong: %+v", env.Payload)
	}
}

func TestDispatcher_HMACWhenSecretSet(t *testing.T) {
	const secret = "my-secret"
	sigOK := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got := r.Header.Get("X-PromptZero-Signature")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got == want {
			sigOK.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New([]Subscription{{Name: "signed", URL: srv.URL, Secret: secret}})
	d.Fire(EventSessionStarted, map[string]string{"hello": "world"})
	waitFor(t, 2*time.Second, func() bool { return sigOK.Load() })
	_ = d.Close(context.Background())
}

func TestDispatcher_RetriesOn5xx(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; exercises exponential backoff — rerun without -short")
	}
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := &dispatcher{
		subs:    []Subscription{{Name: "flaky", URL: srv.URL}},
		client:  &http.Client{Timeout: 2 * time.Second},
		results: map[string][]SendResult{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	env := Envelope{Event: EventSessionStarted, Timestamp: time.Now().UTC(), Payload: nil}
	if err := d.postWithRetry(ctx, d.subs[0], env); err != nil {
		t.Fatalf("postWithRetry: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestDispatcher_NoRetryOn4xx(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	d := &dispatcher{
		subs:    []Subscription{{Name: "rejects", URL: srv.URL}},
		client:  &http.Client{Timeout: 2 * time.Second},
		results: map[string][]SendResult{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	env := Envelope{Event: EventSessionStarted, Timestamp: time.Now().UTC(), Payload: nil}
	if err := d.postWithRetry(ctx, d.subs[0], env); err == nil {
		t.Fatalf("expected error on 400")
	}
	if attempts.Load() != 1 {
		t.Fatalf("expected single attempt on 4xx, got %d", attempts.Load())
	}
}

func TestDispatcher_EventFilter(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New([]Subscription{{Name: "risk-only", URL: srv.URL, Events: []Event{EventRiskPrompted}}})
	d.Fire(EventToolFinished, nil)
	d.Fire(EventRiskPrompted, nil)

	waitFor(t, 2*time.Second, func() bool { return hits.Load() == 1 })
	time.Sleep(50 * time.Millisecond) // give any stragglers a chance to arrive
	if hits.Load() != 1 {
		t.Fatalf("expected exactly 1 hit (event filter), got %d", hits.Load())
	}
	_ = d.Close(context.Background())
}

// TestDispatcher_FireByNameTargetsSingleSubscription locks the
// rule-driven delivery semantics: FireByName goes to exactly the
// named subscription, bypassing its Events allowlist. Covers the
// case where a rule's `webhook: ops-pager` should reach ops-pager
// even if its Events filter doesn't list rule_fired.
func TestDispatcher_FireByNameTargetsSingleSubscription(t *testing.T) {
	var pagerHits, otherHits atomic.Int32
	pager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pagerHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer pager.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	d := New([]Subscription{
		// pager listens to a narrow Events filter that does NOT
		// include rule_fired; FireByName must still deliver.
		{Name: "ops-pager", URL: pager.URL, Events: []Event{EventAuditCritical}},
		// "all-events" subscription; must NOT receive a FireByName
		// targeting ops-pager.
		{Name: "all", URL: other.URL},
	})

	d.FireByName("ops-pager", map[string]string{"reason": "rule alert"})
	waitFor(t, 2*time.Second, func() bool { return pagerHits.Load() == 1 })
	time.Sleep(50 * time.Millisecond)

	if pagerHits.Load() != 1 {
		t.Errorf("ops-pager should receive 1 delivery, got %d", pagerHits.Load())
	}
	if otherHits.Load() != 0 {
		t.Errorf("'all' subscription should NOT receive a name-targeted call, got %d", otherHits.Load())
	}
	_ = d.Close(context.Background())
}

// TestDispatcher_FireByNameUnknownSilent verifies the fire-and-forget
// contract — calling FireByName with no matching subscription is a
// silent no-op (matches the existing Fire behaviour for an event
// no subscription listens to).
func TestDispatcher_FireByNameUnknownSilent(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New([]Subscription{{Name: "exists", URL: srv.URL}})
	d.FireByName("does-not-exist", map[string]any{"x": 1})
	time.Sleep(100 * time.Millisecond)
	if hits.Load() != 0 {
		t.Errorf("unknown name should deliver to nobody, got %d", hits.Load())
	}
	_ = d.Close(context.Background())
}

func TestDispatcher_CloseDrainsQueue(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New([]Subscription{{Name: "drain", URL: srv.URL}})
	const n = 10
	for i := 0; i < n; i++ {
		d.Fire(EventSessionEnded, map[string]int{"i": i})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if hits.Load() != int32(n) {
		t.Fatalf("expected %d deliveries after drain, got %d", n, hits.Load())
	}
}

func TestDispatcher_TestSubscription(t *testing.T) {
	var gotEvent atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var env Envelope
		_ = json.Unmarshal(b, &env)
		gotEvent.Store(string(env.Event))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New([]Subscription{{Name: "t", URL: srv.URL}})
	if err := d.TestSubscription(context.Background(), "t"); err != nil {
		t.Fatalf("TestSubscription: %v", err)
	}
	if got, _ := gotEvent.Load().(string); got != string(EventSessionStarted) {
		t.Fatalf("got event %q", got)
	}
	if err := d.TestSubscription(context.Background(), "missing"); err == nil {
		t.Fatalf("expected error for missing subscription")
	}
	_ = d.Close(context.Background())
}

// TestDispatcher_FireConcurrentWithClose pins the v0.86 race fix:
// Fire and FireByName must not panic with "send on closed channel"
// when called concurrently with Close. Pre-fix the close-detect via
// `<-d.closed` was TOCTOU racy against `close(d.queue)` — Fire could
// observe d.closed open, then try to send to a queue Close had just
// closed.
//
// Webhook fires happen from many goroutines (audit, agent, rules).
// A late event during shutdown was a real production crash path; the
// race is reproducible under `-race` by hammering Fire from N
// goroutines while Close runs.
//
// The test never asserts a specific delivery count — that's racy by
// nature. The contract is "no panic, no deadlock, Close completes."
func TestDispatcher_FireConcurrentWithClose(t *testing.T) {
	// Slow handler so Close has work to drain; we just need the
	// dispatcher to be live for the fire loop.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New([]Subscription{{Name: "race", URL: srv.URL}})

	// Hammer Fire from many goroutines until told to stop.
	stop := make(chan struct{})
	var producers sync.WaitGroup
	const workers = 8
	for i := 0; i < workers; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				d.Fire(EventSessionEnded, map[string]int{"i": 1})
				d.FireByName("race", map[string]int{"i": 2})
			}
		}()
	}

	// Let the producers warm up so the queue is hot when Close fires.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		// Cancellation here would mean Close didn't complete in 5 s —
		// the producer hammer is supposed to be cheap.
		close(stop)
		producers.Wait()
		t.Fatalf("Close returned %v under concurrent Fire — race-induced deadlock?", err)
	}

	// Producers should observe the closed channel and exit cleanly;
	// any panic would have already failed the test under -race.
	close(stop)
	producers.Wait()
}
