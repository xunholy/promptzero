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
