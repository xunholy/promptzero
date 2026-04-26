package companion

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEncodeEvent_FillsVersionAndTimestamp(t *testing.T) {
	t.Cleanup(func() { nowSeconds = func() int64 { return time.Now().Unix() } })
	nowSeconds = func() int64 { return 1700000000 }

	got, err := EncodeEvent(Event{Type: EventBusy, Label: "subghz_tx", Risk: "high"})
	if err != nil {
		t.Fatalf("EncodeEvent: %v", err)
	}
	if !strings.HasSuffix(string(got), "\n") {
		t.Fatalf("EncodeEvent must terminate with newline; got %q", got)
	}

	var ev Event
	if err := json.Unmarshal(got, &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Version != WireVersion {
		t.Errorf("version: want %d got %d", WireVersion, ev.Version)
	}
	if ev.TS != 1700000000 {
		t.Errorf("ts: want 1700000000 got %d", ev.TS)
	}
	if ev.Label != "subghz_tx" || ev.Risk != "high" {
		t.Errorf("payload roundtrip: %+v", ev)
	}
}

func TestEncodeEvent_DoneOmitsOKWhenNil(t *testing.T) {
	got, err := EncodeEvent(Event{Type: EventDone, Label: "x"})
	if err != nil {
		t.Fatalf("EncodeEvent: %v", err)
	}
	if strings.Contains(string(got), `"ok"`) {
		t.Errorf("expected ok field omitted when nil; got %s", got)
	}

	ok := true
	got, _ = EncodeEvent(Event{Type: EventDone, Label: "x", OK: &ok})
	if !strings.Contains(string(got), `"ok":true`) {
		t.Errorf("expected ok:true present; got %s", got)
	}
}

func TestEncodeEvent_ConfirmCarriesID(t *testing.T) {
	got, err := EncodeEvent(Event{Type: EventConfirm, Label: "wifi_deauth", ID: "abc12345"})
	if err != nil {
		t.Fatalf("EncodeEvent: %v", err)
	}
	if !strings.Contains(string(got), `"id":"abc12345"`) {
		t.Errorf("expected id present; got %s", got)
	}
}

func TestNopSink_AllMethodsAreNoOps(t *testing.T) {
	var s Sink = NopSink{}
	s.Idle()
	s.Busy("a", "b", "low")
	s.Done("a", true)
	s.Confirm("id1", "a", "high")
	s.PollResponses(true)
	s.PollResponses(false)
	if err := s.Close(); err != nil {
		t.Errorf("NopSink.Close = %v, want nil", err)
	}
	// Responses() must return a never-firing channel — verify by
	// trying a non-blocking receive.
	select {
	case <-s.Responses():
		t.Errorf("NopSink.Responses() must never deliver")
	default:
	}
}

// fakeIO is a thread-safe in-memory FlipperIO that records every
// WriteFile call and serves a configurable response body to every
// StorageRead. Used to assert FlipperSink behaviour without a live
// USB link.
type fakeIO struct {
	mu          sync.Mutex
	calls       []writeCall
	removed     []string
	writeErr    error
	delay       time.Duration
	respBody    string
	respErr     error
	readCount   atomic.Uint32
	removeCount atomic.Uint32
}

type writeCall struct {
	path string
	data []byte
}

func (w *fakeIO) WriteFile(path string, data []byte) error {
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	w.calls = append(w.calls, writeCall{path: path, data: cp})
	return w.writeErr
}

func (w *fakeIO) StorageRead(_ string) (string, error) {
	w.readCount.Add(1)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.respBody, w.respErr
}

func (w *fakeIO) StorageRemove(path string) (string, error) {
	w.removeCount.Add(1)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.removed = append(w.removed, path)
	return "", nil
}

func (w *fakeIO) removedSnapshot() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, len(w.removed))
	copy(out, w.removed)
	return out
}

func (w *fakeIO) snapshot() []writeCall {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]writeCall, len(w.calls))
	copy(out, w.calls)
	return out
}

func (w *fakeIO) setResponse(body string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.respBody = body
	w.respErr = nil
}

// TestFlipperSink_PushesEachEvent verifies that under non-bursty
// load every Sink call lands as one WriteFile.
func TestFlipperSink_PushesEachEvent(t *testing.T) {
	w := &fakeIO{}
	s := NewFlipperSink(w, "/test/status.json", nil)
	t.Cleanup(func() { _ = s.Close() })

	s.Idle()
	waitFor(t, func() bool { return len(w.snapshot()) >= 1 })

	s.Busy("subghz_tx", "433.92 MHz", "high")
	waitFor(t, func() bool { return len(w.snapshot()) >= 2 })

	s.Done("subghz_tx", true)
	waitFor(t, func() bool { return len(w.snapshot()) >= 3 })

	calls := w.snapshot()
	if len(calls) != 3 {
		t.Fatalf("want 3 writes, got %d", len(calls))
	}
	for _, c := range calls {
		if c.path != "/test/status.json" {
			t.Errorf("path: want /test/status.json got %q", c.path)
		}
	}
	// Verify the last call matches the Done event.
	var ev Event
	if err := json.Unmarshal(calls[2].data, &ev); err != nil {
		t.Fatalf("decode last call: %v", err)
	}
	if ev.Type != EventDone || ev.Label != "subghz_tx" || ev.OK == nil || !*ev.OK {
		t.Errorf("last call mismatch: %+v", ev)
	}
}

// TestFlipperSink_CoalescesBursts verifies that a flurry of pushes
// during a slow USB write collapses to "the latest event wins"
// rather than queuing every interim state.
func TestFlipperSink_CoalescesBursts(t *testing.T) {
	w := &fakeIO{delay: 30 * time.Millisecond}
	s := NewFlipperSink(w, "", nil)
	t.Cleanup(func() { _ = s.Close() })

	for _, d := range []string{"1", "2", "3", "4", "5"} {
		s.Busy("a", d, "low")
	}

	waitFor(t, func() bool {
		calls := w.snapshot()
		if len(calls) == 0 {
			return false
		}
		var ev Event
		if err := json.Unmarshal(calls[len(calls)-1].data, &ev); err != nil {
			return false
		}
		return ev.Detail == "5"
	})

	calls := w.snapshot()
	if len(calls) >= 5 {
		t.Errorf("expected coalescing — want fewer than 5 writes for 5 pushes, got %d", len(calls))
	}
}

func TestFlipperSink_SwallowsWriteErrors(t *testing.T) {
	w := &fakeIO{writeErr: errors.New("usb gone")}
	s := NewFlipperSink(w, "", nil)
	t.Cleanup(func() { _ = s.Close() })

	s.Busy("a", "b", "low")
	s.Done("a", false)
	s.Idle()

	waitFor(t, func() bool { return len(w.snapshot()) >= 1 })
}

// TestFlipperSink_TruncatesPeriodically verifies the every-Nth-write
// removal that prevents Momentum's append-mode write_chunk from
// growing the status file unbounded.
func TestFlipperSink_TruncatesPeriodically(t *testing.T) {
	w := &fakeIO{}
	s := NewFlipperSink(w, "", nil)
	s.TruncateEvery = 3
	t.Cleanup(func() { _ = s.Close() })

	for i := 0; i < 7; i++ {
		s.Idle()
		// Wait for each event to land before pushing the next so
		// coalescing doesn't collapse them into fewer writes.
		expect := i + 1
		waitFor(t, func() bool { return len(w.snapshot()) >= expect })
	}

	// After 7 writes with TruncateEvery=3: writes 3 and 6 trigger
	// a remove first; write 7 doesn't (yet). So 2 removes total.
	if got := w.removeCount.Load(); got != 2 {
		t.Errorf("StorageRemove count = %d, want 2 (writes 3 and 6 trigger truncation)", got)
	}
}

func TestFlipperSink_TruncationDisabled(t *testing.T) {
	w := &fakeIO{}
	s := NewFlipperSink(w, "", nil)
	s.TruncateEvery = 0
	t.Cleanup(func() { _ = s.Close() })

	for i := 0; i < 100; i++ {
		s.Idle()
	}
	waitFor(t, func() bool { return len(w.snapshot()) >= 1 })
	// Give the worker a beat to drain everything.
	time.Sleep(50 * time.Millisecond)

	if got := w.removeCount.Load(); got != 0 {
		t.Errorf("StorageRemove count = %d, want 0 with TruncateEvery=0", got)
	}
}

func TestFlipperSink_CloseIsIdempotent(t *testing.T) {
	s := NewFlipperSink(&fakeIO{}, "", nil)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestFlipperSink_ConfirmIncludesID(t *testing.T) {
	w := &fakeIO{}
	s := NewFlipperSink(w, "", nil)
	t.Cleanup(func() { _ = s.Close() })

	s.Confirm("req-001", "wifi_deauth", "critical")
	waitFor(t, func() bool { return len(w.snapshot()) >= 1 })

	calls := w.snapshot()
	var ev Event
	if err := json.Unmarshal(calls[len(calls)-1].data, &ev); err != nil {
		t.Fatalf("decode confirm: %v", err)
	}
	if ev.Type != EventConfirm || ev.ID != "req-001" || ev.Risk != "critical" {
		t.Errorf("confirm event: %+v", ev)
	}
}

// TestFlipperSink_PollResponses_DisabledByDefault verifies that
// the response poller is dormant until enabled — the USB link
// should be quiet between confirm prompts.
func TestFlipperSink_PollResponses_DisabledByDefault(t *testing.T) {
	w := &fakeIO{}
	s := NewFlipperSink(w, "", nil)
	t.Cleanup(func() { _ = s.Close() })

	// Wait two poll intervals; reads should be zero.
	time.Sleep(2 * responsePollInterval)
	if got := w.readCount.Load(); got != 0 {
		t.Errorf("StorageRead called %d times while polling disabled, want 0", got)
	}
}

// TestFlipperSink_PollResponses_DeliversFreshAnswer verifies the
// happy path: poller is enabled, FAP "writes" a response, sink
// pushes it onto the channel.
func TestFlipperSink_PollResponses_DeliversFreshAnswer(t *testing.T) {
	w := &fakeIO{respBody: `{"id":"req-42","decision":"approve"}`}
	s := NewFlipperSink(w, "", nil)
	t.Cleanup(func() { _ = s.Close() })

	s.PollResponses(true)
	defer s.PollResponses(false)

	select {
	case r := <-s.Responses():
		if r.ID != "req-42" || !r.Approved() {
			t.Errorf("response = %+v, want approve req-42", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no response delivered within 2 s")
	}
}

// TestFlipperSink_PollResponses_DedupsRepeatedReads verifies that
// the sink does not re-deliver the same response on every poll
// tick — the consumer would see the same approval over and over.
func TestFlipperSink_PollResponses_DedupsRepeatedReads(t *testing.T) {
	w := &fakeIO{respBody: `{"id":"req-99","decision":"deny"}`}
	s := NewFlipperSink(w, "", nil)
	t.Cleanup(func() { _ = s.Close() })

	s.PollResponses(true)
	defer s.PollResponses(false)

	// First read should fire.
	select {
	case <-s.Responses():
	case <-time.After(2 * time.Second):
		t.Fatal("first response missed")
	}

	// Subsequent polls of the same body should not re-push.
	select {
	case r := <-s.Responses():
		t.Errorf("duplicate response delivered: %+v", r)
	case <-time.After(3 * responsePollInterval):
		// expected — no new push
	}
}

// TestFlipperSink_PollResponses_PushesNewIDOnContentChange
// verifies that when the FAP writes a different response (new id),
// the sink pushes the new one even though the previous response
// was already delivered.
func TestFlipperSink_PollResponses_PushesNewIDOnContentChange(t *testing.T) {
	w := &fakeIO{respBody: `{"id":"req-1","decision":"approve"}`}
	s := NewFlipperSink(w, "", nil)
	t.Cleanup(func() { _ = s.Close() })

	s.PollResponses(true)
	defer s.PollResponses(false)

	// Drain the first delivery.
	select {
	case <-s.Responses():
	case <-time.After(2 * time.Second):
		t.Fatal("first response missed")
	}

	// FAP "writes" a new answer.
	w.setResponse(`{"id":"req-2","decision":"deny"}`)

	select {
	case r := <-s.Responses():
		if r.ID != "req-2" || r.Approved() {
			t.Errorf("second response = %+v, want deny req-2", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second response missed")
	}
}

func TestFlipperSink_PollResponses_IgnoresMalformed(t *testing.T) {
	w := &fakeIO{respBody: "not json at all"}
	s := NewFlipperSink(w, "", nil)
	t.Cleanup(func() { _ = s.Close() })

	s.PollResponses(true)
	defer s.PollResponses(false)

	select {
	case r := <-s.Responses():
		t.Errorf("malformed body delivered as %+v", r)
	case <-time.After(3 * responsePollInterval):
		// expected
	}
}

func TestFlipperSink_PollResponses_IgnoresMissingID(t *testing.T) {
	// Missing id field — without an id we can't match against an
	// outstanding request, so the response is meaningless.
	w := &fakeIO{respBody: `{"decision":"approve"}`}
	s := NewFlipperSink(w, "", nil)
	t.Cleanup(func() { _ = s.Close() })

	s.PollResponses(true)
	defer s.PollResponses(false)

	select {
	case r := <-s.Responses():
		t.Errorf("id-less body delivered as %+v", r)
	case <-time.After(3 * responsePollInterval):
		// expected
	}
}

func TestParseResponse(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Response
		ok   bool
	}{
		{"clean", `{"id":"a","decision":"approve"}`, Response{ID: "a", Decision: "approve"}, true},
		{"with cli prefix", "Size: 32\n{\"id\":\"b\",\"decision\":\"deny\"}\n>", Response{ID: "b", Decision: "deny"}, true},
		{"trailing whitespace", "  {\"id\":\"c\",\"decision\":\"approve\"}  \n", Response{ID: "c", Decision: "approve"}, true},
		{"no braces", "garbage", Response{}, false},
		{"missing id", `{"decision":"approve"}`, Response{}, false},
		{"empty", "", Response{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseResponse(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (input %q)", ok, tc.ok, tc.in)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestResponse_Approved(t *testing.T) {
	if !(Response{Decision: "approve"}).Approved() {
		t.Error("approve must report Approved=true")
	}
	if (Response{Decision: "deny"}).Approved() {
		t.Error("deny must report Approved=false")
	}
	if (Response{}).Approved() {
		t.Error("empty Decision must report Approved=false (deny by default)")
	}
}

// fakeProbe lets Detect tests inject Flipper-CLI output without a
// real device.
type fakeProbe struct {
	responses map[string]string
	errors    map[string]error
	calls     atomic.Int32
}

func (p *fakeProbe) ExecCtx(_ context.Context, cmd string) (string, error) {
	p.calls.Add(1)
	if e, ok := p.errors[cmd]; ok {
		return "", e
	}
	if r, ok := p.responses[cmd]; ok {
		return r, nil
	}
	return "Storage error: no such file or directory", nil
}

func TestDetect_ReturnsFirstHit(t *testing.T) {
	p := &fakeProbe{
		responses: map[string]string{
			"storage stat /ext/apps/Misc/promptzero_companion.fap": "size:12345",
		},
	}
	got := Detect(context.Background(), p)
	if got != "/ext/apps/Misc/promptzero_companion.fap" {
		t.Errorf("Detect = %q, want Misc path", got)
	}
}

func TestDetect_ReturnsEmptyWhenAbsent(t *testing.T) {
	p := &fakeProbe{}
	if got := Detect(context.Background(), p); got != "" {
		t.Errorf("Detect = %q, want empty", got)
	}
}

func TestDetect_NilProbe(t *testing.T) {
	if got := Detect(context.Background(), nil); got != "" {
		t.Errorf("Detect(nil) = %q, want empty", got)
	}
}

func TestDetect_TreatsCLIErrorAsAbsent(t *testing.T) {
	p := &fakeProbe{
		errors: map[string]error{
			"storage stat /ext/apps/Tools/promptzero_companion.fap": errors.New("usb timeout"),
		},
	}
	if got := Detect(context.Background(), p); got != "" {
		t.Errorf("Detect on cli error: %q, want empty", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waitFor timed out")
}
