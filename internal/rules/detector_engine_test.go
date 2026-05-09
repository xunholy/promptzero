package rules

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubDetector is a minimal Detector used to exercise the Engine
// without wiring up an Anthropic client.
type stubDetector struct {
	name     string
	verdict  Verdict
	err      error
	called   atomic.Int32
	delay    time.Duration
	observed atomic.Value // last (tool, input, output) tuple seen
}

type seen struct{ tool, input, output string }

func (s *stubDetector) Name() string { return s.name }
func (s *stubDetector) Evaluate(ctx context.Context, tool, input, output string) (Verdict, error) {
	s.called.Add(1)
	s.observed.Store(seen{tool: tool, input: input, output: output})
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return Verdict{}, ctx.Err()
		}
	}
	if s.err != nil {
		return Verdict{}, s.err
	}
	return s.verdict, nil
}

func TestDetectorEngine_NoRegistrations(t *testing.T) {
	e := NewDetectorEngine(0) // 0 → default timeout
	if e.HasDetectorsFor("anything") {
		t.Error("fresh engine should report no detectors")
	}
	if v := e.EvaluateFor(context.Background(), "anything", "", ""); v != nil {
		t.Errorf("EvaluateFor on empty engine should return nil, got %+v", v)
	}
}

func TestDetectorEngine_NilReceiverSafe(t *testing.T) {
	// All methods on nil must be callable — avoids defensive nil
	// checks at every agent dispatch site.
	var e *DetectorEngine
	if e.HasDetectorsFor("x") {
		t.Error("nil engine should report no detectors")
	}
	if v := e.EvaluateFor(context.Background(), "x", "", ""); v != nil {
		t.Errorf("nil engine should return nil slice, got %+v", v)
	}
	// Register and RegisterForMany must be no-ops, not panics.
	e.Register("x", &stubDetector{name: "s"})
	e.RegisterForMany([]string{"y"}, &stubDetector{name: "s"})
}

func TestDetectorEngine_RegisterAndEvaluate(t *testing.T) {
	e := NewDetectorEngine(time.Second)
	d := &stubDetector{
		name:    "success",
		verdict: Verdict{Verdict: VerdictSuccess, Confidence: 0.9, Evidence: "ok"},
	}
	e.Register("wifi_deauth", d)

	if !e.HasDetectorsFor("wifi_deauth") {
		t.Fatal("expected registration to stick")
	}
	if e.HasDetectorsFor("wifi_scan_ap") {
		t.Error("registration leaked to unrelated tool")
	}

	out := e.EvaluateFor(context.Background(), "wifi_deauth", `{"duration_seconds":30}`, "frames:23 ack:18")
	if len(out) != 1 {
		t.Fatalf("len(verdicts) = %d, want 1", len(out))
	}
	if out[0].Verdict != VerdictSuccess {
		t.Errorf("verdict = %q, want success", out[0].Verdict)
	}
	// DetectedBy is a Detector responsibility (LLMDetector sets it in
	// Evaluate); the engine's contract is only to pass the struct
	// through unchanged. The stub here deliberately doesn't set it —
	// test focus is on engine dispatch, not detector behaviour.
	if d.called.Load() != 1 {
		t.Errorf("detector called %d times, want 1", d.called.Load())
	}
	obs := d.observed.Load().(seen)
	if obs.tool != "wifi_deauth" {
		t.Errorf("tool = %q, want wifi_deauth", obs.tool)
	}
}

func TestDetectorEngine_MultipleDetectorsRunConcurrently(t *testing.T) {
	e := NewDetectorEngine(2 * time.Second)
	d1 := &stubDetector{name: "a", verdict: Verdict{Verdict: VerdictSuccess}, delay: 50 * time.Millisecond}
	d2 := &stubDetector{name: "b", verdict: Verdict{Verdict: VerdictSuspicious}, delay: 50 * time.Millisecond}
	d3 := &stubDetector{name: "c", verdict: Verdict{Verdict: VerdictFailure}, delay: 50 * time.Millisecond}
	e.Register("wifi_deauth", d1)
	e.Register("wifi_deauth", d2)
	e.Register("wifi_deauth", d3)

	start := time.Now()
	verdicts := e.EvaluateFor(context.Background(), "wifi_deauth", "", "")
	elapsed := time.Since(start)

	if len(verdicts) != 3 {
		t.Fatalf("got %d verdicts, want 3", len(verdicts))
	}
	// Three detectors × 50ms serially = 150ms. Concurrent should be
	// under 100ms on any reasonable runner.
	if elapsed > 120*time.Millisecond {
		t.Errorf("expected concurrent evaluation, took %v (serial ≈ 150ms)", elapsed)
	}
}

func TestDetectorEngine_DetectorErrorsYieldUnknown(t *testing.T) {
	e := NewDetectorEngine(time.Second)
	d := &stubDetector{name: "broken", err: errors.New("upstream 500")}
	e.Register("wifi_deauth", d)

	verdicts := e.EvaluateFor(context.Background(), "wifi_deauth", "", "")
	if len(verdicts) != 1 {
		t.Fatalf("want 1 verdict, got %d", len(verdicts))
	}
	if verdicts[0].Verdict != VerdictUnknown {
		t.Errorf("broken detector should yield unknown, got %q", verdicts[0].Verdict)
	}
	if !strings.Contains(verdicts[0].Evidence, "detector error") {
		t.Errorf("evidence should explain the error: %q", verdicts[0].Evidence)
	}
	if verdicts[0].DetectedBy != "broken" {
		t.Errorf("DetectedBy should name the detector: %q", verdicts[0].DetectedBy)
	}
}

func TestDetectorEngine_Timeout(t *testing.T) {
	// 100ms detector timeout, 500ms detector — the engine must reap
	// it with a ctx-cancelled error and surface Unknown.
	e := NewDetectorEngine(100 * time.Millisecond)
	d := &stubDetector{name: "slow", delay: 500 * time.Millisecond, verdict: Verdict{Verdict: VerdictSuccess}}
	e.Register("wifi_deauth", d)

	start := time.Now()
	verdicts := e.EvaluateFor(context.Background(), "wifi_deauth", "", "")
	elapsed := time.Since(start)
	if elapsed > 250*time.Millisecond {
		t.Errorf("timeout not honoured: took %v", elapsed)
	}
	if len(verdicts) != 1 {
		t.Fatalf("want 1 verdict, got %d", len(verdicts))
	}
	if verdicts[0].Verdict != VerdictUnknown {
		t.Errorf("timed-out detector should yield unknown, got %q", verdicts[0].Verdict)
	}
}

func TestDetectorEngine_RegisterForMany(t *testing.T) {
	e := NewDetectorEngine(time.Second)
	d := &stubDetector{name: "deauth", verdict: Verdict{Verdict: VerdictSuccess}}
	e.RegisterForMany([]string{"wifi_deauth", "wifi_deauth_station_list"}, d)

	for _, tool := range []string{"wifi_deauth", "wifi_deauth_station_list"} {
		if !e.HasDetectorsFor(tool) {
			t.Errorf("detector missing on %s", tool)
		}
	}
	if e.HasDetectorsFor("wifi_scan_ap") {
		t.Error("RegisterForMany should not spread to unlisted tools")
	}
}

// panicDetector implements Detector but blows up inside Evaluate.
// Used to pin the panic-recovery contract on the engine's parallel
// evaluation goroutines.
type panicDetector struct{ name string }

func (p *panicDetector) Name() string { return p.name }
func (p *panicDetector) Evaluate(context.Context, string, string, string) (Verdict, error) {
	panic("synthetic detector panic")
}

func TestDetectorEngine_DetectorPanicYieldsUnknown(t *testing.T) {
	// A misbehaving detector that panics must not crash the engine
	// goroutine and must not leave a zero-valued verdict slot.
	// Contract: surface as VerdictUnknown with evidence naming
	// the panic, same fail-soft behaviour as a returned error.
	e := NewDetectorEngine(time.Second)
	good := &stubDetector{name: "ok", verdict: Verdict{Verdict: VerdictSuccess, Confidence: 0.9}}
	bad := &panicDetector{name: "panicker"}
	e.Register("wifi_deauth", good)
	e.Register("wifi_deauth", bad)

	verdicts := e.EvaluateFor(context.Background(), "wifi_deauth", "", "")
	if len(verdicts) != 2 {
		t.Fatalf("want 2 verdicts, got %d", len(verdicts))
	}

	// Find the panicker's verdict — order is registration order, but
	// scan by DetectedBy to keep the test resilient to refactoring.
	var panicVerdict Verdict
	for _, v := range verdicts {
		if v.DetectedBy == "panicker" {
			panicVerdict = v
		}
	}
	if panicVerdict.Verdict != VerdictUnknown {
		t.Errorf("panicked detector should yield unknown, got %q", panicVerdict.Verdict)
	}
	if !strings.Contains(panicVerdict.Evidence, "detector panic") {
		t.Errorf("evidence should mention the panic: %q", panicVerdict.Evidence)
	}
	if !strings.Contains(panicVerdict.Evidence, "synthetic detector panic") {
		t.Errorf("evidence should include the panic value: %q", panicVerdict.Evidence)
	}

	// Sibling detector still ran and produced its verdict — panic in
	// one goroutine must not poison the others.
	if good.called.Load() != 1 {
		t.Errorf("good detector called %d times, want 1", good.called.Load())
	}
}

func TestDetectorEngine_RegisterBuiltins(t *testing.T) {
	// Built-ins should wire against the expected tools without extra
	// registrations. Use a stub judge so nothing hits the SDK.
	judge := func(context.Context, string, string) (string, error) {
		return `{"verdict":"success","confidence":0.9,"verified":true}`, nil
	}
	e := NewDetectorEngine(time.Second).RegisterBuiltins(judge)
	wantCovered := []string{"wifi_deauth", "wifi_deauth_station_list", "wifi_sniff_pmkid", "nfc_emulate"}
	for _, tool := range wantCovered {
		if !e.HasDetectorsFor(tool) {
			t.Errorf("built-in register missed %s", tool)
		}
	}
}
