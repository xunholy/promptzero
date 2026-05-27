package rules

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/audit"
)

func TestMatch_ToolAndRisk(t *testing.T) {
	m := Match{Tool: "badusb_run", Risk: "critical"}
	if !matches(m, audit.Entry{Tool: "badusb_run", Risk: "critical"}) {
		t.Fatal("expected exact match")
	}
	if matches(m, audit.Entry{Tool: "badusb_run", Risk: "high"}) {
		t.Error("risk mismatch should fail")
	}
	if matches(m, audit.Entry{Tool: "other_tool", Risk: "critical"}) {
		t.Error("tool mismatch should fail")
	}
}

func TestMatch_ToolGlob(t *testing.T) {
	m := Match{Tool: "workflow_*"}
	if !matches(m, audit.Entry{Tool: "workflow_nfc_badge_pipeline"}) {
		t.Error("workflow_* should match workflow_nfc_badge_pipeline")
	}
	if matches(m, audit.Entry{Tool: "badusb_run"}) {
		t.Error("workflow_* should not match badusb_run")
	}
}

func TestMatch_OutputContains(t *testing.T) {
	m := Match{OutputContains: "PMKID"}
	if !matches(m, audit.Entry{Output: "captured PMKID=xyz"}) {
		t.Error("expected contains match")
	}
	if matches(m, audit.Entry{Output: "no capture"}) {
		t.Error("expected contains miss")
	}
}

// TestMatch_Success exercises the tristate: nil Success matches both
// outcomes, &true matches only success, &false matches only failure.
// Same shape as audit.Filter.Success so operators can use the rule
// engine to trigger follow-ups conditional on the previous tool's
// outcome — e.g. "alert when wifi_handshake_capture fails".
func TestMatch_Success(t *testing.T) {
	successEntry := audit.Entry{Tool: "wifi_handshake_capture", Success: true}
	failureEntry := audit.Entry{Tool: "wifi_handshake_capture", Success: false}

	// nil Success: match both outcomes (legacy behaviour, preserved).
	mAny := Match{Tool: "wifi_handshake_capture"}
	if !matches(mAny, successEntry) || !matches(mAny, failureEntry) {
		t.Error("nil Success should match either outcome")
	}

	// Success = &true: match only success.
	tr := true
	mTrue := Match{Tool: "wifi_handshake_capture", Success: &tr}
	if !matches(mTrue, successEntry) {
		t.Error("Success=&true should match a successful entry")
	}
	if matches(mTrue, failureEntry) {
		t.Error("Success=&true should NOT match a failed entry")
	}

	// Success = &false: match only failure.
	fa := false
	mFalse := Match{Tool: "wifi_handshake_capture", Success: &fa}
	if !matches(mFalse, failureEntry) {
		t.Error("Success=&false should match a failed entry")
	}
	if matches(mFalse, successEntry) {
		t.Error("Success=&false should NOT match a successful entry")
	}
}

func TestEngine_FiresWebhook(t *testing.T) {
	var (
		mu    sync.Mutex
		fired []struct {
			name    string
			payload map[string]any
		}
	)
	eng := New(Deps{
		WebhookFire: func(name string, payload map[string]any) {
			mu.Lock()
			defer mu.Unlock()
			fired = append(fired, struct {
				name    string
				payload map[string]any
			}{name, payload})
		},
	})
	eng.Register(Rule{
		Name:    "crit",
		Match:   Match{Risk: "critical"},
		Actions: []Action{{Kind: ActionWebhook, Webhook: "ops", Params: map[string]interface{}{"note": "tool={{tool}} trace={{trace_id}}"}}},
		Enabled: true,
	})

	eng.Handle(audit.Entry{Tool: "subghz_bruteforce", Risk: "critical", TraceID: "abc123"})

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 1 {
		t.Fatalf("fired=%d want 1", len(fired))
	}
	if fired[0].name != "ops" {
		t.Errorf("webhook=%q want ops", fired[0].name)
	}
	note, _ := fired[0].payload["note"].(string)
	if note != "tool=subghz_bruteforce trace=abc123" {
		t.Errorf("template not substituted: %q", note)
	}
	if fired[0].payload["tool"] != "subghz_bruteforce" {
		t.Errorf("payload missing tool: %+v", fired[0].payload)
	}
}

func TestEngine_Cooldown(t *testing.T) {
	now := time.Now()
	var fires int
	eng := New(Deps{
		Now:         func() time.Time { return now },
		WebhookFire: func(_ string, _ map[string]any) { fires++ },
	})
	eng.Register(Rule{
		Name:     "throttled",
		Match:    Match{Tool: "subghz_transmit"},
		Actions:  []Action{{Kind: ActionWebhook, Webhook: "x"}},
		Cooldown: 30 * time.Second,
		Enabled:  true,
	})

	entry := audit.Entry{Tool: "subghz_transmit"}
	eng.Handle(entry) // fire 1
	eng.Handle(entry) // suppressed
	if fires != 1 {
		t.Fatalf("fires=%d want 1 (cooldown should suppress the second)", fires)
	}

	// Advance past the cooldown.
	now = now.Add(31 * time.Second)
	eng.Handle(entry) // fire 2
	if fires != 2 {
		t.Fatalf("fires=%d want 2 (after cooldown expiry)", fires)
	}
}

func TestEngine_PauseResume(t *testing.T) {
	var fires int
	eng := New(Deps{
		WebhookFire: func(_ string, _ map[string]any) { fires++ },
	})
	eng.Register(Rule{
		Name:    "r",
		Match:   Match{Tool: "t"},
		Actions: []Action{{Kind: ActionWebhook}},
		Enabled: true,
	})

	eng.Handle(audit.Entry{Tool: "t"})
	if fires != 1 {
		t.Fatalf("initial fire count=%d want 1", fires)
	}
	if !eng.Pause("r") {
		t.Fatal("Pause(r) returned false")
	}
	eng.Handle(audit.Entry{Tool: "t"})
	if fires != 1 {
		t.Fatalf("after pause fires=%d want 1", fires)
	}
	if !eng.Resume("r") {
		t.Fatal("Resume(r) returned false")
	}
	eng.Handle(audit.Entry{Tool: "t"})
	if fires != 2 {
		t.Fatalf("after resume fires=%d want 2", fires)
	}
}

func TestEngine_List(t *testing.T) {
	eng := New(Deps{})
	eng.Register(Rule{Name: "b", Description: "second", Enabled: true})
	eng.Register(Rule{Name: "a", Description: "first", Enabled: true})
	snaps := eng.List()
	if len(snaps) != 2 {
		t.Fatalf("len=%d want 2", len(snaps))
	}
	if snaps[0].Name != "a" || snaps[1].Name != "b" {
		t.Errorf("not sorted: %q %q", snaps[0].Name, snaps[1].Name)
	}
}

func TestEngine_Remove(t *testing.T) {
	var fires int
	eng := New(Deps{
		WebhookFire: func(_ string, _ map[string]any) { fires++ },
	})
	eng.Register(Rule{
		Name:    "r",
		Match:   Match{Tool: "t"},
		Actions: []Action{{Kind: ActionWebhook}},
		Enabled: true,
	})

	// Fire once to populate lastFire + fires counters; Remove must
	// clear both alongside the rule itself.
	eng.Handle(audit.Entry{Tool: "t"})
	if fires != 1 {
		t.Fatalf("pre-Remove fires=%d want 1", fires)
	}
	if got := eng.List(); len(got) != 1 {
		t.Fatalf("pre-Remove List len=%d want 1", len(got))
	}

	eng.Remove("r")

	if got := eng.List(); len(got) != 0 {
		t.Fatalf("post-Remove List len=%d want 0", len(got))
	}
	// Subsequent events for the removed rule must not fire its action.
	eng.Handle(audit.Entry{Tool: "t"})
	if fires != 1 {
		t.Errorf("post-Remove fires=%d want 1 (no new fires)", fires)
	}

	// Remove of an unknown rule is a documented no-op.
	eng.Remove("does-not-exist")
}

func TestEngine_Test(t *testing.T) {
	eng := New(Deps{})
	eng.Register(Rule{
		Name:    "r",
		Match:   Match{Risk: "critical"},
		Actions: []Action{{Kind: ActionLog, Params: map[string]interface{}{"message": "saw {{tool}}"}}},
		Enabled: true,
	})
	out, err := eng.Test("r", audit.Entry{Tool: "x"})
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if len(out) != 1 || out[0] != "log: saw x" {
		t.Errorf("render output = %v", out)
	}
}

func TestEngine_NilHooksDontCrash(t *testing.T) {
	eng := New(Deps{})
	eng.Register(Rule{
		Name: "r", Match: Match{Tool: "t"},
		Actions: []Action{
			{Kind: ActionWebhook, Webhook: "x"},
			{Kind: ActionTool, Tool: "x"},
		},
		Enabled: true,
	})
	// Must not panic when Deps are nil.
	eng.Handle(audit.Entry{Tool: "t"})
}

func TestEngine_ToolActionInvokesRunner(t *testing.T) {
	var (
		mu     sync.Mutex
		called bool
		got    string
	)
	eng := New(Deps{
		RunTool: func(_ context.Context, tool string, _ map[string]interface{}) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			called = true
			got = tool
			return "", nil
		},
	})
	eng.Register(Rule{
		Name:    "r",
		Match:   Match{Tool: "trigger"},
		Actions: []Action{{Kind: ActionTool, Tool: "vibro"}},
		Enabled: true,
	})
	eng.Handle(audit.Entry{Tool: "trigger"})

	// Tool action fires on a goroutine; wait briefly.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		if called {
			mu.Unlock()
			break
		}
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if !called {
		t.Fatal("RunTool was not called")
	}
	if got != "vibro" {
		t.Errorf("tool=%q want vibro", got)
	}
}

// TestEngine_ToolActionSaturation verifies that once maxToolActions goroutines
// are in flight the engine drops additional triggers rather than spawning more.
func TestEngine_ToolActionSaturation(t *testing.T) {
	const total = maxToolActions + 3 // try to spawn more than the cap

	// Block all goroutines until we release them so we can control the count
	// of concurrent in-flight actions.
	gate := make(chan struct{})
	var mu sync.Mutex
	var called []string

	eng := New(Deps{
		RunTool: func(_ context.Context, tool string, _ map[string]interface{}) (string, error) {
			<-gate // block until released
			mu.Lock()
			called = append(called, tool)
			mu.Unlock()
			return "", nil
		},
	})
	eng.Register(Rule{
		Name:    "sat",
		Match:   Match{Tool: "trigger"},
		Actions: []Action{{Kind: ActionTool, Tool: "slow_tool"}},
		Enabled: true,
	})

	// Trigger total times; each fires a goroutine that blocks on gate.
	for i := 0; i < total; i++ {
		eng.Handle(audit.Entry{Tool: "trigger"})
	}

	// Give goroutines time to start and hit the gate.
	time.Sleep(50 * time.Millisecond)

	// The in-flight count must not exceed the cap.
	if got := eng.inFlight.Load(); got > maxToolActions {
		t.Errorf("inFlight=%d exceeds cap %d", got, maxToolActions)
	}

	// Release all blocked goroutines.
	close(gate)

	// Wait for them to finish.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if eng.inFlight.Load() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if eng.inFlight.Load() != 0 {
		t.Errorf("inFlight=%d after release, expected 0", eng.inFlight.Load())
	}

	// The number of actual RunTool calls must be <= maxToolActions.
	mu.Lock()
	n := len(called)
	mu.Unlock()
	if n > maxToolActions {
		t.Errorf("RunTool called %d times, want <= %d (cap)", n, maxToolActions)
	}
}

// TestEngine_ToolActionSaturation_ConcurrentHandle pins the v0.142
// fix: the in-flight cap must hold even when Handle is invoked from
// multiple goroutines simultaneously. Pre-fix the check was
// Load() + Add() in two steps, and concurrent firers could both pass
// the boundary check at inFlight=maxToolActions-1 and then both Add(1)
// — leaving inFlight at cap+1. Under `go test -race -count=50` this
// reliably reproduced (inFlight=9 with cap=8). The fix is an atomic
// Add(1) + rollback-if-over.
func TestEngine_ToolActionSaturation_ConcurrentHandle(t *testing.T) {
	const total = maxToolActions + 16 // overshoot heavily so any race window lands
	gate := make(chan struct{})
	eng := New(Deps{
		RunTool: func(_ context.Context, _ string, _ map[string]interface{}) (string, error) {
			<-gate
			return "", nil
		},
	})
	eng.Register(Rule{
		Name:    "sat-concurrent",
		Match:   Match{Tool: "trigger"},
		Actions: []Action{{Kind: ActionTool, Tool: "slow_tool"}},
		Enabled: true,
	})

	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			eng.Handle(audit.Entry{Tool: "trigger"})
		}()
	}
	wg.Wait()
	time.Sleep(50 * time.Millisecond) // let any racing Add(1) land

	if got := eng.inFlight.Load(); got > maxToolActions {
		t.Fatalf("inFlight=%d exceeds cap %d (concurrent Handle overran the gate)", got, maxToolActions)
	}
	close(gate)
}

// TestEngine_ToolActionPanicRecovered verifies that a panic inside a
// RunTool goroutine is caught by obs.SafeGo so the rules engine (daemon)
// keeps running and can fire subsequent rules normally.
func TestEngine_ToolActionPanicRecovered(t *testing.T) {
	started := make(chan struct{})
	eng := New(Deps{
		RunTool: func(_ context.Context, tool string, _ map[string]interface{}) (string, error) {
			close(started)
			panic("deliberate test panic in tool")
		},
	})
	eng.Register(Rule{
		Name:    "panic_rule",
		Match:   Match{Tool: "panic_trigger"},
		Actions: []Action{{Kind: ActionTool, Tool: "panic_tool"}},
		Enabled: true,
	})

	eng.Handle(audit.Entry{Tool: "panic_trigger"})

	// Wait for the goroutine to start and panic.
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("tool goroutine did not start within 1s")
	}

	// Allow the panic/recover to complete.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if eng.inFlight.Load() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if eng.inFlight.Load() != 0 {
		t.Errorf("inFlight=%d after panic recovery, expected 0 (defer did not run)", eng.inFlight.Load())
	}
}

// TestRegister_DefaultsEnabledTrue pins the Rule docstring's contract:
// "Enabled defaults true when the rule is registered; flip it via
// Pause." Pre-this-fix Register stored the rule with whatever Enabled
// the caller had set — and Go's zero value for bool is false. So a
// caller writing the natural shape
//
//	eng.Register(rules.Rule{Name: "X", Match: ..., Actions: ...})
//
// would silently register a never-firing rule because Handle's
// `if !r.Enabled { continue }` skipped it. The fix forces
// cp.Enabled = true at Register time. Operators wanting an initially-
// paused rule still call Pause(name) afterwards.
func TestRegister_DefaultsEnabledTrue(t *testing.T) {
	var fires int
	eng := New(Deps{
		WebhookFire: func(_ string, _ map[string]any) { fires++ },
	})

	// Deliberately omit the Enabled field — exactly what the docstring
	// promises is safe to do.
	eng.Register(Rule{
		Name:    "default-on",
		Match:   Match{Tool: "tool_x"},
		Actions: []Action{{Kind: ActionWebhook, Webhook: "ops"}},
	})

	eng.Handle(audit.Entry{Tool: "tool_x"})
	if fires != 1 {
		t.Fatalf("rule with implicit-true Enabled did not fire: got %d webhook calls, want 1", fires)
	}

	// Sanity: explicit Enabled: false at Register-time is OVERRIDDEN
	// to true per the contract (operators wanting paused-at-register
	// call Pause afterwards). The previous "Enabled: false silently
	// kept off" path was the bug.
	eng.Register(Rule{
		Name:    "even-false-becomes-true",
		Match:   Match{Tool: "tool_y"},
		Actions: []Action{{Kind: ActionWebhook, Webhook: "ops"}},
		Enabled: false,
	})
	eng.Handle(audit.Entry{Tool: "tool_y"})
	if fires != 2 {
		t.Fatalf("Register did not normalise Enabled to true: got %d total fires after the second event, want 2", fires)
	}

	// And the Pause path — the documented way to disable a rule —
	// still works after the Register-time normalisation.
	if !eng.Pause("default-on") {
		t.Fatal("Pause returned false for a registered rule")
	}
	eng.Handle(audit.Entry{Tool: "tool_x"})
	if fires != 2 {
		t.Fatalf("paused rule fired anyway: got %d fires after Pause+Handle, want 2", fires)
	}
}

// --- Success tristate match tests added in v0.346 ---

func TestMatch_SuccessNil_MatchesBoth(t *testing.T) {
	var fires int
	eng := New(Deps{
		WebhookFire: func(_ string, _ map[string]any) { fires++ },
	})
	eng.Register(Rule{
		Name:    "any-outcome",
		Match:   Match{Tool: "scan", Success: nil},
		Actions: []Action{{Kind: ActionWebhook, Webhook: "ops"}},
	})
	eng.Handle(audit.Entry{Tool: "scan", Success: true})
	eng.Handle(audit.Entry{Tool: "scan", Success: false})
	if fires != 2 {
		t.Errorf("nil Success should match both outcomes: got %d fires, want 2", fires)
	}
}

func TestMatch_SuccessTrue_OnlyMatchesSuccess(t *testing.T) {
	var fires int
	eng := New(Deps{
		WebhookFire: func(_ string, _ map[string]any) { fires++ },
	})
	tr := true
	eng.Register(Rule{
		Name:    "success-only",
		Match:   Match{Tool: "scan", Success: &tr},
		Actions: []Action{{Kind: ActionWebhook, Webhook: "ops"}},
	})
	eng.Handle(audit.Entry{Tool: "scan", Success: true})
	eng.Handle(audit.Entry{Tool: "scan", Success: false})
	if fires != 1 {
		t.Errorf("Success=true should match only successes: got %d fires, want 1", fires)
	}
}

func TestMatch_SuccessFalse_OnlyMatchesFailure(t *testing.T) {
	var fires int
	eng := New(Deps{
		WebhookFire: func(_ string, _ map[string]any) { fires++ },
	})
	f := false
	eng.Register(Rule{
		Name:    "failure-only",
		Match:   Match{Tool: "scan", Success: &f},
		Actions: []Action{{Kind: ActionWebhook, Webhook: "ops"}},
	})
	eng.Handle(audit.Entry{Tool: "scan", Success: true})
	eng.Handle(audit.Entry{Tool: "scan", Success: false})
	if fires != 1 {
		t.Errorf("Success=false should match only failures: got %d fires, want 1", fires)
	}
}

func TestMatch_SuccessFalse_CombinedWithRisk(t *testing.T) {
	var fires int
	eng := New(Deps{
		WebhookFire: func(_ string, _ map[string]any) { fires++ },
	})
	f := false
	eng.Register(Rule{
		Name:    "high-risk-failures",
		Match:   Match{Risk: "high", Success: &f},
		Actions: []Action{{Kind: ActionWebhook, Webhook: "ops"}},
	})
	eng.Handle(audit.Entry{Tool: "a", Risk: "high", Success: true})
	eng.Handle(audit.Entry{Tool: "b", Risk: "low", Success: false})
	eng.Handle(audit.Entry{Tool: "c", Risk: "high", Success: false})
	if fires != 1 {
		t.Errorf("expected 1 fire (high+failed), got %d", fires)
	}
}

func TestMatch_SuccessTrue_CombinedWithToolGlob(t *testing.T) {
	var fires int
	eng := New(Deps{
		WebhookFire: func(_ string, _ map[string]any) { fires++ },
	})
	tr := true
	eng.Register(Rule{
		Name:    "workflow-successes",
		Match:   Match{Tool: "workflow_*", Success: &tr},
		Actions: []Action{{Kind: ActionWebhook, Webhook: "ops"}},
	})
	eng.Handle(audit.Entry{Tool: "workflow_recon", Success: true})
	eng.Handle(audit.Entry{Tool: "workflow_recon", Success: false})
	eng.Handle(audit.Entry{Tool: "rfid_read", Success: true})
	if fires != 1 {
		t.Errorf("expected 1 fire (workflow_* + success), got %d", fires)
	}
}
