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
