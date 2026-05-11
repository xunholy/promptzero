package agent

import (
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

// setters_test.go covers the 0%-tested setter / accessor surface
// on Agent plus the ConfirmDelayGate helper and hasWiFiTool
// classifier. These are not feature-tests — they're contract pins
// for the glue that wires hardware clients into the agent at boot
// time. A regression here silently leaves the agent without its
// transport pointer.

// TestAgentHardwareSetters pins the per-transport attach/detach
// surface. Each Set… stores its argument verbatim (no validation,
// nil acceptable — the dependency-gate helpers downstream check
// nil). The companion getters return the same pointer.
func TestAgentHardwareSetters(t *testing.T) {
	a := NewForTest("test-model")

	// Marauder: Set + Get round-trip, then clear.
	if a.Marauder() != nil {
		t.Errorf("fresh agent Marauder() = %v, want nil", a.Marauder())
	}
	// Use a sentinel non-nil pointer; we can't construct a real
	// marauder.Marauder without a port, so dereference is forbidden
	// — but the setter / getter don't dereference.
	a.SetMarauder(nil) // explicit nil-store should still be a no-op
	if a.Marauder() != nil {
		t.Errorf("after SetMarauder(nil): Marauder() = %v, want nil", a.Marauder())
	}

	// Bruce / Faultier / BusPirate / Generator / GenLLM all accept
	// nil today; the test confirms the setter doesn't panic on nil.
	a.SetBruce(nil)
	a.SetFaultier(nil)
	a.SetBusPirate(nil)
	a.SetGenerator(nil)
	a.SetGenLLM(nil)
}

// TestAgentPersonaReset pins Reset clears history. The agent's
// history field is unexported, so we use HistorySnapshot to
// observe it. Empty agent → empty snapshot; Reset() on an empty
// agent stays empty (no panic).
func TestAgentPersonaReset(t *testing.T) {
	a := NewForTest("test-model")
	if got := HistorySnapshot(a); got != "" {
		t.Errorf("fresh agent HistorySnapshot = %q, want empty", got)
	}
	a.Reset()
	if got := HistorySnapshot(a); got != "" {
		t.Errorf("Reset on empty agent: HistorySnapshot = %q, want empty", got)
	}
}

// TestAgentPersonaAccessors pins the Persona / PersonaSnapshot
// dual-read pattern. Persona() takes the mutex; PersonaSnapshot()
// reads the atomic pointer for hot-path callers that can't block.
// Both return nil for an agent with no persona installed.
func TestAgentPersonaAccessors(t *testing.T) {
	a := NewForTest("test-model")
	if got := a.Persona(); got != nil {
		t.Errorf("fresh agent Persona() = %v, want nil", got)
	}
	if got := a.PersonaSnapshot(); got != nil {
		t.Errorf("fresh agent PersonaSnapshot() = %v, want nil", got)
	}

	// SetPersona(nil) should leave the persona empty.
	a.SetPersona(nil)
	if got := a.Persona(); got != nil {
		t.Errorf("after SetPersona(nil): Persona() = %v, want nil", got)
	}
}

// TestAgentUIContext pins the web-UI navigation-state plumbing.
// SetUIContext stores; UIContext returns the last stored value;
// the default (never-set) state returns empty strings.
func TestAgentUIContext(t *testing.T) {
	a := NewForTest("test-model")

	v, p := a.UIContext()
	if v != "" || p != "" {
		t.Errorf("fresh UIContext = (%q, %q), want both empty", v, p)
	}

	a.SetUIContext("scan", "/web/scan")
	v, p = a.UIContext()
	if v != "scan" || p != "/web/scan" {
		t.Errorf("after SetUIContext: (%q, %q), want (scan, /web/scan)", v, p)
	}

	// Later set overrides earlier.
	a.SetUIContext("home", "/")
	v, p = a.UIContext()
	if v != "home" || p != "/" {
		t.Errorf("after override: (%q, %q), want (home, /)", v, p)
	}
}

// TestAgentSetDetectorEngine pins that SetDetectorEngine accepts
// nil without panic. Real DetectorEngine wiring is exercised by
// the rules / agent integration tests; this test only confirms
// the setter doesn't crash on the disable-detection case.
func TestAgentSetDetectorEngine(t *testing.T) {
	a := NewForTest("test-model")
	a.SetDetectorEngine(nil) // disable: must not panic
}

// TestAgentSetCallbacks pins the four single-line setter
// helpers: SetToolStatusCallback, SetTextDeltaCallback,
// SetUsageCallback, SetStreamErrorCallback. Each is a verbatim
// field assignment; nil-installs clear the callback.
func TestAgentSetCallbacks(t *testing.T) {
	a := NewForTest("test-model")
	// Set with non-nil, then clear with nil. No way to observe
	// the field externally, so we're confirming no-panic only.
	a.SetToolStatusCallback(func(_ ToolEvent) {})
	a.SetToolStatusCallback(nil)
	a.SetTextDeltaCallback(func(_ TextDelta) {})
	a.SetTextDeltaCallback(nil)
	a.SetUsageCallback(func(_ Usage) {})
	a.SetUsageCallback(nil)
	a.SetStreamErrorCallback(func(_ error) {})
	a.SetStreamErrorCallback(nil)
}

// TestAgentSetConfirmIdleTimeout pins the confirm-idle setter.
// Negative / zero values are accepted (the actual idle-deadline
// logic in confirmWithIdleTimeout floors a non-positive value to
// the default at call time). Positive values store verbatim.
func TestAgentSetConfirmIdleTimeout(t *testing.T) {
	a := NewForTest("test-model")
	a.SetConfirmIdleTimeout(0)
	a.SetConfirmIdleTimeout(-1 * time.Second)
	a.SetConfirmIdleTimeout(10 * time.Second)
}

// TestHasWiFiTool pins the helper that flips on wifi-framing
// when at least one wifi_* tool is in the catalog. Empty
// catalog → false; mixed catalog with wifi_scan_ap → true;
// non-WiFi-only catalog → false. Nil OfTool entries are
// tolerated (skipped via the OfTool == nil guard).
func TestHasWiFiTool(t *testing.T) {
	mk := func(name string) anthropic.ToolUnionParam {
		return anthropic.ToolUnionParam{OfTool: &anthropic.ToolParam{Name: name}}
	}

	t.Run("empty", func(t *testing.T) {
		if hasWiFiTool(nil) {
			t.Error("hasWiFiTool(nil) = true, want false")
		}
		if hasWiFiTool([]anthropic.ToolUnionParam{}) {
			t.Error("hasWiFiTool([]) = true, want false")
		}
	})
	t.Run("wifi_present", func(t *testing.T) {
		tools := []anthropic.ToolUnionParam{
			mk("device_info"),
			mk("wifi_scan_ap"),
			mk("subghz_transmit"),
		}
		if !hasWiFiTool(tools) {
			t.Error("hasWiFiTool with wifi_scan_ap = false, want true")
		}
	})
	t.Run("no_wifi", func(t *testing.T) {
		tools := []anthropic.ToolUnionParam{
			mk("device_info"),
			mk("subghz_transmit"),
			mk("nfc_emulate"),
		}
		if hasWiFiTool(tools) {
			t.Error("hasWiFiTool without wifi_* = true, want false")
		}
	})
	t.Run("nil_OfTool_skipped", func(t *testing.T) {
		// An entry with OfTool=nil must be skipped without panic.
		tools := []anthropic.ToolUnionParam{
			{OfTool: nil},
			mk("wifi_scan_ap"),
		}
		if !hasWiFiTool(tools) {
			t.Error("hasWiFiTool tolerant skip on nil OfTool failed")
		}
	})
	t.Run("only_nil_OfTool", func(t *testing.T) {
		tools := []anthropic.ToolUnionParam{{OfTool: nil}, {OfTool: nil}}
		if hasWiFiTool(tools) {
			t.Error("hasWiFiTool on all-nil OfTool = true, want false")
		}
	})
}

// TestConfirmDelayGate pins the 2-second pre-approval window used
// by the high-risk-confirm UX. Before Show() the gate is closed
// (full delay remains); after Show() the remaining time counts
// down; Open() reports the gate state.
func TestConfirmDelayGate(t *testing.T) {
	t.Run("before_Show_closed", func(t *testing.T) {
		g := NewConfirmDelayGate(500 * time.Millisecond)
		if g.Open() {
			t.Error("before Show(): Open() = true, want false")
		}
		if g.Remaining() != 500*time.Millisecond {
			t.Errorf("before Show(): Remaining() = %v, want 500ms (full delay)", g.Remaining())
		}
	})

	t.Run("zero_delay_open_immediately", func(t *testing.T) {
		g := NewConfirmDelayGate(0)
		// Zero delay: even without Show(), Remaining() returns 0
		// — Open() is true.
		if !g.Open() {
			t.Errorf("zero-delay gate: Open() = false, want true (Remaining=%v)", g.Remaining())
		}
	})

	t.Run("after_Show_then_wait", func(t *testing.T) {
		g := NewConfirmDelayGate(50 * time.Millisecond)
		g.Show()
		if g.Open() {
			t.Error("immediately after Show(): Open() = true, want false")
		}

		// Wait past the delay window. 100ms > 50ms.
		time.Sleep(100 * time.Millisecond)
		if !g.Open() {
			t.Errorf("after delay elapsed: Open() = false (Remaining=%v)", g.Remaining())
		}
	})

	t.Run("Show_resets_clock", func(t *testing.T) {
		g := NewConfirmDelayGate(50 * time.Millisecond)
		g.Show()
		time.Sleep(30 * time.Millisecond)
		// Re-show — clock should reset; gate still closed.
		g.Show()
		if g.Open() {
			t.Error("Show() after partial wait should reset clock; Open() = true unexpectedly")
		}
	})

	t.Run("injectable_now_for_determinism", func(t *testing.T) {
		// The now field is an injection point; tests can pin time
		// without sleep. Inject a fixed clock that's well past the
		// delay, simulating the gate-open state.
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		g := &ConfirmDelayGate{
			delay: 1 * time.Second,
			now:   func() time.Time { return base },
		}
		g.Show() // shownAt = base
		// Advance the clock by 2 seconds — past delay.
		g.now = func() time.Time { return base.Add(2 * time.Second) }
		if !g.Open() {
			t.Errorf("with injected clock past delay: Open() = false (Remaining=%v)", g.Remaining())
		}
	})
}
