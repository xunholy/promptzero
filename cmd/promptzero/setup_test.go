package main

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/risk"
)

// TestResolveConfirmRisk_Defaults pins the unconfigured-zero-flags
// path: empty cfg + empty flag + no yolo → confirm at High,
// gate enabled. This is the documented out-of-the-box behaviour.
func TestResolveConfirmRisk_Defaults(t *testing.T) {
	level, enabled, err := resolveConfirmRisk("", "", false)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if level != risk.High {
		t.Errorf("level = %v, want High", level)
	}
	if !enabled {
		t.Errorf("enabled = false, want true (gate is on by default)")
	}
}

// TestResolveConfirmRisk_FlagOverridesConfig confirms the precedence:
// --confirm-risk wins over the config-file value.
func TestResolveConfirmRisk_FlagOverridesConfig(t *testing.T) {
	level, _, err := resolveConfirmRisk("low", "critical", false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if level != risk.Critical {
		t.Errorf("level = %v, want Critical (flag should override config)", level)
	}
}

// TestResolveConfirmRisk_YoloDisablesGate covers the --yolo mode
// shortcut: gate disabled, threshold pinned to High (so the
// "still gate at critical" guarantee documented elsewhere holds —
// the disabled boolean is the actual escape hatch).
func TestResolveConfirmRisk_YoloDisablesGate(t *testing.T) {
	level, enabled, err := resolveConfirmRisk("low", "low", true)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if enabled {
		t.Errorf("enabled = true under --yolo, want false")
	}
	// Under YOLO the level value isn't actually consulted (gate
	// is off), but should be a sensible default rather than a
	// zero-value to avoid surprises if the gate is later
	// re-enabled at runtime.
	if level != risk.High {
		t.Errorf("level = %v under yolo, want High default", level)
	}
}

// TestResolveConfirmRisk_None covers the explicit "none" config
// value, which disables the gate without setting yolo. Same
// outcome as yolo: enabled=false, level pinned to High.
func TestResolveConfirmRisk_None(t *testing.T) {
	_, enabled, err := resolveConfirmRisk("none", "", false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if enabled {
		t.Errorf("enabled = true for confirm_risk=none, want false")
	}
}

// TestResolveConfirmRisk_AllLevels exercises each documented level
// string and confirms the matching risk.Level constant comes out.
func TestResolveConfirmRisk_AllLevels(t *testing.T) {
	cases := []struct {
		in   string
		want risk.Level
	}{
		{"low", risk.Low},
		{"medium", risk.Medium},
		{"high", risk.High},
		{"critical", risk.Critical},
		{"  HIGH  ", risk.High}, // whitespace + case-insensitive
		{"Medium", risk.Medium},
	}
	for _, c := range cases {
		level, enabled, err := resolveConfirmRisk(c.in, "", false)
		if err != nil {
			t.Errorf("level %q errored: %v", c.in, err)
			continue
		}
		if !enabled {
			t.Errorf("level %q produced enabled=false", c.in)
		}
		if level != c.want {
			t.Errorf("level %q = %v, want %v", c.in, level, c.want)
		}
	}
}

// TestResolveConfirmRisk_UnknownReturnsErrorPlusFallback covers
// the error path: typo'd level should error AND return a sensible
// fallback (High + enabled) so a misconfigured operator at least
// gets the safe-default gate on.
func TestResolveConfirmRisk_UnknownReturnsErrorPlusFallback(t *testing.T) {
	level, enabled, err := resolveConfirmRisk("crirtical", "", false)
	if err == nil {
		t.Fatal("expected error for typo'd risk level")
	}
	if !strings.Contains(err.Error(), "unknown confirm_risk") {
		t.Errorf("error %q should mention unknown confirm_risk", err.Error())
	}
	if level != risk.High {
		t.Errorf("fallback level = %v, want High (safe default)", level)
	}
	if !enabled {
		t.Errorf("fallback enabled = false; misconfigured operator should still get the gate on")
	}
}

// TestSetupBudget_WiresCallbacksEvenWithoutCap pins the v0.81 fix:
// when the operator starts with no --budget flag and no
// cost.budget_usd configured, setupBudget still installs the warn/hit
// callbacks on the tracker. Otherwise a later /budget set <USD> raises
// a cap that the threshold logic in (*Tracker).Add() never reports on,
// and operators silently lose the 80 / 100 percent banners.
//
// The companion ai.SetBudgetCheckCallback wiring lives in the same
// code path; agent-side enforcement is covered by
// internal/agent.TestBudgetCheckCallback_RefusesAtCap.
func TestSetupBudget_WiresCallbacksEvenWithoutCap(t *testing.T) {
	a := agent.NewForTest("claude-sonnet-4-6")
	tracker := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)

	// Unbudgeted start — neither the flag nor the config field sets a cap.
	cfg := &config.Config{}
	setupBudget(cfg, 0, a, tracker)

	// Operator raises a cap at runtime via /budget set 10. The threshold
	// callbacks must fire when spend crosses 80% and 100% — pre-fix they
	// were never installed because setupBudget returned early.
	tracker.UpdateBudgetCap(10.00)

	out := captureStderr(t, func() {
		// At $3/MTok input + $15/MTok output, 1M output tokens = $15.
		// One Add call crosses both the 80% and 100% thresholds, firing
		// both warn and hit callbacks in the same invocation.
		tracker.AddUsage(0, 1_000_000)
	})

	if !strings.Contains(out, "80% of budget") {
		t.Errorf("warn callback didn't fire after /budget set on unbudgeted start; stderr: %q", out)
	}
	if !strings.Contains(out, "BUDGET EXHAUSTED") {
		t.Errorf("hit callback didn't fire after /budget set on unbudgeted start; stderr: %q", out)
	}
	if !tracker.BudgetExceeded() {
		t.Errorf("BudgetExceeded() = false after spending $15 against a $10 cap")
	}
}

// TestSetupBudget_QuietWhenNoCap verifies the operator-visible banner
// stays gated on cap > 0. The callback wiring runs regardless (see
// the test above) but the "Session budget …" line would be misleading
// when no cap is set.
func TestSetupBudget_QuietWhenNoCap(t *testing.T) {
	a := agent.NewForTest("claude-sonnet-4-6")
	tracker := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	cfg := &config.Config{}

	out := captureStderr(t, func() {
		setupBudget(cfg, 0, a, tracker)
	})

	if strings.Contains(out, "Session budget") {
		t.Errorf("setupBudget with cap=0 should not print the budget banner; stderr: %q", out)
	}
}
