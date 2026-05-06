package cost

import (
	"testing"
)

// TestSetBudget_FiresWarnAndHitOnce locks the v0.21.0 budget contract:
// the 80% callback fires exactly once when the threshold is first
// crossed, and the 100% callback fires exactly once when the cap is
// reached. Subsequent AddUsage calls do not re-fire either callback
// — the operator gets one notification per threshold per session.
func TestSetBudget_FiresWarnAndHitOnce(t *testing.T) {
	pricer := NewPricer(nil)
	tr := NewTracker(pricer, "claude-sonnet-4-6", nil)

	var warns, hits int
	tr.SetBudget(1.00, // $1 cap
		func(_, _ float64) { warns++ },
		func(_, _ float64) { hits++ },
	)

	// Synthesise spend in stages. Sonnet input is ~$3/MTok, output
	// ~$15/MTok in the default pricer table; AddUsage with output
	// tokens lands quickly. Use direct setter via internal AddUsage
	// to keep the test independent of the price table specifics by
	// inspecting tr.totalUSD-equivalent through Snapshot.

	// Push to ~$0.50 — below 80%, no callbacks yet.
	tr.AddUsageFull(0, 33333, 0, 0) // 33k output @ $15/MTok ≈ $0.50
	if warns != 0 || hits != 0 {
		t.Fatalf("below 80%%: warns=%d hits=%d, want 0/0", warns, hits)
	}

	// Push to ~$0.85 — crosses 80%, warn fires once.
	tr.AddUsageFull(0, 23333, 0, 0) // +$0.35
	if warns != 1 {
		t.Errorf("after crossing 80%%: warns=%d, want 1", warns)
	}
	if hits != 0 {
		t.Errorf("after crossing 80%%: hits=%d, want 0", hits)
	}

	// More spend below 100% — no additional warn.
	tr.AddUsageFull(0, 5000, 0, 0)
	if warns != 1 {
		t.Errorf("after second sub-100%% spend: warns=%d, want still 1 (one-shot)", warns)
	}

	// Push past 100% — hit fires once.
	tr.AddUsageFull(0, 50000, 0, 0)
	if hits != 1 {
		t.Errorf("after crossing 100%%: hits=%d, want 1", hits)
	}

	// Even more spend — hit does not re-fire.
	tr.AddUsageFull(0, 100000, 0, 0)
	if hits != 1 {
		t.Errorf("after second post-100%% spend: hits=%d, want still 1", hits)
	}
}

// TestSetBudget_NoBudget_NoCallbacks verifies the historic behaviour:
// without a budget configured, neither callback fires regardless of
// spend.
func TestSetBudget_NoBudget_NoCallbacks(t *testing.T) {
	pricer := NewPricer(nil)
	tr := NewTracker(pricer, "claude-opus-4-7", nil)

	var fired bool
	tr.SetBudget(0,
		func(_, _ float64) { fired = true },
		func(_, _ float64) { fired = true },
	)

	// Lots of expensive spend.
	tr.AddUsageFull(1_000_000, 1_000_000, 0, 0)
	if fired {
		t.Error("no budget configured but a callback fired")
	}
}

// TestBudgetExceeded_ReportsOverCapState checks the gate predicate
// the agent uses to refuse new turns past 100%.
func TestBudgetExceeded_ReportsOverCapState(t *testing.T) {
	pricer := NewPricer(nil)
	tr := NewTracker(pricer, "claude-sonnet-4-6", nil)
	tr.SetBudget(1.00, nil, nil)

	if tr.BudgetExceeded() {
		t.Error("fresh tracker with budget should not be exceeded")
	}
	tr.AddUsageFull(0, 75000, 0, 0) // ~$1.13 at Sonnet output rate
	if !tr.BudgetExceeded() {
		t.Error("tracker over $1 cap should report exceeded")
	}
}

// TestSetBudget_RaisingCapResetsFlags locks the operator-bump
// behaviour: when the operator extends the cap clear of current
// spend, the warned/hit flags reset so future thresholds re-fire.
func TestSetBudget_RaisingCapResetsFlags(t *testing.T) {
	pricer := NewPricer(nil)
	tr := NewTracker(pricer, "claude-sonnet-4-6", nil)

	var warns int
	tr.SetBudget(1.00, func(_, _ float64) { warns++ }, nil)

	tr.AddUsageFull(0, 55000, 0, 0) // crosses 80%
	if warns != 1 {
		t.Fatalf("first warn: warns=%d", warns)
	}

	// Operator bumps cap to $5 (well above current ~$0.83 spend).
	tr.SetBudget(5.00, func(_, _ float64) { warns++ }, nil)

	// Push past 80% of the new cap (~$4).
	tr.AddUsageFull(0, 250000, 0, 0)
	if warns != 2 {
		t.Errorf("after raised-cap re-cross: warns=%d, want 2 (flag should reset on bump)", warns)
	}
}

// TestBudget_SnapshotExposesCap ensures the budget surfaces in the
// Snapshot so /cost / /status can render it.
func TestBudget_SnapshotExposesCap(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.SetBudget(2.50, nil, nil)
	if got := tr.Snapshot().BudgetUSD; got != 2.50 {
		t.Errorf("Snapshot.BudgetUSD = %v, want 2.50", got)
	}
}

// TestUpdateBudgetCap_ChangesCapPreservesCallbacks asserts that
// /budget set <USD> bumps the cap and lets the existing warn/hit
// callbacks (wired once at setup) fire fresh after re-crossing.
func TestUpdateBudgetCap_ChangesCapPreservesCallbacks(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	var warns, hits int
	tr.SetBudget(1.00, func(_, _ float64) { warns++ }, func(_, _ float64) { hits++ })

	tr.AddUsageFull(0, 70000, 0, 0) // crosses both at $1 cap
	if warns != 1 || hits != 1 {
		t.Fatalf("first crossing: warns=%d hits=%d", warns, hits)
	}

	// Operator bumps the cap mid-session via /budget set 5
	tr.UpdateBudgetCap(5.00)
	if got := tr.Snapshot().BudgetUSD; got != 5.00 {
		t.Errorf("BudgetUSD after UpdateBudgetCap = %v, want 5.00", got)
	}
	if tr.BudgetExceeded() {
		t.Error("BudgetExceeded() = true after raising cap above current spend")
	}

	// New crossing past 80% of the new cap should fire the original
	// callbacks again — they were not replaced.
	tr.AddUsageFull(0, 250000, 0, 0)
	if warns != 2 {
		t.Errorf("after new-cap re-cross: warns=%d, want 2 (callbacks lost across UpdateBudgetCap?)", warns)
	}
}

// TestUpdateBudgetCap_DisableSetsZero verifies /budget off resets the
// cap to 0 (no budget gate) without touching accumulated spend.
func TestUpdateBudgetCap_DisableSetsZero(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.SetBudget(1.00, nil, nil)
	tr.AddUsageFull(0, 80000, 0, 0) // crosses 100% at $1
	if !tr.BudgetExceeded() {
		t.Fatal("precondition: BudgetExceeded should be true")
	}
	tr.UpdateBudgetCap(0)
	if tr.BudgetExceeded() {
		t.Error("BudgetExceeded() = true after disabling cap")
	}
	if got := tr.Snapshot().BudgetUSD; got != 0 {
		t.Errorf("BudgetUSD after disable = %v, want 0", got)
	}
}

// TestSnapshot_FormatRendersBudget asserts /cost surfaces the
// budget=$spent/$cap (pct%) block when a budget is set.
func TestSnapshot_FormatRendersBudget(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.SetBudget(2.00, nil, nil)
	tr.AddUsageFull(0, 80000, 0, 0) // ~$1.20 → 60%

	out := tr.Snapshot().Format()
	if !contains(out, "budget=$") {
		t.Errorf("Format() = %q, want budget block", out)
	}
	if !contains(out, "/$2.00") {
		t.Errorf("Format() = %q, want cap rendered as $2.00", out)
	}
}

// TestSnapshot_FormatOmitsBudgetWhenZero asserts /cost stays terse when
// no budget is configured (operators that never set --budget).
func TestSnapshot_FormatOmitsBudgetWhenZero(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.AddUsageFull(0, 1000, 0, 0)

	out := tr.Snapshot().Format()
	if contains(out, "budget=") {
		t.Errorf("Format() = %q, should not render budget block when cap is 0", out)
	}
}
