package main

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/cost"
	flippermock "github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/testmocks"
)

func TestHandleValidate_NoPath_ShowsUsage(t *testing.T) {
	// dispatchSlashCommand sends the usage hint when the user omits the
	// path argument. Exercise it end-to-end so the public entry point stays
	// wired.
	flip := testmocks.NewMockFlipper(t)
	deps := &REPLDeps{flip: flip, ed: newLineEditor(&termUI{enabled: false})}

	out := captureStderr(t, func() {
		handled, exit := dispatchSlashCommand("/validate", deps)
		if !handled {
			t.Fatalf("/validate with no args should be handled")
		}
		if exit {
			t.Fatalf("/validate should not trigger REPL exit")
		}
	})
	if !strings.Contains(out, "usage: /validate") {
		t.Fatalf("usage line missing: %q", out)
	}
}

func TestHandleValidate_CleanPayload(t *testing.T) {
	payload := "REM benign demo\nDELAY 500\nSTRING hello world\n"
	flip := testmocks.NewMockFlipper(t, testmocks.WithFlipperHandler("storage", func(args []string) string {
		if len(args) >= 1 && args[0] == "read" {
			return payload
		}
		return ""
	}))

	out := captureStderr(t, func() {
		handleValidate(flip, "/ext/badusb/demo.txt")
	})

	if !strings.Contains(out, "no findings") {
		t.Fatalf("expected 'no findings' for clean payload, got:\n%s", out)
	}
}

func TestHandleValidate_CriticalPayload(t *testing.T) {
	// rm -rf / on a STRING line — exactly the shape badusb_validate is
	// meant to flag before the Flipper types it.
	payload := "STRING rm -rf /\n"
	flip := testmocks.NewMockFlipper(t, testmocks.WithFlipperHandler("storage", func(args []string) string {
		if len(args) >= 1 && args[0] == "read" {
			return payload
		}
		return ""
	}))

	out := captureStderr(t, func() {
		handleValidate(flip, "/ext/badusb/bad.txt")
	})

	if !strings.Contains(out, "critical") {
		t.Fatalf("expected critical severity label, got:\n%s", out)
	}
	if !strings.Contains(out, "rm -rf /") {
		t.Fatalf("expected payload excerpt in output, got:\n%s", out)
	}
}

func TestHandleValidate_NilFlipper(t *testing.T) {
	// handleValidate defends against being called without a connected
	// Flipper (e.g. when the REPL starts in a degraded state).
	out := captureStderr(t, func() {
		handleValidate(nil, "/ext/badusb/demo.txt")
	})
	if !strings.Contains(out, "needs a connected Flipper") {
		t.Fatalf("expected guard message, got:\n%s", out)
	}
}

// Ensure flippermock import stays referenced if the handler type changes.
var _ flippermock.Handler = func(args []string) string { return "" }

// TestBudget_NoArgs_ShowsDisabled verifies /budget with no args and no
// cap configured renders the "disabled" state with a hint. Locks the
// printBudget output so a future refactor doesn't strand operators.
func TestBudget_NoArgs_ShowsDisabled(t *testing.T) {
	tracker := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	deps := &REPLDeps{
		ed:          newLineEditor(&termUI{enabled: false}),
		costTracker: tracker,
	}
	out := captureStderr(t, func() {
		handleBudget(deps, nil)
	})
	if !strings.Contains(out, "disabled") {
		t.Errorf("expected 'disabled' in output, got: %q", out)
	}
	if !strings.Contains(out, "/budget set") {
		t.Errorf("expected hint to /budget set, got: %q", out)
	}
}

// TestBudget_SetParsesDollarPrefix accepts both "/budget set 5" and
// "/budget set $5" so operators don't have to remember which form the
// command expects.
func TestBudget_SetParsesDollarPrefix(t *testing.T) {
	tracker := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	deps := &REPLDeps{
		ed:          newLineEditor(&termUI{enabled: false}),
		costTracker: tracker,
	}
	out := captureStderr(t, func() {
		handleBudget(deps, []string{"set", "$2.50"})
	})
	if got := tracker.Snapshot().BudgetUSD; got != 2.50 {
		t.Errorf("BudgetUSD = %v, want 2.50 (dollar prefix should be stripped)", got)
	}
	if !strings.Contains(out, "$2.50") {
		t.Errorf("confirmation should echo the cap, got: %q", out)
	}
}

// TestBudget_SetRejectsGarbage covers the parse-failure branch — a
// non-numeric arg should produce the error message and leave the tracker
// untouched.
func TestBudget_SetRejectsGarbage(t *testing.T) {
	tracker := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	tracker.SetBudget(1.00, nil, nil)
	deps := &REPLDeps{
		ed:          newLineEditor(&termUI{enabled: false}),
		costTracker: tracker,
	}
	out := captureStderr(t, func() {
		handleBudget(deps, []string{"set", "abc"})
	})
	if !strings.Contains(out, "not a non-negative number") {
		t.Errorf("expected parse-error message, got: %q", out)
	}
	if got := tracker.Snapshot().BudgetUSD; got != 1.00 {
		t.Errorf("BudgetUSD = %v, want 1.00 — garbage arg shouldn't mutate cap", got)
	}
}

// TestBudget_OffDisablesCap covers the off/clear/disable aliases — all
// three should set the cap to 0.
func TestBudget_OffDisablesCap(t *testing.T) {
	for _, alias := range []string{"off", "clear", "disable"} {
		t.Run(alias, func(t *testing.T) {
			tracker := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
			tracker.SetBudget(5.00, nil, nil)
			deps := &REPLDeps{
				ed:          newLineEditor(&termUI{enabled: false}),
				costTracker: tracker,
			}
			handleBudget(deps, []string{alias})
			if got := tracker.Snapshot().BudgetUSD; got != 0 {
				t.Errorf("alias %q: BudgetUSD = %v, want 0", alias, got)
			}
		})
	}
}

// /forget without an id should print the usage hint via dispatchSlashCommand
// and not exit the REPL. Exercises the dispatcher path so a future rename
// of /forget can't silently strand it.
func TestForget_NoArgs_ShowsUsage(t *testing.T) {
	deps := &REPLDeps{ed: newLineEditor(&termUI{enabled: false})}

	out := captureStderr(t, func() {
		handled, exit := dispatchSlashCommand("/forget", deps)
		if !handled {
			t.Fatalf("/forget with no args should be handled")
		}
		if exit {
			t.Fatalf("/forget should not trigger REPL exit")
		}
	})
	if !strings.Contains(out, "usage: /forget") {
		t.Fatalf("usage line missing: %q", out)
	}
}
