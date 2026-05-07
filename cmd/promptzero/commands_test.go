package main

import (
	"strings"
	"testing"
	"time"

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

// TestDispatch_UnknownSlashCommand catches the typo trap. Without
// the guard the REPL fell through on /budgett (typo of /budget) and
// sent the literal text to Claude as a question. Now it's caught
// locally with a hint at /help.
func TestDispatch_UnknownSlashCommand(t *testing.T) {
	deps := &REPLDeps{ed: newLineEditor(&termUI{enabled: false})}
	out := captureStderr(t, func() {
		handled, exit := dispatchSlashCommand("/budgett", deps)
		if !handled {
			t.Fatal("/budgett should be handled (with error message)")
		}
		if exit {
			t.Fatal("/budgett should not exit")
		}
	})
	if !strings.Contains(out, "unknown command") {
		t.Errorf("expected 'unknown command' in output, got: %q", out)
	}
	if !strings.Contains(out, "/help") {
		t.Errorf("expected '/help' hint in output, got: %q", out)
	}
}

// TestDispatch_NonSlashStillPassesThrough confirms a regular prompt
// (no leading "/") is NOT swallowed by the unknown-command guard.
// Returning false here is what lets the REPL send the line to Claude.
func TestDispatch_NonSlashStillPassesThrough(t *testing.T) {
	deps := &REPLDeps{ed: newLineEditor(&termUI{enabled: false})}
	handled, _ := dispatchSlashCommand("scan the network", deps)
	if handled {
		t.Error("non-slash input should pass through (handled=false)")
	}
}

// TestDispatch_PassesThroughIncidentalSlashes covers the boundary
// between "operator typed a typo" and "operator's prompt happens to
// start with a slash". File paths, numeric expressions, and dashed
// strings should pass through untouched so they reach Claude.
func TestDispatch_PassesThroughIncidentalSlashes(t *testing.T) {
	deps := &REPLDeps{ed: newLineEditor(&termUI{enabled: false})}
	for _, in := range []string{"/dev/sda is broken", "/2 of these", "/budget-cap"} {
		t.Run(in, func(t *testing.T) {
			handled, _ := dispatchSlashCommand(in, deps)
			if handled {
				t.Errorf("%q should pass through, got handled=true", in)
			}
		})
	}
}

// TestLooksLikeSlashCommand discriminates between operator typos
// (caught with hint) and incidental leading slashes that should
// pass through to the agent.
func TestLooksLikeSlashCommand(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/budget", true},
		{"/forget", true},
		{"/Help", true}, // case-insensitive on the alpha part
		// Pass-throughs:
		{"/dev/sda", false},    // unix path — has more slashes
		{"/2", false},          // numeric — could be "/2 of these"
		{"/", false},           // bare slash
		{"/budget-cap", false}, // contains '-'
		{"hello", false},       // no leading slash
		{"", false},            // empty
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := looksLikeSlashCommand(c.in); got != c.want {
				t.Errorf("looksLikeSlashCommand(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestHumanSince covers the unit-step ladder for the /rules list
// "last X ago" annotation. The function drops sub-unit precision so
// the output stays compact at every scale from sub-second to days.
func TestHumanSince(t *testing.T) {
	cases := []struct {
		ago  time.Duration
		want string
	}{
		{500 * time.Millisecond, "now"},
		{12 * time.Second, "12s"},
		{90 * time.Second, "1m"},
		{45 * time.Minute, "45m"},
		{2 * time.Hour, "2h"},
		{25 * time.Hour, "1d"},
		{72 * time.Hour, "3d"},
	}
	for _, tc := range cases {
		got := humanSince(time.Now().Add(-tc.ago))
		if got != tc.want {
			t.Errorf("humanSince(now-%s) = %q, want %q", tc.ago, got, tc.want)
		}
	}
}

// TestNormaliseAttackIDs locks the /attack set id-format check.
// MITRE technique IDs are T followed by 4 digits, optionally
// .NNN for the sub-technique. The normaliser uppercases and trims
// whitespace so common operator paste mistakes survive.
func TestNormaliseAttackIDs(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		got, err := normaliseAttackIDs([]string{"T1557.004", "T1499", "T1078"})
		if err != nil {
			t.Fatalf("happy path: %v", err)
		}
		want := []string{"T1557.004", "T1499", "T1078"}
		if len(got) != len(want) {
			t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})
	t.Run("normalises_case_and_whitespace", func(t *testing.T) {
		got, err := normaliseAttackIDs([]string{"  t1557.004 ", "t1499"})
		if err != nil {
			t.Fatalf("normalise: %v", err)
		}
		if got[0] != "T1557.004" || got[1] != "T1499" {
			t.Errorf("got %v, want [T1557.004 T1499]", got)
		}
	})
	t.Run("skips_empty_entries", func(t *testing.T) {
		got, err := normaliseAttackIDs([]string{"", "   ", "T1018"})
		if err != nil {
			t.Fatalf("skip empties: %v", err)
		}
		if len(got) != 1 || got[0] != "T1018" {
			t.Errorf("got %v, want [T1018]", got)
		}
	})
	t.Run("rejects_malformed", func(t *testing.T) {
		for _, bad := range []string{
			"T155", "T15573", "T1557.04", "T1557.0040",
			"BogusID", "T1557-004", "1557",
		} {
			_, err := normaliseAttackIDs([]string{bad})
			if err == nil {
				t.Errorf("%q should error", bad)
			}
		}
	})
	t.Run("all_empty_errors", func(t *testing.T) {
		_, err := normaliseAttackIDs([]string{"", "  "})
		if err == nil {
			t.Error("all-empty input should error")
		}
	})
}

// TestParseWhen_RejectsNegativeDuration locks the future-timestamp
// guard. Go's time.ParseDuration accepts "-30m" as a valid negative
// duration. The old parseWhen happily computed time.Now() - (-30m)
// = time.Now() + 30m, returning a timestamp in the future. A "since"
// filter set to a future time matches no past audit rows — silent
// zero-row response with no signal to the operator that their
// "negative duration" had no sensible meaning.
func TestParseWhen_RejectsNegativeDuration(t *testing.T) {
	for _, in := range []string{"-30m", "-1h", "-2h30m"} {
		t.Run(in, func(t *testing.T) {
			_, err := parseWhen(in)
			if err == nil {
				t.Errorf("%q should error (negative duration)", in)
			}
		})
	}
}

// TestParseWhen_AcceptsValid covers the canonical happy paths so a
// future tightening doesn't accidentally break legitimate input.
func TestParseWhen_AcceptsValid(t *testing.T) {
	for _, in := range []string{"30m", "2h", "7d", "1m30s", "2026-05-07T00:00:00Z"} {
		t.Run(in, func(t *testing.T) {
			if _, err := parseWhen(in); err != nil {
				t.Errorf("%q should parse: %v", in, err)
			}
		})
	}
}

// TestParseAuditFilter_LimitCap rejects an oversized limit. Without
// the cap an operator typing limit=1000000 (typo or stress) would
// tie up SQLite for seconds and flood the terminal.
func TestParseAuditFilter_LimitCap(t *testing.T) {
	t.Run("at_cap_ok", func(t *testing.T) {
		f, err := parseAuditFilter([]string{"limit=10000"})
		if err != nil {
			t.Errorf("limit=10000 should parse, got: %v", err)
		}
		if f.Limit != 10000 {
			t.Errorf("Limit = %d, want 10000", f.Limit)
		}
	})
	t.Run("over_cap_errors", func(t *testing.T) {
		_, err := parseAuditFilter([]string{"limit=10001"})
		if err == nil {
			t.Error("limit=10001 should error")
		}
	})
	t.Run("way_over_cap_errors", func(t *testing.T) {
		_, err := parseAuditFilter([]string{"limit=1000000"})
		if err == nil {
			t.Error("limit=1000000 should error")
		}
	})
}

// TestParseAuditFilter_RiskValidation locks the canonical risk-string
// allowlist. A typo like "danger" or wrong case like "CRITICAL" used
// to silently match zero rows because SQLite's default LIKE/= is
// case-sensitive against the lowercase stored values. Validate at
// parse time and lowercase normalise so common variants work.
func TestParseAuditFilter_RiskValidation(t *testing.T) {
	t.Run("happy_path_lowercased", func(t *testing.T) {
		f, err := parseAuditFilter([]string{"risk=Critical"})
		if err != nil {
			t.Fatalf("Critical should normalise, got: %v", err)
		}
		if f.Risk != "critical" {
			t.Errorf("Risk = %q, want lowercase 'critical'", f.Risk)
		}
	})
	for _, v := range []string{"low", "medium", "high", "critical"} {
		t.Run(v, func(t *testing.T) {
			f, err := parseAuditFilter([]string{"risk=" + v})
			if err != nil {
				t.Fatalf("risk=%s should parse, got: %v", v, err)
			}
			if f.Risk != v {
				t.Errorf("Risk = %q, want %q", f.Risk, v)
			}
		})
	}
	for _, v := range []string{"danger", "moderate", "highest", ""} {
		t.Run("rejects_"+v, func(t *testing.T) {
			_, err := parseAuditFilter([]string{"risk=" + v})
			if err == nil {
				t.Errorf("risk=%q should error", v)
			}
		})
	}
}

// TestParseAuditFilter_SinceAfterUntilFails locks the swapped-pair
// guard. since=1h means "1 hour ago"; until=24h means "24 hours ago".
// A naïve operator typing them in that order gets a SQL clause that
// returns 0 rows. parseAuditFilter must reject this combination with
// a clear message rather than letting /audit find swallow the typo.
func TestParseAuditFilter_SinceAfterUntilFails(t *testing.T) {
	_, err := parseAuditFilter([]string{"since=1h", "until=24h"})
	if err == nil {
		t.Fatal("expected error for swapped since/until")
	}
	if !strings.Contains(err.Error(), "after until") {
		t.Errorf("expected 'after until' in error, got: %v", err)
	}
}

// TestParseAuditFilter_SinceBeforeUntilOK is the happy-path bookend —
// when the operator orders the bounds correctly the parser returns
// without complaint.
func TestParseAuditFilter_SinceBeforeUntilOK(t *testing.T) {
	if _, err := parseAuditFilter([]string{"since=24h", "until=1h"}); err != nil {
		t.Errorf("ordered since/until should parse cleanly, got: %v", err)
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
