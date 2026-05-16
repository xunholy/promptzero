package mode

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/tools"
)

// allKnownGroups enumerates every Group constant currently defined in
// the tools package — kept here as a literal slice so a future Group
// constant added without a corresponding mode allow-list update fails
// the coverage assertion in TestAllows_TableCoverage.
var allKnownGroups = []tools.Group{
	tools.GroupMetaAudit,
	tools.GroupMetaUtil,
	tools.GroupFlipperSystem,
	tools.GroupFlipperSubGHz,
	tools.GroupFlipperIR,
	tools.GroupFlipperNFC,
	tools.GroupFlipperRFID,
	tools.GroupFlipperIButton,
	tools.GroupFlipperBadUSB,
	tools.GroupFlipperHW,
	tools.GroupMarauderWiFi,
	tools.GroupGen,
	tools.GroupWorkflows,
	tools.GroupVision,
	tools.GroupSecurity,
	tools.GroupHostTools,
	tools.GroupBruce,
	tools.GroupFaultier,
}

// TestAllows_TableCoverage exhaustively checks Allows(group) for
// every (mode, group) pair. The expected matrix is hand-encoded so a
// regression in the allow-list (e.g. accidentally including
// GroupFlipperSubGHz in Recon) trips the table immediately.
func TestAllows_TableCoverage(t *testing.T) {
	type want struct {
		mode  Mode
		group tools.Group
		allow bool
	}

	cases := []want{
		// Standard: everything allowed.
		{ModeStandard, tools.GroupMetaAudit, true},
		{ModeStandard, tools.GroupMetaUtil, true},
		{ModeStandard, tools.GroupFlipperSystem, true},
		{ModeStandard, tools.GroupFlipperSubGHz, true},
		{ModeStandard, tools.GroupFlipperIR, true},
		{ModeStandard, tools.GroupFlipperNFC, true},
		{ModeStandard, tools.GroupFlipperRFID, true},
		{ModeStandard, tools.GroupFlipperIButton, true},
		{ModeStandard, tools.GroupFlipperBadUSB, true},
		{ModeStandard, tools.GroupFlipperHW, true},
		{ModeStandard, tools.GroupMarauderWiFi, true},
		{ModeStandard, tools.GroupGen, true},
		{ModeStandard, tools.GroupWorkflows, true},
		{ModeStandard, tools.GroupVision, true},
		{ModeStandard, tools.GroupSecurity, true},
		{ModeStandard, tools.GroupHostTools, true},
		{ModeStandard, tools.GroupBruce, true},
		{ModeStandard, tools.GroupFaultier, true},

		// Recon: meta + system + Marauder (scan-only via risk gate).
		// Everything RF-transmit, write, generation, workflow, or
		// peripheral-extension is denied.
		{ModeRecon, tools.GroupMetaAudit, true},
		{ModeRecon, tools.GroupMetaUtil, true},
		{ModeRecon, tools.GroupFlipperSystem, true},
		{ModeRecon, tools.GroupFlipperSubGHz, false},
		{ModeRecon, tools.GroupFlipperIR, false},
		{ModeRecon, tools.GroupFlipperNFC, false},
		{ModeRecon, tools.GroupFlipperRFID, false},
		{ModeRecon, tools.GroupFlipperIButton, false},
		{ModeRecon, tools.GroupFlipperBadUSB, false},
		{ModeRecon, tools.GroupFlipperHW, false},
		{ModeRecon, tools.GroupMarauderWiFi, true},
		{ModeRecon, tools.GroupGen, false},
		{ModeRecon, tools.GroupWorkflows, false},
		{ModeRecon, tools.GroupVision, false},
		{ModeRecon, tools.GroupSecurity, false},
		{ModeRecon, tools.GroupHostTools, false},
		{ModeRecon, tools.GroupBruce, false},
		{ModeRecon, tools.GroupFaultier, false},

		// Intel: Recon + Vision/RAG/host-side analysis groups.
		{ModeIntel, tools.GroupMetaAudit, true},
		{ModeIntel, tools.GroupMetaUtil, true},
		{ModeIntel, tools.GroupFlipperSystem, true},
		{ModeIntel, tools.GroupFlipperSubGHz, false},
		{ModeIntel, tools.GroupFlipperIR, false},
		{ModeIntel, tools.GroupFlipperNFC, false},
		{ModeIntel, tools.GroupFlipperRFID, false},
		{ModeIntel, tools.GroupFlipperIButton, false},
		{ModeIntel, tools.GroupFlipperBadUSB, false},
		{ModeIntel, tools.GroupFlipperHW, false},
		{ModeIntel, tools.GroupMarauderWiFi, true},
		{ModeIntel, tools.GroupGen, false},
		{ModeIntel, tools.GroupWorkflows, false},
		{ModeIntel, tools.GroupVision, true},
		{ModeIntel, tools.GroupSecurity, true},
		{ModeIntel, tools.GroupHostTools, true},
		{ModeIntel, tools.GroupBruce, false},
		{ModeIntel, tools.GroupFaultier, false},

		// Stealth: minimal RF — meta + system + IR only.
		{ModeStealth, tools.GroupMetaAudit, true},
		{ModeStealth, tools.GroupMetaUtil, true},
		{ModeStealth, tools.GroupFlipperSystem, true},
		{ModeStealth, tools.GroupFlipperSubGHz, false},
		{ModeStealth, tools.GroupFlipperIR, true},
		{ModeStealth, tools.GroupFlipperNFC, false},
		{ModeStealth, tools.GroupFlipperRFID, false},
		{ModeStealth, tools.GroupFlipperIButton, false},
		{ModeStealth, tools.GroupFlipperBadUSB, false},
		{ModeStealth, tools.GroupFlipperHW, false},
		{ModeStealth, tools.GroupMarauderWiFi, false},
		{ModeStealth, tools.GroupGen, false},
		{ModeStealth, tools.GroupWorkflows, false},
		{ModeStealth, tools.GroupVision, false},
		{ModeStealth, tools.GroupSecurity, false},
		{ModeStealth, tools.GroupHostTools, false},
		{ModeStealth, tools.GroupBruce, false},
		{ModeStealth, tools.GroupFaultier, false},

		// Assault: identical to Standard.
		{ModeAssault, tools.GroupMetaAudit, true},
		{ModeAssault, tools.GroupMetaUtil, true},
		{ModeAssault, tools.GroupFlipperSystem, true},
		{ModeAssault, tools.GroupFlipperSubGHz, true},
		{ModeAssault, tools.GroupFlipperIR, true},
		{ModeAssault, tools.GroupFlipperNFC, true},
		{ModeAssault, tools.GroupFlipperRFID, true},
		{ModeAssault, tools.GroupFlipperIButton, true},
		{ModeAssault, tools.GroupFlipperBadUSB, true},
		{ModeAssault, tools.GroupFlipperHW, true},
		{ModeAssault, tools.GroupMarauderWiFi, true},
		{ModeAssault, tools.GroupGen, true},
		{ModeAssault, tools.GroupWorkflows, true},
		{ModeAssault, tools.GroupVision, true},
		{ModeAssault, tools.GroupSecurity, true},
		{ModeAssault, tools.GroupHostTools, true},
		{ModeAssault, tools.GroupBruce, true},
		{ModeAssault, tools.GroupFaultier, true},
	}

	// Sanity: the case set must cover every (mode, group) pair so a
	// new Group constant added to allKnownGroups without a matching
	// row trips this assertion.
	wantCount := len(allModes) * len(allKnownGroups)
	if len(cases) != wantCount {
		t.Fatalf("table coverage mismatch: got %d cases, want %d (modes=%d × groups=%d) — add rows when introducing a new Group/Mode",
			len(cases), wantCount, len(allModes), len(allKnownGroups))
	}

	for _, c := range cases {
		c := c // capture for parallel-safety inside the subtest.
		name := string(c.mode) + "/" + string(c.group)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := c.mode.Allows(c.group); got != c.allow {
				t.Errorf("Mode(%q).Allows(%q) = %v, want %v",
					c.mode, c.group, got, c.allow)
			}
		})
	}
}

// TestAllows_StandardMatchesEveryGroup pins the Standard mode's
// promise: behaviour identical to today (every group is allowed).
// Future groups added to the tools package MUST keep returning true
// here — the package contract is "Standard is a no-op profile".
func TestAllows_StandardMatchesEveryGroup(t *testing.T) {
	for _, g := range allKnownGroups {
		if !ModeStandard.Allows(g) {
			t.Errorf("ModeStandard.Allows(%q) = false, want true (Standard must be a no-op)", g)
		}
	}
}

// TestAllows_AssaultMatchesStandard pins the Assault contract:
// dispatch behaviour is identical to Standard. The distinction is
// documentational only.
func TestAllows_AssaultMatchesStandard(t *testing.T) {
	for _, g := range allKnownGroups {
		if ModeAssault.Allows(g) != ModeStandard.Allows(g) {
			t.Errorf("ModeAssault.Allows(%q) ≠ ModeStandard.Allows(%q) — Assault must mirror Standard at dispatch", g, g)
		}
	}
}

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{"", ModeStandard, false},
		{" ", ModeStandard, false},
		{"standard", ModeStandard, false},
		{"STANDARD", ModeStandard, false},
		{"Standard", ModeStandard, false},
		{"  recon  ", ModeRecon, false},
		{"Recon", ModeRecon, false},
		{"RECON", ModeRecon, false},
		{"intel", ModeIntel, false},
		{"INTEL", ModeIntel, false},
		{"stealth", ModeStealth, false},
		{"Stealth", ModeStealth, false},
		{"assault", ModeAssault, false},
		{"Assault", ModeAssault, false},
		{"unknown", "", true},
		{"reconnoiter", "", true},
		{"yolo", "", true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseMode(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ParseMode(%q) = %q, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMode(%q) returned unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("ParseMode(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestParseMode_UnknownErrorListsAllModes confirms the error message
// is self-correcting — the operator who typoed sees every supported
// mode listed.
func TestParseMode_UnknownErrorListsAllModes(t *testing.T) {
	_, err := ParseMode("definitely-not-a-mode")
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
	msg := err.Error()
	for _, m := range allModes {
		if !strings.Contains(msg, string(m)) {
			t.Errorf("error %q missing supported mode %q", msg, m)
		}
	}
}

func TestDisplayName(t *testing.T) {
	cases := map[Mode]string{
		ModeStandard: "Standard",
		ModeRecon:    "Recon",
		ModeIntel:    "Intel",
		ModeStealth:  "Stealth",
		ModeAssault:  "Assault",
		"":           "Standard",
	}
	for m, want := range cases {
		if got := m.DisplayName(); got != want {
			t.Errorf("Mode(%q).DisplayName() = %q, want %q", m, got, want)
		}
	}
}

func TestDescription_NonEmpty(t *testing.T) {
	for _, m := range allModes {
		if d := m.Description(); strings.TrimSpace(d) == "" {
			t.Errorf("Mode(%q).Description() returned empty string — every mode needs an operator-facing summary", m)
		}
	}
}

func TestReason_MentionsModeName(t *testing.T) {
	// Reason is consumed by dispatch error formatting; it should
	// either name the mode (so the operator can correlate the
	// rejection) or reference the constraint family. Loose check —
	// the exact wording can evolve.
	for _, m := range []Mode{ModeRecon, ModeIntel, ModeStealth} {
		got := m.Reason(tools.GroupFlipperSubGHz)
		if got == "" {
			t.Errorf("Mode(%q).Reason: empty string", m)
		}
		lower := strings.ToLower(got)
		if !strings.Contains(lower, strings.ToLower(string(m))) &&
			!strings.Contains(lower, strings.ToLower(m.DisplayName())) {
			t.Errorf("Mode(%q).Reason() = %q does not name the mode", m, got)
		}
	}
}

// TestDisplayName_UnknownModeFirstLetterUppercased pins the default
// branch of DisplayName: a Mode value not in the known set
// (e.g. "custom") gets first-letter-upper-cased rather than
// panicking. Empty string is already covered in TestDisplayName.
func TestDisplayName_UnknownModeFirstLetterUppercased(t *testing.T) {
	cases := map[Mode]string{
		Mode("custom"):  "Custom",
		Mode("xtreme"):  "Xtreme",
		Mode("redteam"): "Redteam",
		Mode("a"):       "A",
	}
	for m, want := range cases {
		if got := m.DisplayName(); got != want {
			t.Errorf("Mode(%q).DisplayName() = %q; want %q", m, got, want)
		}
	}
}

// TestDescription_UnknownModeReturnsSentinel pins the default branch
// of Description: an unknown mode returns "unknown mode" rather than
// empty (every call site renders the description verbatim).
func TestDescription_UnknownModeReturnsSentinel(t *testing.T) {
	if got := Mode("nonsense").Description(); got != "unknown mode" {
		t.Errorf("Mode(nonsense).Description() = %q; want 'unknown mode'", got)
	}
}

// TestReason_UnknownModeNamesModeAndGroup pins the Sprintf-based
// default branch — the rejection sentence still names both the mode
// and the group so an operator can correlate it back.
func TestReason_UnknownModeNamesModeAndGroup(t *testing.T) {
	got := Mode("custom").Reason(tools.GroupFlipperSubGHz)
	if !strings.Contains(got, "Custom") {
		t.Errorf("Reason missing mode name: %q", got)
	}
	if !strings.Contains(got, string(tools.GroupFlipperSubGHz)) {
		t.Errorf("Reason missing group name: %q", got)
	}
}

// TestAllows_UnknownModeDegradeOpen pins the documented
// fail-open contract: a Mode not in modeAllowList permits every
// group rather than refusing everything.
func TestAllows_UnknownModeDegradeOpen(t *testing.T) {
	if !Mode("future_mode").Allows(tools.GroupFlipperSubGHz) {
		t.Error("unknown mode should degrade open and allow every group")
	}
	// Empty mode is treated as Standard via the switch — also allowed.
	if !Mode("").Allows(tools.GroupFlipperSubGHz) {
		t.Error("empty mode should allow every group (Standard semantics)")
	}
}

// TestAll_ReturnsCopy confirms the public catalog accessor returns a
// fresh slice — callers mutating the result must not corrupt
// package state.
func TestAll_ReturnsCopy(t *testing.T) {
	first := All()
	if len(first) == 0 {
		t.Fatal("All() returned no modes")
	}
	original := first[0]
	first[0] = "tampered"
	second := All()
	if second[0] != original {
		t.Fatalf("All() leaked underlying slice: second[0]=%q, want %q", second[0], original)
	}
}

// TestIsReadRestrictive pins which modes imply the ReadOnly
// defence-in-depth overlay. cmd/promptzero (setupMode at
// startup + handleMode at runtime) both call this to decide
// whether to engage ReadOnly on top of the per-mode group
// allow-list. Before v0.80 the coupling was open-coded only at
// startup, so /mode recon at runtime silently skipped the
// overlay — a regression here re-introduces that gap.
func TestIsReadRestrictive(t *testing.T) {
	cases := map[Mode]bool{
		ModeStandard: false,
		ModeAssault:  false,
		ModeRecon:    true,
		ModeIntel:    true,
		ModeStealth:  true,
		// Unknown / blank modes are not read-restrictive.
		Mode(""):       false,
		Mode("future"): false,
	}
	for m, want := range cases {
		if got := m.IsReadRestrictive(); got != want {
			t.Errorf("Mode(%q).IsReadRestrictive() = %v, want %v", m, got, want)
		}
	}
}
