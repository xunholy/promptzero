package risk

import (
	"testing"
)

func TestClassify_spots(t *testing.T) {
	cases := []struct {
		tool string
		want Level
	}{
		{"wifi_deauth", Critical},
		{"storage_read", Low},
		{"rfid_write", High},
		{"nfc_emulate", High},
		// a few more anchors across tiers
		{"wifi_scan_ap", Medium},
		{"wifi_beacon_spam", High},
		{"subghz_bruteforce", Critical},
	}
	for _, tc := range cases {
		if got := Classify(tc.tool); got != tc.want {
			t.Errorf("Classify(%q) = %s, want %s", tc.tool, got, tc.want)
		}
	}
}

func TestClassify_unknownDefaultsHigh(t *testing.T) {
	// Unknown tools must default to High (safe-default contract).
	got := Classify("totally_unknown_tool_xyz")
	if got != High {
		t.Errorf("unknown tool: got %s, want High", got)
	}
}

func TestAutoApprove_threshold(t *testing.T) {
	cases := []struct {
		threshold Level
		toolRisk  Level
		want      bool
	}{
		{Medium, Low, true},
		{Low, Medium, false},
		{Critical, Critical, true},
		{High, Critical, false},
		{Low, Low, true},
		{Medium, Medium, true},
		{Medium, High, false},
	}
	for _, tc := range cases {
		got := AutoApprove(tc.threshold, tc.toolRisk)
		if got != tc.want {
			t.Errorf("AutoApprove(%s, %s) = %v, want %v", tc.threshold, tc.toolRisk, got, tc.want)
		}
	}
}

func TestWantsDiff(t *testing.T) {
	cases := []struct {
		level Level
		want  bool
	}{
		{Low, false},
		{Medium, true},
		{High, false},
		{Critical, false},
	}
	for _, tc := range cases {
		if got := WantsDiff(tc.level); got != tc.want {
			t.Errorf("WantsDiff(%s) = %v, want %v", tc.level, got, tc.want)
		}
	}
}

func TestRegisterUnregister(t *testing.T) {
	const tool = "test_register_tool_unique"

	// Before registration, unknown → High.
	if l := Classify(tool); l != High {
		t.Fatalf("pre-register: got %s, want High", l)
	}

	Register(tool, Low)
	if l := Classify(tool); l != Low {
		t.Errorf("after Register(Low): got %s, want Low", l)
	}

	// Second Register overrides.
	Register(tool, Critical)
	if l := Classify(tool); l != Critical {
		t.Errorf("after second Register(Critical): got %s, want Critical", l)
	}

	Unregister(tool)
	if l := Classify(tool); l != High {
		t.Errorf("after Unregister: got %s, want High (safe default)", l)
	}
}

// TestClassifyExplicit pins the (Level, bool) contract: the bool
// distinguishes "explicitly registered, here's the level" from the
// safe-default fallback that Classify silently returns. Coverage
// validators (agent.risk_coverage_test, tools.registry_coverage_test)
// rely on this distinction so an unregistered tool surfaces as a
// hard failure rather than a Classify-default coincidence.
func TestClassifyExplicit(t *testing.T) {
	// Compile-time-registered tool: explicit hit.
	if l, ok := ClassifyExplicit("wifi_deauth"); !ok || l != Critical {
		t.Errorf("ClassifyExplicit(wifi_deauth) = (%s, %v), want (Critical, true)", l, ok)
	}

	// Unknown tool: ok=false, level returns the zero-value Low (NOT
	// the High safe-default that Classify applies). Callers wanting
	// the safe default should use Classify; callers wanting the
	// explicit/inferred distinction should use ClassifyExplicit.
	if l, ok := ClassifyExplicit("totally_unknown_xyz"); ok {
		t.Errorf("ClassifyExplicit(unknown) ok = true, want false; level = %s", l)
	}

	// Runtime-registered tool: takes precedence over compile-time
	// table; explicit hit at the runtime-supplied level.
	const runtimeTool = "test_runtime_classify_explicit"
	defer Unregister(runtimeTool)
	Register(runtimeTool, Medium)
	if l, ok := ClassifyExplicit(runtimeTool); !ok || l != Medium {
		t.Errorf("ClassifyExplicit(runtime-registered) = (%s, %v), want (Medium, true)", l, ok)
	}

	// Runtime override of a compile-time tool: explicit hit at the
	// runtime level, not the compile-time level. This is the same
	// precedence Classify uses; ClassifyExplicit just exposes the
	// explicit-vs-default bit alongside.
	defer Unregister("wifi_deauth") // restore compile-time entry
	Register("wifi_deauth", Low)
	if l, ok := ClassifyExplicit("wifi_deauth"); !ok || l != Low {
		t.Errorf("runtime override: ClassifyExplicit(wifi_deauth) = (%s, %v), want (Low, true)", l, ok)
	}
}

func TestLevelString(t *testing.T) {
	cases := []struct {
		level Level
		want  string
	}{
		{Low, "low"},
		{Medium, "medium"},
		{High, "high"},
		{Critical, "critical"},
		{Level(99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.level.String(); got != tc.want {
			t.Errorf("Level(%d).String() = %q, want %q", tc.level, got, tc.want)
		}
	}
}

// TestRegister_RejectsInvalidLevel pins the v0.148 defensive guard.
// AutoApprove is `toolRisk <= threshold` — a Level(-1) stored via a
// typo'd Register call would silently auto-approve at every non-
// negative threshold, bypassing the confirm gate. The registry must
// drop such writes so the tool falls through to Classify's High
// safe-default instead.
func TestRegister_RejectsInvalidLevel(t *testing.T) {
	cases := []struct {
		name  string
		level Level
	}{
		{"negative", Level(-1)},
		{"way-below", Level(-99)},
		{"above-critical", Level(int(Critical) + 1)},
		{"way-above", Level(99)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool := "test_register_invalid_" + tc.name
			defer Unregister(tool)
			Register(tool, tc.level)
			// Classify must fall through to the High safe-default,
			// proving the invalid Register did NOT store.
			if l := Classify(tool); l != High {
				t.Errorf("Classify after invalid Register(%d) = %s, want High (rejected register should fall through)",
					int(tc.level), l)
			}
			// ClassifyExplicit confirms there's no explicit entry.
			if _, ok := ClassifyExplicit(tool); ok {
				t.Errorf("ClassifyExplicit after invalid Register(%d) returned ok=true; invalid level was stored",
					int(tc.level))
			}
		})
	}
}

// TestRegister_AcceptsBoundaryLevels confirms the reject is a strict
// out-of-range check (Low and Critical themselves are valid).
func TestRegister_AcceptsBoundaryLevels(t *testing.T) {
	for _, lvl := range []Level{Low, Medium, High, Critical} {
		t.Run(lvl.String(), func(t *testing.T) {
			tool := "test_register_boundary_" + lvl.String()
			defer Unregister(tool)
			Register(tool, lvl)
			if got := Classify(tool); got != lvl {
				t.Errorf("Classify after Register(%s) = %s, want %s", lvl, got, lvl)
			}
		})
	}
}

// TestEscalateForPath pins the shared run_payload escalation rule that every
// dispatch surface (agent Run loop, RunTool, MCP) applies before its gates.
func TestEscalateForPath(t *testing.T) {
	cases := []struct {
		name string
		tool string
		base Level
		path string
		want Level
	}{
		// run_payload escalates to the underlying op's level when higher.
		{"sub_to_critical", "run_payload", High, "/ext/subghz/door.sub", Critical},
		{"evilportal_to_critical", "run_payload", Medium, "/ext/apps_data/evil_portal/index.html", Critical},
		{"badusb_to_critical", "run_payload", Medium, "/ext/badusb/payload.txt", Critical},
		{"nfc_to_high", "run_payload", Low, "/ext/nfc/card.nfc", High},
		{"rfid_to_high", "run_payload", Low, "/ext/lfrfid/tag.rfid", High},
		{"unknown_ext_defaults_high", "run_payload", Low, "/ext/misc/file.bin", High},
		// Never lowers: base already at or above the derived level wins.
		{"ir_keeps_higher_base", "run_payload", High, "/ext/infrared/tv.ir", High},
		{"already_critical_stays", "run_payload", Critical, "/ext/nfc/card.nfc", Critical},
		// No escalation conditions.
		{"empty_path_no_change", "run_payload", Medium, "", Medium},
		{"non_dispatcher_tool_unchanged", "nfc_detect", Low, "/ext/subghz/door.sub", Low},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EscalateForPath(c.tool, c.base, c.path); got != c.want {
				t.Errorf("EscalateForPath(%q, %v, %q) = %v, want %v", c.tool, c.base, c.path, got, c.want)
			}
		})
	}
}
