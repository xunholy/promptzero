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
