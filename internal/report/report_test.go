package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/audit"
)

func stubEntries() []audit.Entry {
	base := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	return []audit.Entry{
		{
			ID:        1,
			Timestamp: base,
			Tool:      "wifi_scan_ap",
			Risk:      "medium",
			Level:     audit.LevelAction,
			Duration:  1500,
			Success:   true,
		},
		{
			ID:        2,
			Timestamp: base.Add(30 * time.Second),
			Tool:      "wifi_deauth",
			Risk:      "critical",
			Level:     audit.LevelAction,
			Duration:  2100,
			Success:   true,
		},
		{
			ID:        3,
			Timestamp: base.Add(90 * time.Second),
			Tool:      "nfc_emulate",
			Risk:      "high",
			Level:     audit.LevelAction,
			Duration:  4200,
			Success:   false,
		},
	}
}

func TestSummarise_PopulatesCounts(t *testing.T) {
	s := Summarise("sess-1", stubEntries(), attack.NewDefaultIndex())
	if s.TotalEntries != 3 {
		t.Errorf("TotalEntries = %d, want 3", s.TotalEntries)
	}
	if s.ByRisk["critical"] != 1 {
		t.Errorf("ByRisk[critical] = %d, want 1", s.ByRisk["critical"])
	}
	if s.ByRisk["high"] != 1 {
		t.Errorf("ByRisk[high] = %d, want 1", s.ByRisk["high"])
	}
	if s.BySuccess[true] != 2 {
		t.Errorf("BySuccess[true] = %d, want 2", s.BySuccess[true])
	}
	if s.BySuccess[false] != 1 {
		t.Errorf("BySuccess[false] = %d, want 1", s.BySuccess[false])
	}
	if s.ByTool["wifi_scan_ap"] != 1 {
		t.Errorf("ByTool[wifi_scan_ap] = %d, want 1", s.ByTool["wifi_scan_ap"])
	}
	if s.TotalDurationMs != 7800 {
		t.Errorf("TotalDurationMs = %d, want 7800", s.TotalDurationMs)
	}
	// Span should run from the earliest to the latest entry.
	if !s.StartedAt.Before(s.EndedAt) {
		t.Errorf("StartedAt should precede EndedAt: %v vs %v", s.StartedAt, s.EndedAt)
	}
}

func TestSummarise_ATTACKCoverage(t *testing.T) {
	s := Summarise("sess-1", stubEntries(), attack.NewDefaultIndex())
	// wifi_scan_ap -> T1018
	// wifi_deauth -> T1499, T1557
	// nfc_emulate -> T1556, T1078
	for _, id := range []string{"T1018", "T1499", "T1557", "T1556", "T1078"} {
		if s.ATTACKCoverage[id] == 0 {
			t.Errorf("expected coverage on %s, got map=%+v", id, s.ATTACKCoverage)
		}
	}
}

func TestSummarise_NoATTACKWhenIndexNil(t *testing.T) {
	s := Summarise("sess", stubEntries(), nil)
	if len(s.ATTACKCoverage) != 0 {
		t.Errorf("nil index should yield zero coverage map, got %+v", s.ATTACKCoverage)
	}
}

func TestSummarise_EmptyEntries(t *testing.T) {
	s := Summarise("sess", nil, attack.NewDefaultIndex())
	if s.TotalEntries != 0 {
		t.Errorf("empty entries should yield TotalEntries=0, got %d", s.TotalEntries)
	}
	if !s.StartedAt.IsZero() {
		t.Errorf("StartedAt should be zero for empty session")
	}
}

func TestSummarise_SortsTimelineByTimestamp(t *testing.T) {
	// Feed entries out of order and verify the sort.
	reversed := []audit.Entry{
		stubEntries()[2],
		stubEntries()[0],
		stubEntries()[1],
	}
	s := Summarise("sess", reversed, attack.NewDefaultIndex())
	for i := 1; i < len(s.Timeline); i++ {
		if s.Timeline[i].Timestamp.Before(s.Timeline[i-1].Timestamp) {
			t.Fatalf("timeline not sorted at index %d: %v before %v", i, s.Timeline[i].Timestamp, s.Timeline[i-1].Timestamp)
		}
	}
}

func TestMarkdownRenderer_EmptySession(t *testing.T) {
	r := MarkdownRenderer{}
	raw, err := r.Render(Summarise("sess-empty", nil, nil))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := string(raw)
	if !strings.Contains(out, "sess-empty") {
		t.Errorf("output should mention session id: %s", out)
	}
	if !strings.Contains(out, "No audit entries") {
		t.Errorf("empty session should say so: %s", out)
	}
}

func TestMarkdownRenderer_PopulatedSession(t *testing.T) {
	r := MarkdownRenderer{}
	raw, err := r.Render(Summarise("sess-1", stubEntries(), attack.NewDefaultIndex()))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := string(raw)

	// Key sections must all be present.
	for _, need := range []string{
		"# PromptZero Session Report",
		"Risk tier breakdown",
		"Tool usage",
		"MITRE ATT&CK coverage",
		"Timeline",
		"wifi_scan_ap",
		"wifi_deauth",
		"nfc_emulate",
	} {
		if !strings.Contains(out, need) {
			t.Errorf("output missing %q:\n%s", need, out)
		}
	}

	// Risk tier breakdown should list critical + high + medium.
	for _, tier := range []string{"critical:", "high:", "medium:"} {
		if !strings.Contains(out, tier) {
			t.Errorf("risk tier %q missing", tier)
		}
	}

	// MITRE links must follow the T1234/005 slug shape.
	if !strings.Contains(out, "attack.mitre.org/techniques/T1018/") {
		t.Errorf("expected MITRE deep-link slug, got:\n%s", out)
	}
}

func TestMdEscape(t *testing.T) {
	cases := map[string]string{
		"simple":       "simple",
		"has|pipe":     "has\\|pipe",
		"has`backtick": "has\\`backtick",
		"a|b`c":        "a\\|b\\`c",
	}
	for in, want := range cases {
		if got := mdEscape(in); got != want {
			t.Errorf("mdEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMitreSlug(t *testing.T) {
	cases := map[string]string{
		"T1040":     "T1040",
		"T1557":     "T1557",
		"T1557.004": "T1557/004",
		"T1552.004": "T1552/004",
	}
	for in, want := range cases {
		if got := mitreSlug(in); got != want {
			t.Errorf("mitreSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHeatmapBar locks the visual contract for the ATT&CK heatmap
// rendering: filled cells are '█', empty cells are '░', a non-zero
// count always renders at least one filled cell so it's visible.
func TestHeatmapBar(t *testing.T) {
	cases := []struct {
		n, max, width int
		want          string
	}{
		{0, 10, 5, "░░░░░"},  // zero → all empty
		{5, 10, 5, "██░░░"},  // half
		{10, 10, 5, "█████"}, // full
		{1, 10, 5, "█░░░░"},  // tiny but visible (the floor at 1)
		{0, 0, 5, ""},        // defensive: zero max returns empty
		{5, 10, 0, ""},       // defensive: zero width returns empty
	}
	for _, c := range cases {
		if got := heatmapBar(c.n, c.max, c.width); got != c.want {
			t.Errorf("heatmapBar(%d, %d, %d) = %q, want %q", c.n, c.max, c.width, got, c.want)
		}
	}
}

// TestJSONRenderer_RoundTrip ensures the JSON output is well-formed
// and contains the structured fields downstream tooling needs. The
// renderer remaps Summary into a JSON-friendly schema (success and
// failure counts split rather than the bool-keyed BySuccess map), so
// we parse into a generic map[string]any to verify shape rather than
// rebinding to Summary.
func TestJSONRenderer_RoundTrip(t *testing.T) {
	s := Summary{
		SessionID:    "test-session",
		TotalEntries: 3,
		BySuccess:    map[bool]int{true: 2, false: 1},
		ByRisk:       map[string]int{"high": 1, "low": 2},
		ByTool:       map[string]int{"audit_query": 2, "wifi_scan_ap": 1},
		ATTACKCoverage: map[string]int{
			"T1040":     1,
			"T1557.004": 1,
		},
	}
	out, err := JSONRenderer{}.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("JSON output not parseable: %v\n%s", err, out)
	}
	if parsed["session_id"] != "test-session" {
		t.Errorf("session_id = %v", parsed["session_id"])
	}
	if got, _ := parsed["total_entries"].(float64); int(got) != 3 {
		t.Errorf("total_entries = %v, want 3", parsed["total_entries"])
	}
	if got, _ := parsed["success_count"].(float64); int(got) != 2 {
		t.Errorf("success_count = %v, want 2", parsed["success_count"])
	}
	if got, _ := parsed["failure_count"].(float64); int(got) != 1 {
		t.Errorf("failure_count = %v, want 1", parsed["failure_count"])
	}
	cov, _ := parsed["attack_coverage"].(map[string]any)
	if len(cov) != 2 {
		t.Errorf("attack_coverage size = %d, want 2", len(cov))
	}
}

// TestMarkdownRenderer_HeatmapVisible verifies that a populated
// session's markdown report includes the heatmap column with at
// least one filled bar.
func TestMarkdownRenderer_HeatmapVisible(t *testing.T) {
	s := Summary{
		SessionID:    "test",
		TotalEntries: 1,
		BySuccess:    map[bool]int{true: 1},
		ByRisk:       map[string]int{"low": 1},
		ByTool:       map[string]int{"wifi_scan_ap": 1},
		ATTACKCoverage: map[string]int{
			"T1040": 5,
			"T1018": 1,
		},
	}
	out, err := MarkdownRenderer{}.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	if !strings.Contains(body, "Frequency") {
		t.Error("heatmap column header missing")
	}
	if !strings.Contains(body, "█") {
		t.Errorf("heatmap should contain at least one filled bar; output:\n%s", body)
	}
	if !strings.Contains(body, "░") {
		t.Errorf("heatmap should contain at least one empty cell; output:\n%s", body)
	}
}
