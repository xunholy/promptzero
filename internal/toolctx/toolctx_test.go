package toolctx

import (
	"strings"
	"testing"
)

func TestGet_KnownTool(t *testing.T) {
	got := Get("subghz_build")
	if got == "" {
		t.Fatal("subghz_build should have a cheat sheet")
	}
	if !strings.Contains(got, "Princeton") {
		t.Errorf("subghz_build sheet missing Princeton reference: %q", got)
	}
}

func TestGet_UnknownTool(t *testing.T) {
	if got := Get("completely_made_up_tool"); got != "" {
		t.Errorf("unknown tool should return empty, got %q", got)
	}
}

func TestEnrichDescription_AddsContext(t *testing.T) {
	got := EnrichDescription("nfc_build", "base desc")
	if !strings.HasPrefix(got, "base desc") {
		t.Errorf("description prefix changed: %q", got)
	}
	if !strings.Contains(got, "Context:") {
		t.Errorf("Context marker missing: %q", got)
	}
	if !strings.Contains(got, "Mifare Classic") {
		t.Errorf("nfc_build sheet content missing: %q", got)
	}
}

func TestEnrichDescription_Passthrough(t *testing.T) {
	// Unknown tool: description passes through unchanged.
	got := EnrichDescription("unknown_tool", "base desc")
	if got != "base desc" {
		t.Errorf("unknown tool should not alter description, got %q", got)
	}
}

// Lock the minimum set of high-priority tools that should always
// carry a cheat sheet. A future refactor that drops one trips this
// test with a specific diagnostic.
func TestCoverage_HighPriorityTools(t *testing.T) {
	required := []string{
		// Parametric builders
		"subghz_build", "rfid_build", "ir_build", "nfc_build",
		"subghz_bruteforce_generate",
		// Critical-risk tools
		"badusb_run", "wifi_evil_portal_start", "wifi_deauth",
		"wifi_sniff_pmkid", "nfc_emulate", "rfid_write",
		"subghz_receive",
	}
	for _, tool := range required {
		if !Has(tool) {
			t.Errorf("required tool %q missing cheat sheet", tool)
		}
	}
}

// Sanity: sheets shouldn't be embarrassingly long. Oversized sheets
// bloat the system prompt and hurt the first-turn cache miss.
func TestCoverage_SheetsAreBounded(t *testing.T) {
	const maxChars = 800
	for name, sheet := range sheets {
		if len(sheet) > maxChars {
			t.Errorf("sheet for %q is %d chars, want <= %d", name, len(sheet), maxChars)
		}
	}
}

// TestToolsWithSheets_Sorted pins the docstring's "sorted
// alphabetically" promise. Pre-fix the function returned tool names
// in Go's randomised map-iteration order — the inline comment even
// admitted "sort not imported here". Any caller relying on a stable
// layout (a /tools UI baseline, a regression test comparing
// returned[0]) would silently flake across runs. The fix imports
// sort and applies sort.Strings to the output.
func TestToolsWithSheets_Sorted(t *testing.T) {
	got := ToolsWithSheets()
	if len(got) == 0 {
		t.Fatal("ToolsWithSheets returned empty — sheets map should not be empty")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("ToolsWithSheets not sorted: %q comes before %q at indices %d/%d",
				got[i-1], got[i], i-1, i)
		}
	}
}
