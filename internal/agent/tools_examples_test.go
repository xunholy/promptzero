package agent

import (
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

func TestRenderExamples_EmptyPassThrough(t *testing.T) {
	got := renderExamples("base desc", nil)
	if got != "base desc" {
		t.Fatalf("empty examples should pass through: %q", got)
	}
}

func TestRenderExamples_SingleExample(t *testing.T) {
	got := renderExamples("desc", []ToolExample{
		{Input: `{"k":"v"}`, Note: "a hint"},
	})
	want := "desc\n\nExamples:\n- {\"k\":\"v\"}  — a hint"
	if got != want {
		t.Fatalf("shape mismatch:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestRenderExamples_MultipleExamples(t *testing.T) {
	got := renderExamples("desc", []ToolExample{
		{Input: `{"a":1}`, Note: "first"},
		{Input: `{"b":2}`, Note: "second"},
	})
	if !strings.Contains(got, "- {\"a\":1}") {
		t.Errorf("missing first example: %q", got)
	}
	if !strings.Contains(got, "- {\"b\":2}") {
		t.Errorf("missing second example: %q", got)
	}
	if strings.Count(got, "\n- ") != 2 {
		t.Errorf("expected 2 example bullets, got %d in %q", strings.Count(got, "\n- "), got)
	}
}

func TestRenderExamples_NoteOptional(t *testing.T) {
	got := renderExamples("desc", []ToolExample{
		{Input: `{"bare":true}`},
	})
	// When Note is empty the separator " — " must not appear.
	if strings.Contains(got, " — ") {
		t.Fatalf("empty note leaked separator: %q", got)
	}
	if !strings.Contains(got, `- {"bare":true}`) {
		t.Fatalf("missing bare example: %q", got)
	}
}

func TestToolEx_EmbedsExamplesInDescription(t *testing.T) {
	tl := toolEx(
		"x_tool",
		"base description",
		props(reqProp("file", "string", "path")),
		[]ToolExample{{Input: `{"file":"/a.sub"}`, Note: "replay a"}},
		"file",
	)
	if tl.OfTool == nil {
		t.Fatalf("toolEx returned nil OfTool")
	}
	desc := tl.OfTool.Description.Or("")
	if !strings.Contains(desc, "Examples:") {
		t.Errorf("description missing Examples section: %q", desc)
	}
	if !strings.Contains(desc, "/a.sub") {
		t.Errorf("description missing example input: %q", desc)
	}
}

// The production catalog should actually ship examples on the tools we
// targeted — this guards against a future refactor accidentally
// reverting toolEx calls to plain tool() without noticing. Keep the
// set small; any tool we meaningfully uplift belongs here.
func TestCatalog_TargetedToolsCarryExamples(t *testing.T) {
	want := []string{
		"subghz_transmit",
		"subghz_receive",
		"nfc_emulate",
		"rfid_write",
		"badusb_run",
		"wifi_evil_portal_start",
	}
	all := buildTools()
	all = append(all, buildMarauderTools()...)
	byName := map[string]anthropic.ToolUnionParam{}
	for _, t := range all {
		if t.OfTool != nil {
			byName[t.OfTool.Name] = t
		}
	}
	for _, n := range want {
		tl, ok := byName[n]
		if !ok {
			t.Errorf("tool %s missing from catalog", n)
			continue
		}
		desc := tl.OfTool.Description.Or("")
		if !strings.Contains(desc, "Examples:") {
			t.Errorf("tool %s lost its Examples block: %q", n, desc)
		}
	}
}
