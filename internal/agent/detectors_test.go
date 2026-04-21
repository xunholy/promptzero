package agent

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/rules"
)

func TestAppendDetectorVerdicts_Empty(t *testing.T) {
	if got := appendDetectorVerdicts("raw output", nil); got != "raw output" {
		t.Fatalf("empty verdicts should pass through: %q", got)
	}
}

func TestAppendDetectorVerdicts_OneVerdictAppended(t *testing.T) {
	out := appendDetectorVerdicts("scan result", []rules.Verdict{
		{Verdict: rules.VerdictSuccess, Confidence: 0.9, DetectedBy: "deauth_success"},
	})
	if !strings.HasPrefix(out, "scan result") {
		t.Errorf("original output should be preserved at the head: %q", out)
	}
	if !strings.Contains(out, "<detector-verdict>") {
		t.Errorf("expected <detector-verdict> tag: %q", out)
	}
	if !strings.Contains(out, `"verdict":"success"`) {
		t.Errorf("verdict JSON missing: %q", out)
	}
	if !strings.Contains(out, `"detected_by":"deauth_success"`) {
		t.Errorf("detector name missing: %q", out)
	}
}

func TestAppendDetectorVerdicts_MultipleVerdicts(t *testing.T) {
	out := appendDetectorVerdicts("raw", []rules.Verdict{
		{Verdict: rules.VerdictSuspicious, DetectedBy: "a"},
		{Verdict: rules.VerdictFailure, DetectedBy: "b"},
	})
	// Two tagged blocks.
	if got := strings.Count(out, "<detector-verdict>"); got != 2 {
		t.Errorf("want 2 blocks, got %d: %s", got, out)
	}
	// Each detector's name must appear.
	for _, want := range []string{`"detected_by":"a"`, `"detected_by":"b"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
}
