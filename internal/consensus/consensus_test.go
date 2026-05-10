package consensus

import (
	"strings"
	"testing"
)

func TestVote_EmptyInput(t *testing.T) {
	r := Vote(nil)
	if r.Unanimous {
		t.Errorf("zero verdicts should not be unanimous")
	}
	if r.AgreedRisk != "" {
		t.Errorf("AgreedRisk = %q, want empty", r.AgreedRisk)
	}
}

func TestVote_AllAgreeOK(t *testing.T) {
	r := Vote([]Verdict{
		{Model: "haiku", Risk: "ok"},
		{Model: "sonnet", Risk: "ok"},
	})
	if !r.Unanimous {
		t.Fatalf("expected Unanimous=true, got %+v", r)
	}
	if r.AgreedRisk != "ok" {
		t.Errorf("AgreedRisk = %q, want ok", r.AgreedRisk)
	}
}

func TestVote_AllAgreeRisky(t *testing.T) {
	r := Vote([]Verdict{
		{Model: "haiku", Risk: "risky"},
		{Model: "sonnet", Risk: "risky"},
		{Model: "opus", Risk: "risky"},
	})
	if !r.Unanimous || r.AgreedRisk != "risky" {
		t.Errorf("expected unanimous risky, got %+v", r)
	}
}

func TestVote_DisagreementBlocks(t *testing.T) {
	r := Vote([]Verdict{
		{Model: "haiku", Risk: "ok"},
		{Model: "sonnet", Risk: "risky"},
	})
	if r.Unanimous {
		t.Errorf("disagreement should not be unanimous: %+v", r)
	}
	if r.AgreedRisk != "" {
		t.Errorf("AgreedRisk should be empty on disagreement, got %q", r.AgreedRisk)
	}
}

func TestVote_NormalisesCaseAndWhitespace(t *testing.T) {
	r := Vote([]Verdict{
		{Model: "h", Risk: " OK "},
		{Model: "s", Risk: "ok"},
		{Model: "o", Risk: "Ok"},
	})
	if !r.Unanimous || r.AgreedRisk != "ok" {
		t.Errorf("expected case-insensitive consensus on 'ok', got %+v", r)
	}
}

func TestVote_RejectsUnknownRiskValues(t *testing.T) {
	// "okay" is NOT a valid canonical risk; treat as abstain.
	r := Vote([]Verdict{
		{Model: "h", Risk: "okay"},
		{Model: "s", Risk: "ok"},
	})
	if !r.Unanimous {
		t.Errorf("one valid + one abstain should still be Unanimous=true, got %+v", r)
	}
	if r.AgreedRisk != "ok" {
		t.Errorf("AgreedRisk = %q, want ok (abstention excluded)", r.AgreedRisk)
	}
	if r.Abstentions != 1 {
		t.Errorf("Abstentions = %d, want 1", r.Abstentions)
	}
}

func TestVote_AllAbstainProducesNoSignal(t *testing.T) {
	r := Vote([]Verdict{
		{Model: "h", Risk: ""},
		{Model: "s", Risk: "garbage"},
	})
	if r.Unanimous {
		t.Errorf("all-abstain should not be Unanimous: %+v", r)
	}
	if r.AgreedRisk != "" {
		t.Errorf("AgreedRisk = %q, want empty", r.AgreedRisk)
	}
	if r.Abstentions != 2 {
		t.Errorf("Abstentions = %d, want 2", r.Abstentions)
	}
}

func TestVote_SingleVoterStillPasses(t *testing.T) {
	// One model with a real verdict + one abstention is treated as
	// unanimous on the single signal — better than blocking the call
	// entirely just because one provider rate-limited.
	r := Vote([]Verdict{
		{Model: "h", Risk: "ok"},
		{Model: "s", Risk: ""},
	})
	if !r.Unanimous {
		t.Errorf("single non-abstain should be Unanimous=true, got %+v", r)
	}
	if r.AgreedRisk != "ok" {
		t.Errorf("AgreedRisk = %q, want ok", r.AgreedRisk)
	}
}

func TestDisagreementMessage_StructureAndContent(t *testing.T) {
	r := Vote([]Verdict{
		{Model: "claude-haiku-4-5", Risk: "ok", Critique: `{"risk":"ok"}`},
		{Model: "claude-sonnet-4-6", Risk: "risky", Critique: "concerns: TX exceeds region cap"},
	})
	msg := DisagreementMessage(r)
	if !strings.HasPrefix(msg, "<consensus-disagreement>") {
		t.Fatalf("missing opening tag: %q", msg)
	}
	if !strings.HasSuffix(msg, "</consensus-disagreement>") {
		t.Fatalf("missing closing tag: %q", msg)
	}
	for _, want := range []string{"claude-haiku-4-5", "claude-sonnet-4-6", "ok", "risky"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in disagreement message: %q", want, msg)
		}
	}
}

func TestDisagreementMessage_UnanimousReturnsEmpty(t *testing.T) {
	r := Vote([]Verdict{
		{Model: "h", Risk: "ok"},
		{Model: "s", Risk: "ok"},
	})
	if got := DisagreementMessage(r); got != "" {
		t.Errorf("Unanimous=true should produce no message, got %q", got)
	}
}

func TestDisagreementMessage_OnlyOneNonAbstainReturnsEmpty(t *testing.T) {
	// If 1 model voted and 2 abstained, there's no real split — even
	// though Vote returns Unanimous=true on a single-voter input,
	// guard belt-and-braces against a bad-Vote-result edge case.
	r := Result{
		Verdicts: []Verdict{
			{Model: "h", Risk: "ok"},
			{Model: "s", Risk: ""},
		},
		Abstentions: 1,
		// Force Unanimous=false so DisagreementMessage's gate is exercised.
		Unanimous: false,
	}
	if got := DisagreementMessage(r); got != "" {
		t.Errorf("only one non-abstain should yield no escalation, got %q", got)
	}
}

func TestDisagreementMessage_AbstentionTallyRendered(t *testing.T) {
	r := Result{
		Verdicts: []Verdict{
			{Model: "h", Risk: "ok"},
			{Model: "s", Risk: "risky"},
			{Model: "o", Risk: ""},
		},
		Abstentions: 1,
		Unanimous:   false,
	}
	msg := DisagreementMessage(r)
	if !strings.Contains(msg, "1 model abstained") {
		t.Errorf("abstention tally missing: %q", msg)
	}
	r.Abstentions = 3
	r.Verdicts = append(r.Verdicts, Verdict{Model: "x", Risk: ""}, Verdict{Model: "y", Risk: ""})
	msg = DisagreementMessage(r)
	if !strings.Contains(msg, "3 models abstained") {
		t.Errorf("multi-abstention tally missing: %q", msg)
	}
}

func TestSummariseCritique_FirstNonEmptyLineCapped(t *testing.T) {
	if got := summariseCritique(""); got != "" {
		t.Errorf("empty input: got %q", got)
	}
	if got := summariseCritique("\n\n  hello world\nignored second line"); got != "hello world" {
		t.Errorf("first-line extract: got %q", got)
	}
	long := strings.Repeat("x", 250)
	got := summariseCritique(long)
	if len(got) <= 200 || !strings.HasSuffix(got, "…") {
		t.Errorf("long line not capped: len=%d, suffix=%q", len(got), got[max(0, len(got)-3):])
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
