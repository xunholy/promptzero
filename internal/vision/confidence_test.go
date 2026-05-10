package vision

import (
	"testing"

	"github.com/xunholy/promptzero/internal/confidence"
)

func TestExtractVisionAnswer_ObjectWithConfidence(t *testing.T) {
	raw := `{"answer":"a Flipper Zero","confidence":0.92}`
	text, score, has := extractVisionAnswer(raw)
	if !has {
		t.Fatal("expected hasSignal=true")
	}
	if text != "a Flipper Zero" {
		t.Errorf("answer = %q", text)
	}
	if score != 0.92 {
		t.Errorf("score = %v", score)
	}
}

func TestExtractVisionAnswer_PlainProseReturnsRawWithFullSignal(t *testing.T) {
	raw := "It looks like a generic IR remote."
	text, score, has := extractVisionAnswer(raw)
	if has {
		t.Errorf("hasSignal = true on prose")
	}
	if score != confidence.Score(1.0) {
		t.Errorf("score = %v, want 1.0", score)
	}
	if text != raw {
		t.Errorf("text mutated for prose response: %q", text)
	}
}

func TestExtractVisionAnswer_ObjectWithoutAnswerFallsThrough(t *testing.T) {
	// An object that parses but has no answer field should not be
	// returned as the answer text — treat as prose fallback.
	raw := `{"confidence":0.4}`
	text, _, has := extractVisionAnswer(raw)
	if has {
		t.Errorf("hasSignal should be false when answer is missing")
	}
	if text != raw {
		t.Errorf("text should fall back to raw, got %q", text)
	}
}

func TestExtractVisionAnswer_ClampsConfidenceOutOfRange(t *testing.T) {
	raw := `{"answer":"x","confidence":2.5}`
	_, score, has := extractVisionAnswer(raw)
	if !has {
		t.Fatal("hasSignal=false; want true")
	}
	if score != 1.0 {
		t.Errorf("score = %v, want clamped to 1.0", score)
	}
}
