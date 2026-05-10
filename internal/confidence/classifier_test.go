package confidence

import (
	"math"
	"testing"
)

func TestParseClassifierResponse_ObjectWithConfidence(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Score
	}{
		{"router shape", `{"groups":["wifi"],"confidence":0.82}`, 0.82},
		{"vision shape", `{"answer":"a remote","confidence":0.5}`, 0.5},
		{"int confidence", `{"confidence":1}`, 1.0},
		{"zero", `{"confidence":0}`, 0},
		{"string-encoded decimal", `{"confidence":"0.42"}`, 0.42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, ok := ParseClassifierResponse(tc.in)
			if !ok {
				t.Fatalf("ok = false; want true (input=%q)", tc.in)
			}
			if math.Abs(float64(score-tc.want)) > 1e-9 {
				t.Errorf("score = %v, want %v", score, tc.want)
			}
		})
	}
}

func TestParseClassifierResponse_NoConfidenceFieldReturnsFullSignal(t *testing.T) {
	cases := []string{
		`{"groups":["wifi"]}`, // object without confidence field
		`["wifi","bt"]`,       // bare-array form (legacy router output)
		"plain prose, no JSON at all",
		"", // empty
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			score, ok := ParseClassifierResponse(in)
			if ok {
				t.Errorf("ok = true; want false (input=%q)", in)
			}
			if score != 1.0 {
				t.Errorf("score = %v, want 1.0 (no-signal default)", score)
			}
		})
	}
}

func TestParseClassifierResponse_ClampsOutOfRangeScores(t *testing.T) {
	if score, _ := ParseClassifierResponse(`{"confidence":1.7}`); score != 1.0 {
		t.Errorf("over-1 not clamped: %v", score)
	}
	if score, _ := ParseClassifierResponse(`{"confidence":-0.3}`); score != 0.0 {
		t.Errorf("negative not clamped: %v", score)
	}
}

func TestShouldAbstainAt(t *testing.T) {
	cases := []struct {
		name      string
		score     Score
		threshold Score
		want      bool
	}{
		{"score above default", 0.9, 0, false},
		{"score equals default", 0.5, 0, false}, // strict <, so equal is NOT abstain
		{"score below default", 0.3, 0, true},
		{"explicit threshold high", 0.7, 0.8, true},
		{"explicit threshold low", 0.7, 0.5, false},
		{"negative threshold normalises to default", 0.6, -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldAbstainAt(tc.score, tc.threshold); got != tc.want {
				t.Errorf("ShouldAbstainAt(%v, %v) = %v, want %v", tc.score, tc.threshold, got, tc.want)
			}
		})
	}
}

func TestParseClassifierResponse_RejectsMalformedJSON(t *testing.T) {
	score, ok := ParseClassifierResponse(`{"confidence": not-a-number}`)
	if ok {
		t.Errorf("ok=true on malformed JSON; want false")
	}
	if score != 1.0 {
		t.Errorf("malformed JSON should default to 1.0, got %v", score)
	}
}

func TestParseClassifierResponse_NonNumericConfidence(t *testing.T) {
	// A boolean or array under "confidence" must NOT propagate a
	// confused score; treat as no-signal.
	for _, in := range []string{
		`{"confidence":true}`,
		`{"confidence":[0.5]}`,
		`{"confidence":null}`,
	} {
		score, ok := ParseClassifierResponse(in)
		if ok {
			t.Errorf("ok=true on non-numeric confidence %q", in)
		}
		if score != 1.0 {
			t.Errorf("score = %v, want 1.0 (input=%q)", score, in)
		}
	}
}
