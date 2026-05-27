// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"strings"
	"testing"
)

func TestNewClassifierHas23Protocols(t *testing.T) {
	c := NewClassifier()
	if got := len(c.protos); got != 23 {
		t.Errorf("NewClassifier has %d protocols, want 23", got)
	}
}

func TestClassifyEmptyPulses(t *testing.T) {
	c := NewClassifier()
	if got := c.Classify(nil, 3); got != nil {
		t.Errorf("Classify(nil) = %v, want nil", got)
	}
	if got := c.Classify([]int{}, 3); got != nil {
		t.Errorf("Classify([]) = %v, want nil", got)
	}
}

func TestClassifyTopNLimits(t *testing.T) {
	// Build a Princeton PT2262 frame: addr=0xAA (101010101010), data=0x5 (0101)
	// TE = 350 µs; sync = 1×TE mark + 31×TE space
	te := 350
	bits := []byte{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1}
	pulses := EncodePWMPulses(bits, te, 1, 31, 3, 1, 1, 3, 3)

	c := NewClassifier()
	matches := c.Classify(pulses, 1)
	if len(matches) > 1 {
		t.Errorf("top_n=1 returned %d matches", len(matches))
	}
}

func TestClassifyTopNZeroReturnsAll(t *testing.T) {
	te := 350
	bits := []byte{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1}
	pulses := EncodePWMPulses(bits, te, 1, 31, 3, 1, 1, 3, 3)

	c := NewClassifier()
	matches := c.Classify(pulses, 0)
	// Some protocols share similar timings; at least 1 must match
	if len(matches) == 0 {
		t.Error("expected at least one match")
	}
}

func TestClassifyMatchesAreSorted(t *testing.T) {
	te := 350
	bits := []byte{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1}
	pulses := EncodePWMPulses(bits, te, 1, 31, 3, 1, 1, 3, 3)

	c := NewClassifier()
	matches := c.Classify(pulses, 5)
	for i := 1; i < len(matches); i++ {
		if matches[i].Confidence > matches[i-1].Confidence {
			t.Errorf("matches not sorted: [%d]=%f > [%d]=%f",
				i, matches[i].Confidence, i-1, matches[i-1].Confidence)
		}
	}
}

// TestClassifyFromSubFile verifies the full pipeline: SubFile → Classify.
func TestClassifyFromSubFile(t *testing.T) {
	te := 350
	bits := []byte{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1}
	pulses := EncodePWMPulses(bits, te, 1, 31, 3, 1, 1, 3, 3)
	text := SubFileString(433920000, "FuriHalSubGhzPresetOok650Async", pulses)

	sf, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	c := NewClassifier()
	matches := c.Classify(sf.Pulses, 3)
	if len(matches) == 0 {
		t.Fatal("expected at least one match from sub file")
	}
	// Princeton PT2262 or Princeton-Holtek should appear in top-3
	found := false
	for _, m := range matches {
		if strings.Contains(m.Protocol, "Princeton") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Princeton in top-3, got: %v", matchNames(matches))
	}
}

func matchNames(matches []Match) []string {
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.Protocol
	}
	return names
}
