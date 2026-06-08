// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"strings"
	"testing"
)

func TestNewClassifierHas32Protocols(t *testing.T) {
	c := NewClassifier()
	if got := len(c.protos); got != 32 {
		t.Errorf("NewClassifier has %d protocols, want 32", got)
	}
}

// TestClassifyGangQiTopMatch builds a checksum-valid GangQi frame and confirms
// the classifier surfaces GangQi as the top match — a regression guard against a
// future decoder shadowing it. The frame is rendered inline (mirroring the
// firmware encoder) to keep this test independent of the protocols package.
func TestClassifyGangQiTopMatch(t *testing.T) {
	const (
		teShort = 500
		teLong  = 1200
		teDelta = 200
	)
	// Assemble a 34-bit code: upper-20 = 0x12345, button = 0xD (Arm), with the
	// firmware's original-remote bytesum so the frame passes the checksum gate.
	upper20 := uint64(0x12345)
	btn := byte(0xD)
	serial16 := uint16(upper20 >> 4)
	constAndBtn := byte(0xD0 | btn)
	bytesum := byte(0xC8) - byte(serial16>>8) - byte(serial16&0xFF) - constAndBtn
	code := upper20<<14 | uint64(btn)<<10 | uint64(bytesum)<<2

	// Render to a PWM pulse train: 2×te_long leading gap, 34 MSB-first bits, the
	// last bit closing on the inter-frame gap (te_short×4 + te_delta).
	pulses := []int{-(2 * teLong)}
	for k := 33; k >= 0; k-- {
		bit := (code >> uint(k)) & 1
		mark, space := teShort, -teLong
		if bit == 1 {
			mark, space = teLong, -teShort
		}
		if k == 0 {
			space = -(teShort*4 + teDelta)
		}
		pulses = append(pulses, mark, space)
	}

	matches := NewClassifier().Classify(pulses, 3)
	if len(matches) == 0 {
		t.Fatal("expected at least one match for a GangQi frame")
	}
	if matches[0].Protocol != "GangQi" {
		t.Errorf("top match = %q (conf %.3f), want GangQi; got %v",
			matches[0].Protocol, matches[0].Confidence, matchNames(matches))
	}
	if matches[0].Confidence != 1.0 {
		t.Errorf("GangQi confidence = %v, want 1.0", matches[0].Confidence)
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
