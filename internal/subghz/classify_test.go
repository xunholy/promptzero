// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"strings"
	"testing"
)

func TestNewClassifierHas36Protocols(t *testing.T) {
	c := NewClassifier()
	if got := len(c.protos); got != 36 {
		t.Errorf("NewClassifier has %d protocols, want 36", got)
	}
}

// TestProtocolNames asserts ProtocolNames mirrors the registered roster exactly
// (same length, same order, every entry non-empty). This is the source of truth
// the tool description and docs generate from, so drift here is caught at the
// classifier rather than downstream.
func TestProtocolNames(t *testing.T) {
	c := NewClassifier()
	names := c.ProtocolNames()
	if len(names) != len(c.protos) {
		t.Fatalf("ProtocolNames returned %d names, want %d", len(names), len(c.protos))
	}
	for i, p := range c.protos {
		if names[i] != p.Name() {
			t.Errorf("name[%d] = %q, want %q (order must match roster)", i, names[i], p.Name())
		}
		if names[i] == "" {
			t.Errorf("name[%d] is empty", i)
		}
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

// TestClassifyHormannTopMatch confirms a Hormann HSM frame surfaces Hormann as
// the top match (the protocol is wired and no other decoder shadows it). The
// frame is rendered inline (24×te_short guard + 44 PWM bits) to keep this test
// independent of the protocols package.
func TestClassifyHormannTopMatch(t *testing.T) {
	const teShort, teLong = 500, 1000
	const code = 0xFFABCDEF703 // satisfies the fixed pattern; button = 0x7
	pulses := []int{24 * teShort, -teShort}
	for k := 43; k >= 0; k-- {
		if (code>>uint(k))&1 == 1 {
			pulses = append(pulses, teLong, -teShort)
		} else {
			pulses = append(pulses, teShort, -teLong)
		}
	}
	pulses = append(pulses, 24*teShort)

	matches := NewClassifier().Classify(pulses, 3)
	if len(matches) == 0 {
		t.Fatal("expected at least one match for a Hormann frame")
	}
	if matches[0].Protocol != "Hormann HSM" {
		t.Errorf("top match = %q (conf %.3f), want Hormann HSM; got %v",
			matches[0].Protocol, matches[0].Confidence, matchNames(matches))
	}
}

// TestClassifyDooyaTopMatch confirms a Dooya frame surfaces Dooya in the
// top-confidence tier. A Dooya frame is 40-bit PWM with a long guard, which
// Security+ v1's gate-less 40-bit PWM reader also accepts at full confidence
// (the same over-matching the classifier ordering already accounts for) — so
// Dooya legitimately *ties* and is not the unique top match. Asserting Dooya is
// present at the top confidence is the honest, deterministic property. The
// frame is rendered inline (13×te_short guard + 40 PWM bits) to keep this test
// independent of the protocols package.
func TestClassifyDooyaTopMatch(t *testing.T) {
	const teShort, teLong = 366, 733
	const code = 0xE1DC030533 // firmware example: serial 0xE1DC03, ch 5, long press down
	pulses := []int{13 * teShort, -(2 * teLong)}
	for k := 39; k >= 0; k-- {
		if (code>>uint(k))&1 == 1 {
			pulses = append(pulses, teLong, -teShort)
		} else {
			pulses = append(pulses, teShort, -teLong)
		}
	}
	pulses = append(pulses, 13*teShort)

	matches := NewClassifier().Classify(pulses, 3)
	if len(matches) == 0 {
		t.Fatal("expected at least one match for a Dooya frame")
	}
	dooyaConf, found := -1.0, false
	for _, m := range matches {
		if m.Protocol == "Dooya" {
			dooyaConf, found = m.Confidence, true
		}
	}
	if !found {
		t.Errorf("Dooya absent from matches; got %v", matchNames(matches))
	} else if dooyaConf != matches[0].Confidence {
		t.Errorf("Dooya conf %.3f below top %.3f; got %v", dooyaConf, matches[0].Confidence, matchNames(matches))
	}
}

// TestClassifyMarantec24TopMatch confirms a Marantec24 frame surfaces
// Marantec24 as the top match. The frame is rendered inline (a 9×te_long gap +
// 24 PWM bits) to keep this test independent of the protocols package.
func TestClassifyMarantec24TopMatch(t *testing.T) {
	const teShort, teLong = 800, 1600
	const code = 0xABCDE5 // serial 0xABCDE, button 0x5
	pulses := []int{-(9 * teLong)}
	for k := 23; k >= 0; k-- {
		if (code>>uint(k))&1 == 1 {
			pulses = append(pulses, teShort, -(2 * teLong))
		} else {
			pulses = append(pulses, teLong, -(3 * teShort))
		}
	}
	pulses = append(pulses, -(9 * teLong))

	matches := NewClassifier().Classify(pulses, 3)
	if len(matches) == 0 {
		t.Fatal("expected at least one match for a Marantec24 frame")
	}
	if matches[0].Protocol != "Marantec24" {
		t.Errorf("top match = %q (conf %.3f), want Marantec24; got %v",
			matches[0].Protocol, matches[0].Confidence, matchNames(matches))
	}
}

// TestClassifyIntertechnoV3TopMatch confirms an Intertechno V3 frame surfaces
// Intertechno V3 as the top match — its distinctive four-phase encoding means
// no simple-PWM decoder shadows it. The frame is rendered inline.
func TestClassifyIntertechnoV3TopMatch(t *testing.T) {
	const teShort, teLong = 275, 1375
	const code = 0x3F86C59F // 32-bit firmware example
	pulses := []int{-(37 * teShort), teShort, -(10 * teShort)}
	for k := 31; k >= 0; k-- {
		if (code>>uint(k))&1 == 1 {
			pulses = append(pulses, teShort, -teLong, teShort, -teShort)
		} else {
			pulses = append(pulses, teShort, -teShort, teShort, -teLong)
		}
	}
	pulses = append(pulses, teShort, -(38 * teShort))

	matches := NewClassifier().Classify(pulses, 3)
	if len(matches) == 0 {
		t.Fatal("expected at least one match for an Intertechno V3 frame")
	}
	if matches[0].Protocol != "Intertechno V3" {
		t.Errorf("top match = %q (conf %.3f), want Intertechno V3; got %v",
			matches[0].Protocol, matches[0].Confidence, matchNames(matches))
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
