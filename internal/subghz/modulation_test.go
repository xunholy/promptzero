// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// DemodulateOOK
// ---------------------------------------------------------------------------

func TestDemodulateOOKBasic(t *testing.T) {
	// Short marks (200 µs) = 0, long marks (800 µs) = 1.
	// Marks: 200, 200, 800, 200, 800 → sorted: [200,200,200,800,800]
	// Median (index 2) = 200 → threshold = 200.
	// All marks ≥ 200, so all would be 1. This shows OOK needs more 1s than 0s
	// for the median to split well. Use a cleaner 50/50 split instead.
	//
	// Use 4 shorts and 4 longs so median = 300 (the 4th in sorted[0..7]):
	// sorted [200,200,200,200,800,800,800,800] median = index 4 = 800.
	// Actually index len/2 = 4 → 800. Then 200 < 800 → 0, 800 >= 800 → 1.
	pulses := []int{
		200, -200, 800, -200, 200, -200, 800, -200,
		200, -200, 800, -200, 200, -200, 800, -200,
	}
	// Marks: 200,800,200,800,200,800,200,800 → sorted:[200,200,200,200,800,800,800,800] median(idx4)=800
	// 200 < 800 → 0; 800 >= 800 → 1
	bits := DemodulateOOK(pulses)
	if len(bits) == 0 {
		t.Fatal("DemodulateOOK returned no bits")
	}
	want := []byte{0, 1, 0, 1, 0, 1, 0, 1}
	if !bytes.Equal(bits, want) {
		t.Errorf("DemodulateOOK = %v, want %v", bits, want)
	}
}

func TestDemodulateOOKEmpty(t *testing.T) {
	if bits := DemodulateOOK(nil); bits != nil {
		t.Errorf("expected nil on empty input, got %v", bits)
	}
	if bits := DemodulateOOK([]int{}); bits != nil {
		t.Errorf("expected nil on empty slice, got %v", bits)
	}
}

func TestDemodulateOOKAllNegative(t *testing.T) {
	pulses := []int{-500, -500, -500}
	if bits := DemodulateOOK(pulses); bits != nil {
		t.Errorf("expected nil when no marks, got %v", bits)
	}
}

// ---------------------------------------------------------------------------
// DemodulatePWM
// ---------------------------------------------------------------------------

func TestDemodulatePWMBasic(t *testing.T) {
	// TE = 350 µs; "1" = 3×TE = 1050, "0" = 1×TE = 350
	// Marks: 350, 350, 1050, 350 → sorted: [350,350,350,1050] → median(idx2)=350
	// oneRatio=2.0: threshold = 350*2.0 = 700; 350 < 700 → 0; 1050 ≥ 700 → 1
	pulses := []int{350, -1050, 350, -1050, 1050, -350, 350, -1050}
	bits := DemodulatePWM(pulses, 2.0)
	want := []byte{0, 0, 1, 0}
	if !bytes.Equal(bits, want) {
		t.Errorf("DemodulatePWM = %v, want %v", bits, want)
	}
}

func TestDemodulatePWMEmpty(t *testing.T) {
	if bits := DemodulatePWM(nil, 2.0); bits != nil {
		t.Errorf("expected nil, got %v", bits)
	}
}

// ---------------------------------------------------------------------------
// DemodulateManchester
// ---------------------------------------------------------------------------

func TestDemodulateManchesterBasic(t *testing.T) {
	te := 400
	// bit 1 = mark+space, bit 0 = space+mark (IEEE 802.3)
	// Encode: 1, 0, 1, 1, 0
	pulses := []int{te, -te, -te, te, te, -te, te, -te, -te, te}
	bits := DemodulateManchester(pulses)
	want := []byte{1, 0, 1, 1, 0}
	if !bytes.Equal(bits, want) {
		t.Errorf("DemodulateManchester = %v, want %v", bits, want)
	}
}

func TestDemodulateManchesterEmpty(t *testing.T) {
	if bits := DemodulateManchester(nil); bits != nil {
		t.Errorf("expected nil, got %v", bits)
	}
	if bits := DemodulateManchester([]int{400}); bits != nil {
		t.Errorf("expected nil for single pulse, got %v", bits)
	}
}

// ---------------------------------------------------------------------------
// BitsToBytes / BytesToBits round-trip
// ---------------------------------------------------------------------------

func TestBitsBytesRoundTrip(t *testing.T) {
	cases := []struct {
		bits []byte
	}{
		{[]byte{1, 0, 1, 0, 1, 1, 0, 0}},
		{[]byte{1, 1, 1, 1, 1, 1, 1, 1}},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{[]byte{1, 0, 1, 0, 1, 0, 1, 0, 1, 1}}, // 10 bits
		{[]byte{1}},
	}
	for _, tc := range cases {
		packed := BitsToBytes(tc.bits)
		unpacked := BytesToBits(packed, len(tc.bits))
		if !bytes.Equal(unpacked, tc.bits) {
			t.Errorf("round-trip failed: input=%v packed=%08b unpacked=%v",
				tc.bits, packed, unpacked)
		}
	}
}

func TestBitsToBytesEmpty(t *testing.T) {
	if got := BitsToBytes(nil); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestBytesToBitsEmpty(t *testing.T) {
	if got := BytesToBits(nil, 0); len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// EncodePWMPulses / round-trip with DemodulatePWM
// ---------------------------------------------------------------------------

func TestEncodePWMRoundTrip(t *testing.T) {
	te := 350
	bits := []byte{1, 0, 0, 1, 1, 0, 1, 0}
	// Princeton-style: "1" = 3×TE mark + 1×TE space, "0" = 1×TE mark + 3×TE space
	// No sync pulses so the marks are exactly TE or 3×TE
	pulses := EncodePWMPulses(bits, te, 0, 0, 3, 1, 1, 3, 1)

	// Demodulate with a 2× threshold: marks ≥ 2×TE = 700 are "1"
	decoded := DemodulatePWM(pulses, 2.0)
	if !bytes.Equal(decoded, bits) {
		t.Errorf("PWM round-trip: encoded %v, decoded %v", bits, decoded)
	}
}

// ---------------------------------------------------------------------------
// EncodeManchesterPulses round-trip
// ---------------------------------------------------------------------------

func TestEncodeManchesterRoundTrip(t *testing.T) {
	te := 400
	bits := []byte{1, 0, 1, 1, 0, 0, 1, 0}
	pulses := EncodeManchesterPulses(bits, te, 1)
	decoded := DemodulateManchester(pulses)
	if !bytes.Equal(decoded, bits) {
		t.Errorf("Manchester round-trip: encoded %v, decoded %v", bits, decoded)
	}
}
