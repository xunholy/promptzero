// SPDX-License-Identifier: AGPL-3.0-or-later

package tpms

import (
	"strings"
	"testing"
)

// TestSynth_RoundTrip is the primary check: a frame built by Synth must
// decode back to the same sensor ID + payload via the independent Decode
// path, with the chosen CRC polynomial reported as a match.
func TestSynth_RoundTrip(t *testing.T) {
	cases := []SynthInput{
		{SensorID: 0x1A2B3C4D, Payload: []byte{0x80, 0x55}, CRCPoly: 0x07},
		{SensorID: 0xDEADBEEF, Payload: []byte{0x12}, CRCPoly: 0x2F},
		{SensorID: 0x00000000, Payload: nil, CRCPoly: 0x13},
		{SensorID: 0xFFFFFFFF, Payload: []byte{0xAA, 0xBB, 0xCC}, CRCPoly: 0x07, GEThomas: true},
		{SensorID: 0x12345678, Payload: []byte{0x00}}, // CRCPoly 0 → default 0x07
	}
	polyName := map[byte]string{0x07: "CRC-8/0x07", 0x2F: "CRC-8/0x2F", 0x13: "CRC-8/0x13"}
	for _, in := range cases {
		bits, err := Synth(in)
		if err != nil {
			t.Fatalf("Synth(%+v): %v", in, err)
		}
		res, err := Decode(bits)
		if err != nil {
			t.Fatalf("Decode(Synth(%+v)): %v", in, err)
		}
		wantID := strings.ToUpper(hex4(in.SensorID))
		if res.SensorID != wantID {
			t.Errorf("%+v: SensorID = %q, want %q", in, res.SensorID, wantID)
		}
		if res.SensorIDDecimal == nil || *res.SensorIDDecimal != in.SensorID {
			t.Errorf("%+v: SensorIDDecimal mismatch (%v)", in, res.SensorIDDecimal)
		}
		wantPoly := in.CRCPoly
		if wantPoly == 0 {
			wantPoly = 0x07
		}
		if !containsStr(res.CRC8Matches, polyName[wantPoly]) {
			t.Errorf("%+v: CRC8Matches %v missing %s", in, res.CRC8Matches, polyName[wantPoly])
		}
	}
}

// TestSynth_HandComputedCRC pins the frame layout + CRC against an
// independently-built byte slice: data = [ID][payload], CRC = crc8(data).
func TestSynth_HandComputedCRC(t *testing.T) {
	in := SynthInput{SensorID: 0x1A2B3C4D, Payload: []byte{0x80, 0x55}, CRCPoly: 0x07}
	bits, err := Synth(in)
	if err != nil {
		t.Fatalf("Synth: %v", err)
	}
	data := []byte{0x1A, 0x2B, 0x3C, 0x4D, 0x80, 0x55}
	frame := append(append([]byte{}, data...), crc8(data, 0x07))
	want := encodeManchester(frame, true)
	if bits != want {
		t.Errorf("Synth bits != hand-built frame\n got=%s\nwant=%s", bits, want)
	}
	// IEEE Manchester doubles each bit, so the stream is 2× the frame bits.
	if len(bits) != len(frame)*8*2 {
		t.Errorf("bit length = %d, want %d", len(bits), len(frame)*8*2)
	}
}

func TestSynth_RejectsBadInput(t *testing.T) {
	if _, err := Synth(SynthInput{SensorID: 1, CRCPoly: 0x99}); err == nil {
		t.Error("expected error for unsupported CRC poly 0x99")
	}
	if _, err := Synth(SynthInput{SensorID: 1, Payload: make([]byte, maxSynthPayload+1)}); err == nil {
		t.Error("expected error for oversized payload")
	}
}

func hex4(v uint32) string {
	const hexdigits = "0123456789ABCDEF"
	b := []byte{
		hexdigits[(v>>28)&0xF], hexdigits[(v>>24)&0xF], hexdigits[(v>>20)&0xF], hexdigits[(v>>16)&0xF],
		hexdigits[(v>>12)&0xF], hexdigits[(v>>8)&0xF], hexdigits[(v>>4)&0xF], hexdigits[v&0xF],
	}
	return string(b)
}
