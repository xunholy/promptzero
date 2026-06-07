// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "testing"

// necPronto is a Pronto HEX NEC code (format 0x0000, frequency word 0x006D =
// 38 kHz, 34 intro pairs, 0 repeat) built from a real NEC frame (address 0x04,
// command 0x08) so its burst-pair counts are exactly consistent — the carrier
// (0x006D -> 38029 Hz) and the burst->µs conversion (0156/00AB -> ~9000/4500
// leader) are the independent anchors, and the converted timings chain-decode
// to NEC.
const necPronto = "0000 006D 0022 0000 0156 00AB 0015 0015 0015 0015 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0040 0015 0015 0015 0040 0015 0040 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0015 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0040 0015 0040 0015 0015 0015 0040 0015 0040 0015 0040 0015 0040 0015 05F1"

func TestDecodeProntoNEC(t *testing.T) {
	r, err := DecodePronto(necPronto)
	if err != nil {
		t.Fatalf("DecodePronto: %v", err)
	}
	if r.CarrierHz != 38029 {
		t.Errorf("carrier = %d Hz, want 38029", r.CarrierHz)
	}
	if r.IntroPairs != 0x22 || r.RepeatPairs != 0 {
		t.Errorf("pairs intro=%d repeat=%d, want 34/0", r.IntroPairs, r.RepeatPairs)
	}
	// 34 intro pairs => 68 timing values; leader ~9000/4500.
	if len(r.IntroTimings) != 68 {
		t.Fatalf("intro timings = %d, want 68", len(r.IntroTimings))
	}
	if !within(r.IntroTimings[0], 9000) || !within(r.IntroTimings[1], 4500) {
		t.Errorf("leader = %d/%d, want ~9000/4500", r.IntroTimings[0], r.IntroTimings[1])
	}
	// The chained protocol decode should identify NEC.
	if r.Protocol == nil || r.Protocol.Protocol != "NEC" && r.Protocol.Protocol != "NEC-extended" {
		got := "nil"
		if r.Protocol != nil {
			got = r.Protocol.Protocol
		}
		t.Errorf("chained protocol = %q, want NEC/NEC-extended", got)
	}
}

func TestDecodeProntoCarrierAnchor(t *testing.T) {
	// The canonical anchor: frequency word 0x006D => 38029 Hz.
	r, err := DecodePronto("0000 006D 0001 0000 0157 00AB")
	if err != nil {
		t.Fatalf("DecodePronto: %v", err)
	}
	if r.CarrierHz != 38029 {
		t.Errorf("carrier = %d, want 38029", r.CarrierHz)
	}
	if r.Format != "raw (oscillated / modulated)" {
		t.Errorf("format = %q", r.Format)
	}
	if r.IntroTimings[0] != 9019 || r.IntroTimings[1] != 4497 {
		t.Errorf("timings = %d/%d, want 9019/4497", r.IntroTimings[0], r.IntroTimings[1])
	}
}

func TestDecodeProntoPredefinedFormatNoted(t *testing.T) {
	// A predefined-code format word (e.g. 0x5000) is reported, not converted.
	r, err := DecodePronto("5000 006D 0000 0000")
	if err != nil {
		t.Fatalf("DecodePronto: %v", err)
	}
	if r.CarrierHz != 0 || len(r.IntroTimings) != 0 {
		t.Errorf("predefined format should not be converted to carrier/timings")
	}
	if len(r.Notes) == 0 {
		t.Errorf("expected a note about the predefined format")
	}
}

func TestDecodeProntoErrors(t *testing.T) {
	for _, in := range []string{
		"",
		"0000 006D",                     // too few words
		"0000 006D 0001 0000",           // count says 1 intro pair but no burst data
		"0000 0000 0001 0000 0157 00AB", // zero frequency
		"00 006D 0001 0000",             // non-4-digit word
		"zzzz 006D 0001 0000",           // bad hex
	} {
		if _, err := DecodePronto(in); err == nil {
			t.Errorf("DecodePronto(%q) expected error", in)
		}
	}
}
