// SPDX-License-Identifier: AGPL-3.0-or-later

package t55xx

import "testing"

func TestEncodeMatchesKnownConfigs(t *testing.T) {
	// EM4100 config 0x00148040: RF/64 (5), ASK/Manchester (8), max block 2.
	em, err := EncodeHex(EncodeParams{DataBitRateRaw: 5, ModulationRaw: 8, MaxBlock: 2})
	if err != nil {
		t.Fatalf("EncodeHex EM4100: %v", err)
	}
	if em != "00148040" {
		t.Errorf("EM4100 config = %q, want 00148040", em)
	}
	// HID config 0x00107060: RF/50 (4), FSK2a (7), max block 3.
	hid, err := EncodeHex(EncodeParams{DataBitRateRaw: 4, ModulationRaw: 7, MaxBlock: 3})
	if err != nil {
		t.Fatalf("EncodeHex HID: %v", err)
	}
	if hid != "00107060" {
		t.Errorf("HID config = %q, want 00107060", hid)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := []EncodeParams{
		{DataBitRateRaw: 5, ModulationRaw: 8, MaxBlock: 2},
		{DataBitRateRaw: 4, ModulationRaw: 7, MaxBlock: 3},
		{MasterKey: 0, DataBitRateRaw: 2, ModulationRaw: 1, PSKClock: 1, AnswerOnRequest: true, MaxBlock: 4, PasswordEnabled: true, SequenceTerminator: true},
		{DataBitRateRaw: 7, ModulationRaw: 0x18, MaxBlock: 7},
	}
	for _, p := range cases {
		b, err := Encode(p)
		if err != nil {
			t.Fatalf("Encode(%+v): %v", p, err)
		}
		c := Decode(b)
		if c.MasterKey != p.MasterKey || c.DataBitRateRaw != p.DataBitRateRaw ||
			c.ModulationRaw != p.ModulationRaw || c.AnswerOnRequest != p.AnswerOnRequest ||
			c.MaxBlock != p.MaxBlock || c.PasswordEnabled != p.PasswordEnabled ||
			c.SequenceTerminator != p.SequenceTerminator {
			t.Errorf("round-trip mismatch for %+v -> %+v", p, c)
		}
	}
}

func TestEncodeRangeErrors(t *testing.T) {
	for _, p := range []EncodeParams{
		{MasterKey: 16},
		{DataBitRateRaw: 8},
		{ModulationRaw: 32},
		{PSKClock: 4, ModulationRaw: 1},
		{MaxBlock: 8},
	} {
		if _, err := Encode(p); err == nil {
			t.Errorf("Encode(%+v) expected range error", p)
		}
	}
}
