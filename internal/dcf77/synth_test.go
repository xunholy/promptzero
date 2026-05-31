// SPDX-License-Identifier: AGPL-3.0-or-later

package dcf77

import "testing"

// TestSynth_RoundTrip is the primary correctness check: a telegram built
// by Synth must decode back to the exact input via the independent Decode
// path, with every parity bit valid.
func TestSynth_RoundTrip(t *testing.T) {
	cases := []SynthInput{
		{Minute: 35, Hour: 14, DayOfMonth: 22, DayOfWeek: 2, Month: 4, Year: 26, CEST: true},
		{Minute: 0, Hour: 0, DayOfMonth: 1, DayOfWeek: 1, Month: 1, Year: 0, CEST: false},
		{Minute: 59, Hour: 23, DayOfMonth: 31, DayOfWeek: 7, Month: 12, Year: 99, CEST: false},
		{Minute: 47, Hour: 9, DayOfMonth: 15, DayOfWeek: 3, Month: 10, Year: 84, CEST: true},
	}
	for _, in := range cases {
		bits, err := Synth(in)
		if err != nil {
			t.Fatalf("Synth(%+v): %v", in, err)
		}
		if len(bits) != 60 {
			t.Fatalf("Synth(%+v): got %d bits, want 60", in, len(bits))
		}
		f, err := Decode(bits)
		if err != nil {
			t.Fatalf("Decode(Synth(%+v)): %v", in, err)
		}
		if !f.AllParityValid {
			t.Errorf("%+v: round-trip frame failed parity: %s", in, bits)
		}
		if f.Minute != in.Minute || f.Hour != in.Hour || f.DayOfMonth != in.DayOfMonth ||
			f.DayOfWeek != in.DayOfWeek || f.Month != in.Month || f.Year != in.Year {
			t.Errorf("%+v round-trips to min=%d hr=%d dom=%d dow=%d mon=%d yr=%d",
				in, f.Minute, f.Hour, f.DayOfMonth, f.DayOfWeek, f.Month, f.Year)
		}
		if f.CESTActive != in.CEST {
			t.Errorf("%+v: CESTActive=%v want %v", in, f.CESTActive, in.CEST)
		}
		if f.TimezoneOffsetHours != map[bool]int{true: 2, false: 1}[in.CEST] {
			t.Errorf("%+v: tz offset=%d", in, f.TimezoneOffsetHours)
		}
	}
}

// TestSynth_FixedBits hand-verifies the structural markers and a known BCD
// field independent of Decode. Minute 25 = tens 2 (weight 20) + units 5
// (weights 1+4) → bits at offsets 0,2 and 21..27 weighted {1,2,4,8,10,20,40}:
// positions for 1,4,20 set. Even parity over those 3 ones → parity bit = 1.
func TestSynth_FixedBits(t *testing.T) {
	bits, err := Synth(SynthInput{Minute: 25, Hour: 0, DayOfMonth: 1, DayOfWeek: 1, Month: 1, Year: 0, CEST: true})
	if err != nil {
		t.Fatalf("Synth: %v", err)
	}
	if bits[0] != '0' {
		t.Errorf("bit 0 (start-of-minute) = %c, want 0", bits[0])
	}
	if bits[20] != '1' {
		t.Errorf("bit 20 (start-of-time) = %c, want 1", bits[20])
	}
	// CEST → bit17=1, bit18=0
	if bits[17] != '1' || bits[18] != '0' {
		t.Errorf("timezone bits = %c%c, want 10 (CEST)", bits[17], bits[18])
	}
	// Minute 25: weights {1,2,4,8,10,20,40} at bits 21..27 → set 1(b21), 4(b23), 20(b26)
	wantMin := "1010010" // b21..b27: 1,_,4,_,_,20,_
	if got := bits[21:28]; got != wantMin {
		t.Errorf("minute field bits = %q, want %q", got, wantMin)
	}
	// minute parity (b28): 3 ones → even parity bit = 1
	if bits[28] != '1' {
		t.Errorf("minute parity bit = %c, want 1", bits[28])
	}
}

func TestSynth_RejectsOutOfRange(t *testing.T) {
	bad := []SynthInput{
		{Minute: 60, Hour: 0, DayOfMonth: 1, DayOfWeek: 1, Month: 1, Year: 0},
		{Minute: 0, Hour: 24, DayOfMonth: 1, DayOfWeek: 1, Month: 1, Year: 0},
		{Minute: 0, Hour: 0, DayOfMonth: 0, DayOfWeek: 1, Month: 1, Year: 0},
		{Minute: 0, Hour: 0, DayOfMonth: 1, DayOfWeek: 8, Month: 1, Year: 0},
		{Minute: 0, Hour: 0, DayOfMonth: 1, DayOfWeek: 1, Month: 13, Year: 0},
		{Minute: 0, Hour: 0, DayOfMonth: 1, DayOfWeek: 1, Month: 1, Year: 100},
	}
	for _, in := range bad {
		if _, err := Synth(in); err == nil {
			t.Errorf("Synth(%+v): expected range error, got nil", in)
		}
	}
}
