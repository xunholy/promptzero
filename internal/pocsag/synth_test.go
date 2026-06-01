// SPDX-License-Identifier: AGPL-3.0-or-later

package pocsag

import (
	"strings"
	"testing"
)

// TestBuildCodeword_IdleReference verifies the BCH(31,21) + even-parity
// implementation against the canonical POCSAG idle codeword: rebuilding it
// from its own 21 data bits must reproduce it exactly. This grounds the
// encoder in a published constant, independent of the decoder.
func TestBuildCodeword_IdleReference(t *testing.T) {
	if got := buildCodeword(IdleWord >> 11); got != IdleWord {
		t.Fatalf("buildCodeword(idle data) = %08X, want idle %08X", got, IdleWord)
	}
	// Every codeword we emit must satisfy the decoder's even-parity check.
	for _, w := range []uint32{IdleWord, buildCodeword(0x155555), addressCodeword(0x12345, 0)} {
		if !parityOK(w) {
			t.Errorf("codeword %08X fails parityOK", w)
		}
	}
}

// TestSynth_RoundTrip is the primary check: a transmission built by Synth
// must decode back to the same page (address, function, message) via the
// independent Decode path, with no parity errors, across encodings and
// frame positions.
func TestSynth_RoundTrip(t *testing.T) {
	cases := []struct {
		in      SynthInput
		wantMsg string // after numeric trailing-space trim
		wantEnc string
	}{
		{SynthInput{Address: 0x12345, Function: 0, Message: "12345"}, "12345", "numeric"},
		{SynthInput{Address: 0x000000, Function: 0, Message: "1234567890"}, "1234567890", "numeric"},
		{SynthInput{Address: 0x1FFFFF, Function: 3, Message: ""}, "", "tone"},
		{SynthInput{Address: 0x0ABCDE, Function: 1, Message: "HELLO"}, "HELLO", "alphanumeric"},
		{SynthInput{Address: 0x000007, Function: 2, Message: "Pg"}, "Pg", "alphanumeric"},
		{SynthInput{Address: 0x100000, Function: 0, Message: "911"}, "911", "numeric"}, // padded → trim
	}
	for _, c := range cases {
		stream, err := Synth(c.in)
		if err != nil {
			t.Fatalf("Synth(%+v): %v", c.in, err)
		}
		res, err := Decode(stream)
		if err != nil {
			t.Fatalf("Decode(Synth(%+v)): %v", c.in, err)
		}
		if res.ParityErrors != 0 {
			t.Errorf("%+v: %d parity errors in synthesized stream", c.in, res.ParityErrors)
		}
		var pg *Page
		for i := range res.Pages {
			if res.Pages[i].Address == c.in.Address {
				pg = &res.Pages[i]
			}
		}
		if pg == nil {
			t.Fatalf("%+v: no page with address %07X (got %+v)", c.in, c.in.Address, res.Pages)
		}
		if pg.Function != c.in.Function {
			t.Errorf("%+v: function round-trips to %d", c.in, pg.Function)
		}
		if pg.Encoding != c.wantEnc {
			t.Errorf("%+v: encoding = %q, want %q", c.in, pg.Encoding, c.wantEnc)
		}
		if got := strings.TrimRight(pg.Message, " "); got != c.wantMsg {
			t.Errorf("%+v: message round-trips to %q (trimmed), want %q", c.in, got, c.wantMsg)
		}
	}
}

func TestSynth_RejectsBadInput(t *testing.T) {
	bad := []SynthInput{
		{Address: 0x200000, Function: 0, Message: "1"}, // address > 21 bits
		{Address: 1, Function: 4, Message: "1"},        // function out of range
		{Address: 1, Function: 3, Message: "no"},       // tone with a body
		{Address: 1, Function: 0, Message: "ABC"},      // non-numeric chars in numeric msg
		{Address: 1, Function: 1, Message: "é"},        // non-ASCII alphanumeric
		// frame 7 (address&7==7) leaves only 1 message codeword; 10 alnum
		// chars need 4 → overflow the single batch.
		{Address: 0x000007, Function: 1, Message: "ABCDEFGHIJ"},
	}
	for _, in := range bad {
		if _, err := Synth(in); err == nil {
			t.Errorf("Synth(%+v): expected error, got nil", in)
		}
	}
}
