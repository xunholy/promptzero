package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestWiegand26_KnownGood pins the canonical 26-bit H10301 parser
// against a worked example. Reference: HID Prox specification —
// facility code 123 (0x7B), card number 45678 (0xB26E), with valid
// parities. Bits are constructed byte-by-byte:
//
//	leading even parity = 1 (over bits 1-12)
//	facility 123 = 0111 1011
//	card 45678 = 1011 0010 0110 1110
//	trailing odd parity = 1 (over bits 13-24)
//
// Hand-validated:
//
//	bits 1-12  = 01111011 1011 → seven 1s → odd → leading parity = 1 (to make even)
//	bits 13-24 = 0010 0110 1110 → six 1s → even → trailing parity = 1 (to make odd)
func TestWiegand26_KnownGood(t *testing.T) {
	// 1 01111011 1011001001101110 1
	in := "1" + "01111011" + "1011001001101110" + "1"
	bits, err := parseBitString(in)
	if err != nil {
		t.Fatalf("parseBitString: %v", err)
	}
	res, err := DecodeWiegand(bits)
	if err != nil {
		t.Fatalf("DecodeWiegand: %v", err)
	}
	if res.Format != "H10301 (26-bit)" {
		t.Errorf("Format = %q", res.Format)
	}
	if res.FacilityCode != 123 {
		t.Errorf("FacilityCode = %d, want 123", res.FacilityCode)
	}
	if res.CardNumber != 45678 {
		t.Errorf("CardNumber = %d, want 45678", res.CardNumber)
	}
	if !res.ParityValid {
		t.Errorf("ParityValid = false; expected valid for hand-constructed example")
	}
}

// TestWiegand26_BadParity confirms ParityValid flips off when the
// frame is corrupt at one bit.
func TestWiegand26_BadParity(t *testing.T) {
	// Same as above but flip the leading parity to 0 (now incorrect).
	in := "0" + "01111011" + "1011001001101110" + "1"
	bits, err := parseBitString(in)
	if err != nil {
		t.Fatalf("parseBitString: %v", err)
	}
	res, err := DecodeWiegand(bits)
	if err != nil {
		t.Fatalf("DecodeWiegand: %v", err)
	}
	if res.ParityValid {
		t.Errorf("ParityValid = true; flipped leading bit should invalidate parity")
	}
	// Facility code + card number still parse — the data isn't lost,
	// just the parity check fails.
	if res.FacilityCode != 123 || res.CardNumber != 45678 {
		t.Errorf("data fields drifted on bad parity: facility=%d, card=%d",
			res.FacilityCode, res.CardNumber)
	}
}

// TestWiegand_UnsupportedBitCount confirms unusual lengths produce a
// clean error mentioning the supported set, rather than a silent
// misparse.
func TestWiegand_UnsupportedBitCount(t *testing.T) {
	bits := make([]bool, 30) // not 26/34/35/37
	_, err := DecodeWiegand(bits)
	if err == nil {
		t.Fatal("expected error for unsupported bit count")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error %q should mention unsupported", err.Error())
	}
	if !strings.Contains(err.Error(), "26") {
		t.Errorf("error %q should mention the supported set", err.Error())
	}
}

// TestParseBitString_RejectsNonBinary covers the parseBitString
// guard that errors on any character outside '0' and '1'. Crucial
// because operators paste captures with stray characters (commas,
// dashes, hex prefixes).
func TestParseBitString_RejectsNonBinary(t *testing.T) {
	_, err := parseBitString("0101a01")
	if err == nil {
		t.Fatal("expected error for non-binary character")
	}
	if !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("error %q should mention invalid character", err.Error())
	}
}

// TestWiegandHandler_StripsWhitespace pins the loose-formatting
// tolerance of the Spec handler — operators paste captures with
// spaces/tabs/underscores between groups for readability. Uses the
// package-internal wiegandDecodeSpec directly so the test is
// immune to spec_test.go's resetForTest() registry wipes.
func TestWiegandHandler_StripsWhitespace(t *testing.T) {
	out, err := wiegandDecodeSpec.Handler(context.Background(), &Deps{}, map[string]any{
		"bits": "1 01111011 1011001001101110 1",
	})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	var res WiegandResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, out)
	}
	if res.FacilityCode != 123 || res.CardNumber != 45678 {
		t.Errorf("whitespace-padded input parsed as facility=%d, card=%d (want 123/45678)",
			res.FacilityCode, res.CardNumber)
	}
}

// TestWiegandHandler_RequiresBits confirms missing 'bits' arg yields
// a friendly error rather than a nil-deref.
func TestWiegandHandler_RequiresBits(t *testing.T) {
	_, err := wiegandDecodeSpec.Handler(context.Background(), &Deps{}, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing 'bits' arg")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error %q should mention 'required'", err.Error())
	}
}

// TestWiegand34_ParsesAndValidatesParity exercises the 34-bit format
// against a hand-constructed example with valid parity.
func TestWiegand34_ParsesAndValidatesParity(t *testing.T) {
	// Construct: facility=0x1234, card=0x5678, then compute parities.
	mustBits := func(s string) []bool {
		out := make([]bool, len(s))
		for i, r := range s {
			out[i] = r == '1'
		}
		return out
	}
	facility := mustBits("0001001000110100") // 0x1234
	card := mustBits("0101011001111000")     // 0x5678
	bits := make([]bool, 34)
	copy(bits[1:17], facility)
	copy(bits[17:33], card)
	bits[0] = evenParity(bits[1:17])
	bits[33] = oddParity(bits[17:33])

	res, err := DecodeWiegand(bits)
	if err != nil {
		t.Fatalf("DecodeWiegand: %v", err)
	}
	if res.FacilityCode != 0x1234 {
		t.Errorf("FacilityCode = %#x, want 0x1234", res.FacilityCode)
	}
	if res.CardNumber != 0x5678 {
		t.Errorf("CardNumber = %#x, want 0x5678", res.CardNumber)
	}
	if !res.ParityValid {
		t.Error("ParityValid = false on hand-constructed valid frame")
	}
	if res.BitCount != 34 {
		t.Errorf("BitCount = %d, want 34", res.BitCount)
	}
}

// TestParityHelpers covers the two parity-bit primitives.
func TestParityHelpers(t *testing.T) {
	// Even parity: leading bit makes total ones count even.
	if got := evenParity([]bool{true, false, true}); got != false {
		t.Errorf("evenParity(101) = true, want false (already 2 ones)")
	}
	if got := evenParity([]bool{true, true, true}); got != true {
		t.Errorf("evenParity(111) = false, want true (3 ones → need 1 more)")
	}
	// Odd parity: trailing bit makes total ones count odd.
	if got := oddParity([]bool{true, false, true}); got != true {
		t.Errorf("oddParity(101) = false, want true (2 ones → need 1 more)")
	}
	if got := oddParity([]bool{true, true, true}); got != false {
		t.Errorf("oddParity(111) = true, want false (already 3 ones)")
	}
}
