// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"strings"
	"testing"
)

// TestDecodeTrack2_HandVector decodes a hand-built blob for the canonical
// Luhn-valid Visa test PAN. The nibble string "4111...D25122010000000F" is
// itself valid hex (D and F are hex digits), so it doubles as the raw bytes.
func TestDecodeTrack2_HandVector(t *testing.T) {
	r, err := DecodeTrack2Hex("4111111111111111D25122010000000F")
	if err != nil {
		t.Fatal(err)
	}
	if r.PAN != "4111111111111111" {
		t.Errorf("PAN = %s, want 4111111111111111", r.PAN)
	}
	if r.PANMasked != "411111******1111" {
		t.Errorf("masked = %s, want 411111******1111", r.PANMasked)
	}
	if r.Expiry != "2512" || r.ExpiryFormatted != "12/25" {
		t.Errorf("expiry = %s / %s, want 2512 / 12/25", r.Expiry, r.ExpiryFormatted)
	}
	if r.ServiceCode != "201" {
		t.Errorf("service = %s, want 201", r.ServiceCode)
	}
	if r.Discretionary != "0000000" {
		t.Errorf("discretionary = %s, want 0000000", r.Discretionary)
	}
	if !r.LuhnValid {
		t.Error("4111111111111111 is a Luhn-valid PAN")
	}
	if !strings.Contains(r.ServiceCodeMeaning, "IC preferred") {
		t.Errorf("service meaning = %q, want it to mention IC preferred", r.ServiceCodeMeaning)
	}
}

func TestDecodeTrack2_Mastercard(t *testing.T) {
	// Canonical Mastercard test PAN, no discretionary/pad (even nibble count).
	r, err := DecodeTrack2Hex("5555555555554444D2912101")
	if err != nil {
		t.Fatal(err)
	}
	if r.PAN != "5555555555554444" || !r.LuhnValid {
		t.Errorf("PAN/luhn = %s/%v, want 5555555555554444/true", r.PAN, r.LuhnValid)
	}
	if r.Expiry != "2912" || r.ServiceCode != "101" {
		t.Errorf("expiry/service = %s/%s, want 2912/101", r.Expiry, r.ServiceCode)
	}
}

func TestDecodeTrack2_LuhnFail(t *testing.T) {
	// Last PAN digit flipped 1->2: Luhn must fail and a note must surface.
	r, err := DecodeTrack2Hex("4111111111111112D25122010000000F")
	if err != nil {
		t.Fatal(err)
	}
	if r.LuhnValid {
		t.Error("4111111111111112 should fail Luhn")
	}
	if len(r.Notes) == 0 || !strings.Contains(r.Notes[0], "Luhn") {
		t.Errorf("expected a Luhn-failure note, got %v", r.Notes)
	}
}

func TestDecodeTrack2_ShortPAN(t *testing.T) {
	// 13-digit Visa-style PAN (legacy length), Luhn-valid: 4222222222222.
	r, err := DecodeTrack2Hex("4222222222222D2512201F")
	if err != nil {
		t.Fatal(err)
	}
	if r.PAN != "4222222222222" || !r.LuhnValid {
		t.Errorf("PAN/luhn = %s/%v, want 4222222222222/true", r.PAN, r.LuhnValid)
	}
	// 13 digits: BIN(6) + 3 stars + last 4.
	if r.PANMasked != "422222***2222" {
		t.Errorf("masked = %s, want 422222***2222", r.PANMasked)
	}
}

func TestDecodeTrack2_Errors(t *testing.T) {
	bad := []string{
		"",                         // empty
		"41111111111111110000",     // no 'D' separator
		"D25122010000000F",         // empty PAN before separator
		"4111D25",                  // PAN too short (<8) AND truncated
		"4111111111111111D251",     // truncated after separator (<7 nibbles)
		"41A1111111111111D2512201", // non-decimal nibble — but A is hex... see note
	}
	for i, s := range bad {
		if _, err := DecodeTrack2Hex(s); err == nil {
			t.Errorf("case %d (%q): expected error", i, s)
		}
	}
}

// TestDecodeTrack2_RoundTrip builds track-2 nibbles from fields and confirms
// the decoder recovers them, across PAN lengths and service codes.
func TestDecodeTrack2_RoundTrip(t *testing.T) {
	cases := []struct {
		pan, expiry, service string
	}{
		{"4111111111111111", "2512", "201"},
		{"5555555555554444", "3001", "120"},
		{"4222222222222", "2606", "101"}, // 13-digit
		{"6011000990139424", "2812", "220"},
	}
	for _, c := range cases {
		nib := c.pan + "D" + c.expiry + c.service
		if len(nib)%2 == 1 {
			nib += "F"
		}
		r, err := DecodeTrack2Hex(nib)
		if err != nil {
			t.Fatalf("pan %s: %v", c.pan, err)
		}
		if r.PAN != c.pan || r.Expiry != c.expiry || r.ServiceCode != c.service {
			t.Errorf("pan %s: got %s/%s/%s", c.pan, r.PAN, r.Expiry, r.ServiceCode)
		}
		if !r.LuhnValid {
			t.Errorf("pan %s: expected Luhn-valid test PAN", c.pan)
		}
	}
}
