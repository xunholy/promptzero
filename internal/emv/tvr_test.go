// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"strings"
	"testing"
)

// A clean TVR (all zeroes) flags nothing.
func TestDecodeTVR_Clean(t *testing.T) {
	tvr, err := DecodeTVRHex("0000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !tvr.Clean {
		t.Errorf("0000000000: expected Clean=true, got %+v", tvr)
	}
	if len(tvr.Indications) != 0 {
		t.Errorf("0000000000: expected no indications, got %v", tvr.Indications)
	}
	if len(tvr.Notes) != 0 {
		t.Errorf("0000000000: expected no notes, got %v", tvr.Notes)
	}
}

// Each functional byte decoded in isolation, asserting the exact flag per EMV
// Book 3 Annex C5. The decode is a direct mask of the published table, so these
// single-bit vectors are authoritative.
func TestDecodeTVR_SingleBits(t *testing.T) {
	cases := []struct {
		hex  string
		want string // substring expected in the flat indications
	}{
		{"4000000000", "SDA failed"},                                 // byte1 0x40
		{"0800000000", "DDA failed"},                                 // byte1 0x08
		{"0400000000", "CDA failed"},                                 // byte1 0x04
		{"0040000000", "Expired application"},                        // byte2 0x40
		{"0000200000", "PIN Try Limit exceeded"},                     // byte3 0x20
		{"0000800000", "Cardholder verification was not successful"}, // byte3 0x80
		{"0000008000", "Transaction exceeds floor limit"},            // byte4 0x80
		{"0000004000", "Lower consecutive offline limit exceeded"},   // byte4 0x40
		{"0000000040", "Issuer authentication failed"},               // byte5 0x40
		{"0000000020", "Script processing failed before final GENERATE AC"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			tvr, err := DecodeTVRHex(c.hex)
			if err != nil {
				t.Fatalf("DecodeTVRHex(%q): %v", c.hex, err)
			}
			if tvr.Clean {
				t.Errorf("%s: expected not clean", c.hex)
			}
			joined := strings.Join(tvr.Indications, " | ")
			if !strings.Contains(joined, c.want) {
				t.Errorf("%s: indications %q missing %q", c.hex, joined, c.want)
			}
		})
	}
}

// A realistic offline-decline TVR: SDA failed (byte1 0x40) + cardholder
// verification not successful (byte3 0x80) + transaction exceeds floor limit
// (byte4 0x80) → 0x40 00 80 80 00.
func TestDecodeTVR_RealValue(t *testing.T) {
	tvr, err := DecodeTVRHex("4000808000")
	if err != nil {
		t.Fatal(err)
	}
	if tvr.Clean {
		t.Fatal("4000808000: should not be clean")
	}
	if len(tvr.OfflineDataAuthentication) != 1 || tvr.OfflineDataAuthentication[0] != "SDA failed" {
		t.Errorf("byte1 group = %v, want [SDA failed]", tvr.OfflineDataAuthentication)
	}
	if len(tvr.CardholderVerification) != 1 {
		t.Errorf("byte3 group = %v, want one entry", tvr.CardholderVerification)
	}
	if len(tvr.TerminalRiskManagement) != 1 {
		t.Errorf("byte4 group = %v, want one entry", tvr.TerminalRiskManagement)
	}
	if len(tvr.Indications) != 3 {
		t.Errorf("expected 3 flat indications, got %d: %v", len(tvr.Indications), tvr.Indications)
	}
}

// An RFU bit set in a byte must be surfaced as a note, never named.
func TestDecodeTVR_RFUNote(t *testing.T) {
	// byte 1 bit 1 (0x01) is RFU.
	tvr, err := DecodeTVRHex("0100000000")
	if err != nil {
		t.Fatal(err)
	}
	if len(tvr.Notes) != 1 {
		t.Errorf("0100000000: expected 1 RFU note, got %v", tvr.Notes)
	}
	// 0x01 is RFU in byte 1, so it is not a real indication.
	if len(tvr.Indications) != 0 {
		t.Errorf("0100000000: RFU bit must not be a named indication, got %v", tvr.Indications)
	}
	// Clean is about exception bits; an RFU-only TVR has no named exception.
	if !tvr.Clean {
		t.Errorf("0100000000: no named bit set, expected Clean=true")
	}
}

func TestDecodeTVR_Rejects(t *testing.T) {
	for _, bad := range []string{"", "95", "00000000", "000000000000", "zz"} {
		if _, err := DecodeTVRHex(bad); err == nil {
			t.Errorf("DecodeTVRHex(%q): expected error, got nil", bad)
		}
	}
}
