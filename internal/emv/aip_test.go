// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import "testing"

// Each byte-1 bit decoded in isolation, asserting the exact boolean per EMV
// Book 3 Annex C1. The decode is a direct mask of the published bit table, so
// these single-bit vectors are authoritative.
func TestDecodeAIP_SingleBits(t *testing.T) {
	cases := []struct {
		hex  string
		want func(*AIP) bool
		name string
	}{
		{"4000", func(a *AIP) bool { return a.SDA && !a.DDA && !a.CDA }, "SDA"},
		{"2000", func(a *AIP) bool { return a.DDA && !a.SDA }, "DDA"},
		{"1000", func(a *AIP) bool { return a.CardholderVerification }, "cardholder-verif"},
		{"0800", func(a *AIP) bool { return a.TerminalRiskManagement }, "terminal-risk"},
		{"0400", func(a *AIP) bool { return a.IssuerAuthentication }, "issuer-auth"},
		{"0200", func(a *AIP) bool { return a.OnDeviceCVM }, "on-device-cvm"},
		{"0100", func(a *AIP) bool { return a.CDA && !a.DDA }, "CDA"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := DecodeAIPHex(c.hex)
			if err != nil {
				t.Fatalf("DecodeAIPHex(%q): %v", c.hex, err)
			}
			if !c.want(a) {
				t.Errorf("%s: bit not decoded as expected for %s: %+v", c.name, c.hex, a)
			}
		})
	}
}

// Realistic combined AIP values seen on real cards.
func TestDecodeAIP_RealValues(t *testing.T) {
	// 0x7C00 = 0111 1100: SDA + DDA + cardholder-verif + terminal-risk +
	// issuer-auth — a common offline-DDA credit card.
	a, err := DecodeAIPHex("7C00")
	if err != nil {
		t.Fatal(err)
	}
	full := a.SDA && a.DDA && a.CardholderVerification && a.TerminalRiskManagement && a.IssuerAuthentication
	if !full {
		t.Errorf("7C00: expected SDA+DDA+CV+TRM+IssuerAuth, got %+v", a)
	}
	if a.OnDeviceCVM || a.CDA {
		t.Errorf("7C00: did not expect OnDeviceCVM/CDA, got %+v", a)
	}
	if a.OfflineDataAuthentication != "DDA" {
		t.Errorf("7C00: ODA headline = %q, want DDA", a.OfflineDataAuthentication)
	}
	if len(a.Capabilities) != 5 {
		t.Errorf("7C00: want 5 capabilities, got %d: %v", len(a.Capabilities), a.Capabilities)
	}

	// 0x1800 = 0001 1000: cardholder-verif + terminal-risk, NO offline auth
	// → online-only card.
	b, err := DecodeAIPHex("1800")
	if err != nil {
		t.Fatal(err)
	}
	if b.SDA || b.DDA || b.CDA {
		t.Errorf("1800: expected no offline auth, got %+v", b)
	}
	if b.OfflineDataAuthentication != "none advertised — card relies on online authorization" {
		t.Errorf("1800: ODA headline = %q", b.OfflineDataAuthentication)
	}

	// 0x0500 = 0000 0101: issuer-auth + CDA. CDA must win the ODA headline.
	c, err := DecodeAIPHex("0500")
	if err != nil {
		t.Fatal(err)
	}
	if !c.CDA || !c.IssuerAuthentication {
		t.Errorf("0500: expected CDA+IssuerAuth, got %+v", c)
	}
	if c.OfflineDataAuthentication != "CDA (strongest — combined DDA + cryptogram)" {
		t.Errorf("0500: ODA headline = %q, want CDA", c.OfflineDataAuthentication)
	}
}

// Byte 1 bit 8 and any non-zero byte 2 are RFU in the contact profile and must
// be surfaced as a note, never silently interpreted.
func TestDecodeAIP_RFUNotes(t *testing.T) {
	a, err := DecodeAIPHex("8040")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Notes) != 2 {
		t.Errorf("8040: expected 2 RFU notes (byte1 bit8 + byte2), got %d: %v", len(a.Notes), a.Notes)
	}

	// Clean SDA card: no RFU bits set → no notes.
	clean, err := DecodeAIPHex("4000")
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.Notes) != 0 {
		t.Errorf("4000: expected no notes, got %v", clean.Notes)
	}
}

func TestDecodeAIP_Rejects(t *testing.T) {
	for _, bad := range []string{"", "82", "7C0000", "zz"} {
		if _, err := DecodeAIPHex(bad); err == nil {
			t.Errorf("DecodeAIPHex(%q): expected error, got nil", bad)
		}
	}
}
