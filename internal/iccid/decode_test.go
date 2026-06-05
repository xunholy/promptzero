// SPDX-License-Identifier: AGPL-3.0-or-later

package iccid

import (
	"strings"
	"testing"
)

// Test ICCIDs are 89 + E.164 country code + account, with the Luhn
// check digit computed by an independent reference (Python).

func TestDecodeValid(t *testing.T) {
	cases := []struct {
		in              string
		cc, country, rg string
		shared          bool
		check           string
	}{
		{"89440000000000000002", "44", "United Kingdom", "GB", true, "2"},
		{"89860000000000000001", "86", "China", "CN", false, "1"},
		{"89100000000000000002", "1", "United States", "US", true, "2"},
		{"89490000000000000007", "49", "Germany", "DE", false, "7"},
	}
	for _, c := range cases {
		r, err := Decode(c.in)
		if err != nil {
			t.Fatalf("Decode(%s): %v", c.in, err)
		}
		if !r.MIIValid || r.MII != "89" {
			t.Errorf("%s MII = %s (valid %v)", c.in, r.MII, r.MIIValid)
		}
		if !r.LuhnValid {
			t.Errorf("%s LuhnValid = false; want true", c.in)
		}
		if r.CountryCode != c.cc || r.Region != c.rg {
			t.Errorf("%s cc/region = %s/%s; want %s/%s", c.in, r.CountryCode, r.Region, c.cc, c.rg)
		}
		if !strings.Contains(r.Country, c.country) {
			t.Errorf("%s country = %q; want substring %q", c.in, r.Country, c.country)
		}
		if r.SharedCountryCode != c.shared {
			t.Errorf("%s shared = %v; want %v", c.in, r.SharedCountryCode, c.shared)
		}
		if r.CheckDigit != c.check {
			t.Errorf("%s check = %s; want %s", c.in, r.CheckDigit, c.check)
		}
	}
}

func TestDecodeBadLuhnFlagged(t *testing.T) {
	// Flip the check digit: still decodes, but luhn_valid=false + note.
	r, err := Decode("89440000000000000003") // correct check is 2
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LuhnValid {
		t.Error("LuhnValid = true; want false for a tampered check digit")
	}
	if r.CountryCode != "44" { // still structurally decoded
		t.Errorf("CountryCode = %s; want 44", r.CountryCode)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "Luhn check digit") {
		t.Error("expected a Luhn-mismatch note")
	}
}

func TestDecodeNonTelecomMII(t *testing.T) {
	// MII 88 (not 89): flagged, but the rest still parses.
	r, err := Decode("88440000000000000005")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MIIValid {
		t.Error("MIIValid = true; want false for MII 88")
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "not 89") {
		t.Error("expected a non-telecom MII note")
	}
}

func TestDecodeSeparators(t *testing.T) {
	r, err := Decode("8944-0000 0000:0000 0002")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ICCID != "89440000000000000002" || !r.LuhnValid {
		t.Errorf("got ICCID=%s luhn=%v", r.ICCID, r.LuhnValid)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "abc", "8944", "894400000000000000020000"} { // empty / non-numeric / too short / too long
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestLuhnReference(t *testing.T) {
	// Independent Luhn check value: "79927398713" is the canonical
	// valid Luhn example.
	if !luhnValid("79927398713") {
		t.Error("luhnValid(79927398713) = false; want true (canonical Luhn vector)")
	}
	if luhnValid("79927398710") {
		t.Error("luhnValid(79927398710) = true; want false")
	}
	if got := luhnCheckDigit("7992739871"); got != 3 {
		t.Errorf("luhnCheckDigit(7992739871) = %d; want 3", got)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("89440000000000000002")
	f.Add("8944-0000-0000-0000-0002")
	f.Add("")
	f.Add("89")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
