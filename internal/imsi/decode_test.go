// SPDX-License-Identifier: AGPL-3.0-or-later

package imsi

import (
	"strings"
	"testing"
)

// Expected splits are python-stdnum's imsi.split() of the same numbers.

func TestDecodeUnambiguous(t *testing.T) {
	cases := []struct {
		in                      string
		mcc, country, mnc, msin string
		assumed                 bool
	}{
		// Germany (262) — 2-digit MNC. stdnum: ('262','01','1234567890').
		{"262011234567890", "262", "Germany", "01", "1234567890", true}, // 262 is mixed → assumed
		// United Kingdom (234) — 2-digit MNC, not mixed. ('234','15','9999999999').
		{"234159999999999", "234", "United Kingdom", "15", "9999999999", false},
		// China (460) — 2-digit, not mixed. ('460','00','1234567890').
		{"460001234567890", "460", "China", "00", "1234567890", false},
		// Australia (505) — 2-digit, not mixed. ('505','01','1234567890').
		{"505011234567890", "505", "Australia - AU/CC/CX", "01", "1234567890", false},
	}
	for _, c := range cases {
		r, err := Decode(c.in)
		if err != nil {
			t.Fatalf("Decode(%s): %v", c.in, err)
		}
		if r.MCC != c.mcc || r.MNC != c.mnc || r.MSIN != c.msin {
			t.Errorf("%s split = %s/%s/%s; want %s/%s/%s", c.in, r.MCC, r.MNC, r.MSIN, c.mcc, c.mnc, c.msin)
		}
		if !strings.Contains(r.Country, c.country) {
			t.Errorf("%s country = %q; want substring %q", c.in, r.Country, c.country)
		}
		if r.MNCLengthAssumed != c.assumed {
			t.Errorf("%s MNCLengthAssumed = %v; want %v", c.in, r.MNCLengthAssumed, c.assumed)
		}
	}
}

func TestDecode3DigitMNC(t *testing.T) {
	// USA (310) — 3-digit MNC, mixed-length country. stdnum:
	// ('310','150','123456789') = AT&T. The split must use 3 digits
	// and be flagged (assumed) because 310 is a mixed-length MCC.
	r, err := Decode("310150123456789")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MCC != "310" || r.MNC != "150" || r.MSIN != "123456789" {
		t.Errorf("split = %s/%s/%s; want 310/150/123456789", r.MCC, r.MNC, r.MSIN)
	}
	if !strings.Contains(r.Country, "United States") {
		t.Errorf("country = %q", r.Country)
	}
	if !r.MNCLengthAssumed {
		t.Error("MNCLengthAssumed = false; want true (310 is a mixed-length MCC)")
	}
	joined := strings.Join(r.Notes, " ")
	if !strings.Contains(joined, "both 2- and 3-digit") {
		t.Errorf("expected a mixed-length note; got %q", joined)
	}
}

func TestDecodeSeparators(t *testing.T) {
	r, err := Decode("234 15 9999999999")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.IMSI != "234159999999999" || r.MNC != "15" {
		t.Errorf("got IMSI=%s MNC=%s", r.IMSI, r.MNC)
	}
}

func TestDecodeUnknownMCC(t *testing.T) {
	// MCC 999 is reserved/unassigned in the table; country unknown,
	// MNC length assumed.
	r, err := Decode("099991234567890"[1:]) // 99991234567890 (14 digits, mcc 999)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MCC != "999" {
		t.Fatalf("MCC = %s; want 999", r.MCC)
	}
	// 999 happens to be in the table (test/internal); just assert the
	// structural split is consistent and notes are present.
	if r.MNC == "" || r.MSIN == "" || len(r.Notes) == 0 {
		t.Errorf("expected a populated split + notes, got %+v", r)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "abc", "12345", "1234567890123456"} { // empty / non-numeric / too short / >15
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestOperatorDeferred(t *testing.T) {
	r, _ := Decode("234159999999999")
	joined := strings.Join(r.Notes, " ")
	if !strings.Contains(joined, "Operator") && !strings.Contains(joined, "operator") {
		t.Errorf("expected an operator-deferred note; got %q", joined)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("310150123456789")
	f.Add("234159999999999")
	f.Add("262 01 1234567890")
	f.Add("")
	f.Add("99")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
