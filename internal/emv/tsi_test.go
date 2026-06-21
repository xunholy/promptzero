// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"strings"
	"testing"
)

// Each defined byte-1 bit decoded in isolation, asserting the exact function
// per EMV Book 3 Annex C6. The decode is a direct mask of the published table,
// so these single-bit vectors are authoritative.
func TestDecodeTSI_SingleBits(t *testing.T) {
	cases := []struct {
		hex  string
		want string
	}{
		{"8000", "Offline data authentication was performed"},
		{"4000", "Cardholder verification was performed"},
		{"2000", "Card risk management was performed"},
		{"1000", "Issuer authentication was performed"},
		{"0800", "Terminal risk management was performed"},
		{"0400", "Script processing was performed"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			tsi, err := DecodeTSIHex(c.hex)
			if err != nil {
				t.Fatalf("DecodeTSIHex(%q): %v", c.hex, err)
			}
			if tsi.NonePerformed {
				t.Errorf("%s: expected a function performed", c.hex)
			}
			if len(tsi.FunctionsPerformed) != 1 || tsi.FunctionsPerformed[0] != c.want {
				t.Errorf("%s: functions = %v, want [%q]", c.hex, tsi.FunctionsPerformed, c.want)
			}
		})
	}
}

// A realistic completed-transaction TSI: offline data auth + cardholder
// verification + card risk management + terminal risk management = 0xE8 00.
func TestDecodeTSI_RealValue(t *testing.T) {
	tsi, err := DecodeTSIHex("E800")
	if err != nil {
		t.Fatal(err)
	}
	if tsi.NonePerformed {
		t.Fatal("E800: should not be NonePerformed")
	}
	if len(tsi.FunctionsPerformed) != 4 {
		t.Errorf("E800: want 4 functions, got %d: %v", len(tsi.FunctionsPerformed), tsi.FunctionsPerformed)
	}
	if len(tsi.Notes) != 0 {
		t.Errorf("E800: expected no RFU notes, got %v", tsi.Notes)
	}
}

func TestDecodeTSI_NonePerformed(t *testing.T) {
	tsi, err := DecodeTSIHex("0000")
	if err != nil {
		t.Fatal(err)
	}
	if !tsi.NonePerformed {
		t.Errorf("0000: expected NonePerformed=true")
	}
	if len(tsi.FunctionsPerformed) != 0 {
		t.Errorf("0000: expected no functions, got %v", tsi.FunctionsPerformed)
	}
}

// Byte 1 bit 1 (0x01) is RFU; a non-zero byte 2 is RFU. Both must be noted,
// never named as a function.
func TestDecodeTSI_RFUNotes(t *testing.T) {
	tsi, err := DecodeTSIHex("0101")
	if err != nil {
		t.Fatal(err)
	}
	if len(tsi.Notes) != 2 {
		t.Errorf("0101: expected 2 RFU notes (byte1 RFU + byte2), got %v", tsi.Notes)
	}
	if len(tsi.FunctionsPerformed) != 0 {
		t.Errorf("0101: RFU bits must not be named functions, got %v", tsi.FunctionsPerformed)
	}
	if !tsi.NonePerformed {
		t.Errorf("0101: no named function set, expected NonePerformed=true")
	}
}

func TestDecodeTSI_Rejects(t *testing.T) {
	for _, bad := range []string{"", "9B", "E80000", "zz"} {
		if _, err := DecodeTSIHex(bad); err == nil {
			t.Errorf("DecodeTSIHex(%q): expected error, got nil", bad)
		}
	}
}

// A spot check that the full-byte-1 decode lists all six functions and flags
// the two RFU low bits.
func TestDecodeTSI_AllBitsByte1(t *testing.T) {
	tsi, err := DecodeTSIHex("FF00")
	if err != nil {
		t.Fatal(err)
	}
	if len(tsi.FunctionsPerformed) != 6 {
		t.Errorf("FF00: want 6 functions, got %d", len(tsi.FunctionsPerformed))
	}
	if len(tsi.Notes) != 1 || !strings.Contains(tsi.Notes[0], "RFU") {
		t.Errorf("FF00: expected one byte-1 RFU note, got %v", tsi.Notes)
	}
}
