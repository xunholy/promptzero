// SPDX-License-Identifier: AGPL-3.0-or-later

package iso7816

import (
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestDecodeResponseAPDU_StatusWords(t *testing.T) {
	cases := []struct {
		hexStr, wantCat string
		wantContains    string
	}{
		{"9000", "success", "normal"},
		{"6A82", "error", "file or application not found"},
		{"6982", "error", "security status not satisfied"},
		{"6983", "error", "authentication method blocked"},
		{"6110", "success", "16 (0x10) more"},
		{"6CFF", "error", "255 (0xFF) byte"},
		{"6D00", "error", "instruction"},
		{"6E00", "error", "class"},
	}
	for _, c := range cases {
		r, err := DecodeResponseAPDU(mustHex(t, c.hexStr))
		if err != nil {
			t.Fatalf("%s: %v", c.hexStr, err)
		}
		if r.Category != c.wantCat {
			t.Errorf("%s: category = %s, want %s", c.hexStr, r.Category, c.wantCat)
		}
		if !strings.Contains(r.Status, c.wantContains) {
			t.Errorf("%s: status %q does not contain %q", c.hexStr, r.Status, c.wantContains)
		}
	}
}

// TestDecodeResponseAPDU_DESFire: the 0x91XX wrapping-mode status family.
func TestDecodeResponseAPDU_DESFire(t *testing.T) {
	cases := []struct {
		hexStr, wantCat, wantContains string
	}{
		{"9100", "success", "OPERATION_OK"},
		{"91AF", "warning", "ADDITIONAL_FRAME"},
		{"91AE", "error", "AUTHENTICATION_ERROR"},
		{"919D", "error", "PERMISSION_DENIED"},
		{"91A0", "error", "APPLICATION_NOT_FOUND"},
		{"91F0", "error", "FILE_NOT_FOUND"},
	}
	for _, c := range cases {
		r, err := DecodeResponseAPDU(mustHex(t, c.hexStr))
		if err != nil {
			t.Fatalf("%s: %v", c.hexStr, err)
		}
		if r.Category != c.wantCat || !strings.Contains(r.Status, c.wantContains) {
			t.Errorf("%s = %s / %q, want %s containing %q", c.hexStr, r.Category, r.Status, c.wantCat, c.wantContains)
		}
		if !strings.Contains(r.Status, "DESFire") {
			t.Errorf("%s: status %q should be marked DESFire", c.hexStr, r.Status)
		}
	}
	// An unmapped 91XX is surfaced raw, not guessed.
	r, _ := DecodeResponseAPDU(mustHex(t, "9133"))
	if !strings.Contains(r.Status, "unmapped") || !strings.Contains(r.Status, "0x33") {
		t.Errorf("9133 should be DESFire unmapped-raw, got %q", r.Status)
	}
}

// TestDecodeResponseAPDU_PINRetries: the 63CX family — X retry attempts left.
func TestDecodeResponseAPDU_PINRetries(t *testing.T) {
	r, err := DecodeResponseAPDU(mustHex(t, "63C3"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Category != "warning" || !strings.Contains(r.Status, "3 PIN") {
		t.Errorf("63C3 = %+v, want warning with 3 retries", r)
	}
	// 63C0 = blocked (0 remaining).
	r0, _ := DecodeResponseAPDU(mustHex(t, "63C0"))
	if !strings.Contains(r0.Status, "0 PIN") {
		t.Errorf("63C0 status = %q, want 0 retries", r0.Status)
	}
}

func TestDecodeResponseAPDU_WithData(t *testing.T) {
	r, err := DecodeResponseAPDU(mustHex(t, "0102039000"))
	if err != nil {
		t.Fatal(err)
	}
	if r.DataHex != "010203" || r.SW != "9000" || !r.Success {
		t.Errorf("got data=%s sw=%s success=%v", r.DataHex, r.SW, r.Success)
	}
}

func TestDecodeResponseAPDU_Errors(t *testing.T) {
	if _, err := DecodeResponseAPDU(mustHex(t, "90")); err == nil {
		t.Error("1-byte response: expected error")
	}
}

func TestDecodeCommandAPDU_Cases(t *testing.T) {
	// Case 1: header only.
	if c, err := DecodeCommandAPDU(mustHex(t, "00A40400")); err != nil || c.Case != "1" {
		t.Errorf("case1: %v / %+v", err, c)
	}
	// Case 2S: header + Le. READ BINARY, Le=0 -> 256.
	c2, err := DecodeCommandAPDU(mustHex(t, "00B0000000"))
	if err != nil || c2.Case != "2S" || c2.Le != 256 || c2.INSName != "READ BINARY" {
		t.Errorf("case2S: %v / %+v", err, c2)
	}
	// Case 3S: SELECT by AID, Lc=7, no Le.
	c3, err := DecodeCommandAPDU(mustHex(t, "00A4040007A0000000031010"))
	if err != nil || c3.Case != "3S" || c3.Lc != 7 || c3.INSName != "SELECT" || c3.DataHex != "A0000000031010" {
		t.Errorf("case3S: %v / %+v", err, c3)
	}
	// Case 4S: SELECT + Le.
	c4, err := DecodeCommandAPDU(mustHex(t, "00A4040007A000000003101000"))
	if err != nil || c4.Case != "4S" || c4.Lc != 7 || c4.Le != 256 {
		t.Errorf("case4S: %v / %+v", err, c4)
	}
}

func TestDecodeCommandAPDU_ExtendedAndProprietary(t *testing.T) {
	// Case 3E: extended Lc=3.
	c, err := DecodeCommandAPDU(mustHex(t, "00A40400000003ABCDEF"))
	if err != nil || c.Case != "3E" || c.Lc != 3 || c.DataHex != "ABCDEF" {
		t.Errorf("case3E: %v / %+v", err, c)
	}
	// Proprietary CLA: INS name withheld.
	cp, err := DecodeCommandAPDU(mustHex(t, "80CA9F7F00"))
	if err != nil {
		t.Fatal(err)
	}
	if cp.INSName != "" {
		t.Errorf("proprietary CLA should withhold INS name, got %q", cp.INSName)
	}
	if len(cp.Notes) == 0 {
		t.Error("expected a proprietary-CLA note")
	}
}

// TestDecodeCommandAPDU_DESFire: CLA 0x90 names the INS as the DESFire command.
func TestDecodeCommandAPDU_DESFire(t *testing.T) {
	// SelectApplication: 90 5A 00 00 03 <AID> 00 (Case 4S).
	sel, err := DecodeCommandAPDU(mustHex(t, "905A00000301020300"))
	if err != nil {
		t.Fatal(err)
	}
	if sel.INSName != "DESFire: SELECT_APPLICATION" || sel.Case != "4S" || sel.DataHex != "010203" {
		t.Errorf("select = %+v", sel)
	}
	if len(sel.Notes) == 0 || !strings.Contains(sel.Notes[0], "DESFire ISO-wrapper") {
		t.Errorf("expected a DESFire-wrapper note, got %v", sel.Notes)
	}
	// GetVersion: 90 60 00 00 00 (Case 2S).
	gv, err := DecodeCommandAPDU(mustHex(t, "9060000000"))
	if err != nil || gv.INSName != "DESFire: GET_VERSION" {
		t.Errorf("getversion: %v / %+v", err, gv)
	}
	// AuthenticateAES.
	au, _ := DecodeCommandAPDU(mustHex(t, "90AA0000010000"))
	if au.INSName != "DESFire: AUTHENTICATE_AES" {
		t.Errorf("auth INS name = %q", au.INSName)
	}
	// Unmapped DESFire command code is surfaced raw (no name) but still noted.
	un, _ := DecodeCommandAPDU(mustHex(t, "90FF000000"))
	if un.INSName != "" {
		t.Errorf("unmapped DESFire cmd should have no name, got %q", un.INSName)
	}
}

func TestDecodeCommandAPDU_Errors(t *testing.T) {
	bad := []string{"00A404", "00A4040003AB"} // short header; Lc=3 but 1 data byte
	for _, s := range bad {
		if _, err := DecodeCommandAPDU(mustHex(t, s)); err == nil {
			t.Errorf("%s: expected error", s)
		}
	}
}
