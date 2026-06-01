// SPDX-License-Identifier: AGPL-3.0-or-later

package t2t

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestEncodeHeader_BCCVector hand-verifies the computed BCCs against the
// canonical vector shared with the decode tests.
func TestEncodeHeader_BCCVector(t *testing.T) {
	b, err := EncodeHeader(EncodeRequest{UID: "04112233445566"})
	if err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}
	// page0[3] = BCC0 = 0xBF; page2[0] = BCC1 = 0x44.
	if b[3] != 0xBF {
		t.Errorf("BCC0 = 0x%02X, want 0xBF", b[3])
	}
	if b[8] != 0x44 {
		t.Errorf("BCC1 = 0x%02X, want 0x44", b[8])
	}
	if b[9] != DefaultInternal {
		t.Errorf("internal = 0x%02X, want 0x48", b[9])
	}
}

// TestEncodeHeader_RoundTrip: Encode -> Decode recovers the UID with both
// BCCs valid, the default CC, and any supplied lock bytes.
func TestEncodeHeader_RoundTrip(t *testing.T) {
	b, err := EncodeHeader(EncodeRequest{UID: "DEADBEEF112233", Lock0: 0x08, CC: "E1101F00"})
	if err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}
	d, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.UID != "DEADBEEF112233" {
		t.Errorf("uid round-trips to %s", d.UID)
	}
	if !d.BCC0Valid || !d.BCC1Valid {
		t.Errorf("BCCs not valid: %+v", d)
	}
	if d.CC.Hex != "E1101F00" {
		t.Errorf("cc = %s, want E1101F00", d.CC.Hex)
	}
	// lock0 bit3 -> page 3 locked.
	found := false
	for _, pg := range d.LockedPages {
		if pg == 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected page 3 locked from Lock0=0x08, got %v", d.LockedPages)
	}
}

func TestEncodeHeader_DefaultCC(t *testing.T) {
	b, err := EncodeHeader(EncodeRequest{UID: "04112233445566"})
	if err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}
	if strings.ToUpper(hex.EncodeToString(b[12:16])) != "E1101200" {
		t.Errorf("default CC = %X, want E1101200", b[12:16])
	}
}

func TestEncodeHeader_ToleratesSeparators(t *testing.T) {
	a, _ := EncodeHeader(EncodeRequest{UID: "04:11:22:33:44:55:66"})
	c, _ := EncodeHeader(EncodeRequest{UID: "04112233445566"})
	if hex.EncodeToString(a) != hex.EncodeToString(c) {
		t.Errorf("separator handling diverged")
	}
}

func TestEncodeHeader_Errors(t *testing.T) {
	bad := []EncodeRequest{
		{UID: "0011"},                       // short UID
		{UID: ""},                           // empty
		{UID: "nothexnothexno"},             // non-hex
		{UID: "04112233445566", CC: "E110"}, // short CC
	}
	for i, r := range bad {
		if _, err := EncodeHeader(r); err == nil {
			t.Errorf("case %d (%+v): expected error", i, r)
		}
	}
}
