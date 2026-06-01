// SPDX-License-Identifier: AGPL-3.0-or-later

package t2t

import "testing"

// validDump is a hand-built Type 2 Tag header with verified BCCs:
//
//	UID 04 11 22 33 44 55 66
//	BCC0 = 0x88^0x04^0x11^0x22 = 0xBF
//	BCC1 = 0x33^0x44^0x55^0x66 = 0x44
//	internal 0x48, lock bytes 00 00, CC = E1 10 12 00 (v1.0, 144 bytes, free/free)
const validDump = "041122BF33445566444800 00E1101200"

func TestDecode_ValidBCCs(t *testing.T) {
	d, err := Decode(validDump)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.UID != "04112233445566" {
		t.Errorf("uid = %s, want 04112233445566", d.UID)
	}
	if d.BCC0 != "BF" || !d.BCC0Valid {
		t.Errorf("bcc0 = %s valid=%v, want BF/true", d.BCC0, d.BCC0Valid)
	}
	if d.BCC1 != "44" || !d.BCC1Valid {
		t.Errorf("bcc1 = %s valid=%v, want 44/true", d.BCC1, d.BCC1Valid)
	}
	if d.Internal != "48" {
		t.Errorf("internal = %s, want 48", d.Internal)
	}
	if len(d.LockedPages) != 0 {
		t.Errorf("locked pages = %v, want none", d.LockedPages)
	}
}

func TestDecode_CapabilityContainer(t *testing.T) {
	d, _ := Decode(validDump)
	cc := d.CC
	if !cc.MagicValid {
		t.Error("CC magic should be valid (0xE1)")
	}
	if cc.Version != "1.0" {
		t.Errorf("CC version = %s, want 1.0", cc.Version)
	}
	if cc.SizeBytes != 144 {
		t.Errorf("CC size = %d, want 144", cc.SizeBytes)
	}
	if cc.ReadAccess != "granted (no security)" || cc.WriteAccess != "granted (no security)" {
		t.Errorf("CC access = %s/%s", cc.ReadAccess, cc.WriteAccess)
	}
}

func TestDecode_BCCMismatchFlagged(t *testing.T) {
	// Corrupt BCC0 (BF -> C0).
	d, err := Decode("041122C03344556644480000E1101200")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.BCC0Valid {
		t.Error("corrupted BCC0 should be invalid")
	}
	if len(d.Notes) == 0 {
		t.Error("expected a BCC-mismatch note")
	}
}

func TestDecode_StaticLocks(t *testing.T) {
	// lock bytes 08 01: lock0 bit3 -> page 3, lock1 bit0 -> page 8.
	d, err := Decode("041122BF334455664448" + "0801" + "E1101200")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := map[int]bool{3: true, 8: true}
	if len(d.LockedPages) != 2 {
		t.Fatalf("locked pages = %v, want [3 8]", d.LockedPages)
	}
	for _, p := range d.LockedPages {
		if !want[p] {
			t.Errorf("unexpected locked page %d", p)
		}
	}
}

func TestDecode_BlockLocks(t *testing.T) {
	// lock0 bit2 (0x04) -> BL CC (page 3).
	d, err := Decode("041122BF33445566444804" + "00" + "E1101200")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, bl := range d.BlockLocks {
		if bl == "BL CC (page 3)" {
			found = true
		}
	}
	if !found {
		t.Errorf("block locks = %v, want BL CC (page 3)", d.BlockLocks)
	}
}

func TestDecode_NonNDEFTag(t *testing.T) {
	// CC magic not 0xE1 (a blank / non-NDEF tag).
	d, err := Decode("041122BF334455664448000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.CC.MagicValid {
		t.Error("CC magic should be invalid for a non-NDEF tag")
	}
}

func TestDecode_Errors(t *testing.T) {
	for _, in := range []string{"", "zz", "0411"} { // empty, non-hex, < 16 bytes
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q): expected error", in)
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{validDump, "", "0411", "041122BF33445566444800 00E1101200", "FF"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}
