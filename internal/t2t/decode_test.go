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

// header16 is the verified 16-byte header from validDump (UID + BCCs + CC).
var header16 = []byte{0x04, 0x11, 0x22, 0xBF, 0x33, 0x44, 0x55, 0x66, 0x44, 0x48, 0x00, 0x00, 0xE1, 0x10, 0x12, 0x00}

// ntagDump builds a `pages`-page NTAG dump with the verified header and the
// given AUTH0 / ACCESS in the last four config pages, PWD = FFFFFFFF.
func ntagDump(pages int, auth0, access byte) string {
	b := make([]byte, pages*4)
	copy(b, header16)
	base := (pages - 4) * 4
	b[base+3] = auth0  // CFG0 byte 3
	b[base+4] = access // CFG1 byte 0 (ACCESS)
	copy(b[base+8:base+12], []byte{0xFF, 0xFF, 0xFF, 0xFF})
	return toHex(b)
}

func toHex(b []byte) string {
	const h = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0x0F]
	}
	return string(out)
}

func TestDecode_NTAGConfig(t *testing.T) {
	// NTAG213 (45 pages), AUTH0=0x10, ACCESS=0x80 (PROT set -> read+write).
	d, err := Decode(ntagDump(45, 0x10, 0x80))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.Model != "NTAG213" {
		t.Errorf("model = %q, want NTAG213", d.Model)
	}
	if d.Config == nil {
		t.Fatal("config is nil")
	}
	if d.Config.AUTH0 != 0x10 {
		t.Errorf("auth0 = %d, want 16", d.Config.AUTH0)
	}
	if d.Config.ProtectMode != "read and write" {
		t.Errorf("protect mode = %q, want read and write", d.Config.ProtectMode)
	}
	if d.Config.ProtectedFrom != "pages 16 onward (read and write)" {
		t.Errorf("protected_from = %q", d.Config.ProtectedFrom)
	}
	if d.Config.PWDHex != "FFFFFFFF" {
		t.Errorf("pwd = %s", d.Config.PWDHex)
	}
}

func TestDecode_NTAGConfig_ProtectionDisabled(t *testing.T) {
	// AUTH0 = 0xFF disables protection; ACCESS=0x00 (write-only would-be).
	d, err := Decode(ntagDump(135, 0xFF, 0x00))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.Model != "NTAG215" {
		t.Errorf("model = %q, want NTAG215", d.Model)
	}
	if d.Config == nil || d.Config.ProtectMode != "write only" {
		t.Fatalf("config = %+v", d.Config)
	}
	if d.Config.ProtectedFrom[:4] != "none" {
		t.Errorf("protected_from = %q, want none...", d.Config.ProtectedFrom)
	}
}

func TestDecode_NTAGConfig_AuthLimAndCfgLock(t *testing.T) {
	// ACCESS = 0xC3 -> PROT(0x80) + CFGLCK(0x40) + AUTHLIM(0x03).
	d, err := Decode(ntagDump(231, 0x04, 0xC3))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.Model != "NTAG216" {
		t.Errorf("model = %q, want NTAG216", d.Model)
	}
	if d.Config.AuthLimit != 3 {
		t.Errorf("auth_limit = %d, want 3", d.Config.AuthLimit)
	}
	if !d.Config.ConfigLocked {
		t.Error("config_locked should be true (CFGLCK)")
	}
}

func TestDecode_NoConfigForUnknownSize(t *testing.T) {
	// A 4-page dump is not a recognised NTAG size -> no model/config.
	d, err := Decode(validDump)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.Model != "" || d.Config != nil {
		t.Errorf("unexpected model/config for non-NTAG-size dump: %q %+v", d.Model, d.Config)
	}
}
