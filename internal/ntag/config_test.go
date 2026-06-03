// SPDX-License-Identifier: AGPL-3.0-or-later

package ntag

import "testing"

// Factory-default config: MIRROR=0x04 (no mirror, STRG_MOD_EN=1), AUTH0=0xFF,
// ACCESS=0x00 (write-only, no lock, AUTHLIM 0).
func TestDecode_FactoryDefault(t *testing.T) {
	c, err := DecodeHex("04 00 00 FF 00 00 00 00")
	if err != nil {
		t.Fatal(err)
	}
	if c.MirrorConfRaw != 0 || c.MirrorConf != "no ASCII mirror" {
		t.Errorf("mirror = %d (%s)", c.MirrorConfRaw, c.MirrorConf)
	}
	if !c.StrongModulation {
		t.Errorf("STRG_MOD_EN should be set (default)")
	}
	if c.Auth0 != 0xFF {
		t.Errorf("auth0 = %d, want 255", c.Auth0)
	}
	if c.Protection != "write-only (PROT=0)" {
		t.Errorf("protection = %q", c.Protection)
	}
	if c.ConfigLocked || c.NFCCounterEnabled || c.AuthLimit != 0 {
		t.Errorf("flags should be clear: %+v", c)
	}
}

// Protected config: AUTH0=0x04, ACCESS=0x80 (PROT=1, read+write protected).
// ACCESS=0x80 -> PROT is the anchor from the NXP datasheet / community docs.
func TestDecode_ReadWriteProtected(t *testing.T) {
	c, err := DecodeHex("00000004 80000000")
	if err != nil {
		t.Fatal(err)
	}
	if c.Protection != "read+write (PROT=1)" {
		t.Errorf("protection = %q, want read+write", c.Protection)
	}
	if c.Auth0 != 4 {
		t.Errorf("auth0 = %d, want 4", c.Auth0)
	}
}

// ACCESS=0x1A -> NFC_CNT_EN(bit4)=1, NFC_CNT_PWD_PROT(bit3)=1, AUTHLIM(2-0)=2.
func TestDecode_AccessFields(t *testing.T) {
	c, err := DecodeHex("00000000 1A000000")
	if err != nil {
		t.Fatal(err)
	}
	if !c.NFCCounterEnabled {
		t.Errorf("NFC_CNT_EN should be set")
	}
	if !c.NFCCounterPwdProtected {
		t.Errorf("NFC_CNT_PWD_PROT should be set")
	}
	if c.AuthLimit != 2 {
		t.Errorf("authlim = %d, want 2", c.AuthLimit)
	}
}

// CFGLCK (bit6) + a UID mirror (MIRROR_CONF=01 -> MIRROR byte 0x40).
func TestDecode_CfgLockAndMirror(t *testing.T) {
	c, err := DecodeHex("40 00 05 10 40 00 00 00")
	if err != nil {
		t.Fatal(err)
	}
	if c.MirrorConfRaw != 1 || c.MirrorConf != "UID ASCII mirror" {
		t.Errorf("mirror conf = %d (%s)", c.MirrorConfRaw, c.MirrorConf)
	}
	if c.MirrorPage != 5 {
		t.Errorf("mirror page = %d, want 5", c.MirrorPage)
	}
	if c.StrongModulation {
		t.Errorf("STRG_MOD_EN should be clear (MIRROR byte 0x40)")
	}
	if !c.ConfigLocked {
		t.Errorf("CFGLCK should be set (ACCESS 0x40)")
	}
}

func TestDecode_WithPwdPack(t *testing.T) {
	c, err := DecodeHex("04 00 00 FF 00 00 00 00 FFFFFFFF 0000 0000")
	if err != nil {
		t.Fatal(err)
	}
	if c.Password != "FFFFFFFF" {
		t.Errorf("password = %q", c.Password)
	}
	if c.PACK != "0000" {
		t.Errorf("pack = %q", c.PACK)
	}
}

func TestDecode_Errors(t *testing.T) {
	if _, err := DecodeHex("0011"); err == nil {
		t.Error("non-8/16-byte input should error")
	}
	if _, err := DecodeHex(""); err == nil {
		t.Error("empty should error")
	}
	if _, err := DecodeHex("zz"); err == nil {
		t.Error("non-hex should error")
	}
}
