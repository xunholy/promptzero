// SPDX-License-Identifier: AGPL-3.0-or-later

package wsc

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// tlv builds a (type:2-BE, length:2-BE, value) WSC attribute.
func tlv(typ uint16, val []byte) []byte {
	b := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(b[0:], typ)
	binary.BigEndian.PutUint16(b[2:], uint16(len(val)))
	copy(b[4:], val)
	return b
}

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func buildCredentialBlob() []byte {
	inner := tlv(attrSSID, []byte("MyNetwork"))
	inner = append(inner, tlv(attrAuthType, u16(0x0020))...) // WPA2-PSK
	inner = append(inner, tlv(attrEncrType, u16(0x0008))...) // AES
	inner = append(inner, tlv(attrNetworkKey, []byte("Sup3rSecret!"))...)
	inner = append(inner, tlv(attrMACAddr, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})...)
	return tlv(attrCredential, inner)
}

func TestDecodeCredential(t *testing.T) {
	blob := buildCredentialBlob()
	res, err := Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Credentials) != 1 {
		t.Fatalf("want 1 credential, got %d", len(res.Credentials))
	}
	c := res.Credentials[0]
	if c.SSID != "MyNetwork" {
		t.Errorf("SSID = %q", c.SSID)
	}
	if c.NetworkKey != "Sup3rSecret!" {
		t.Errorf("NetworkKey = %q", c.NetworkKey)
	}
	if c.AuthTypeRaw != 0x0020 || len(c.AuthType) != 1 || c.AuthType[0] != "WPA2-PSK" {
		t.Errorf("AuthType = %v (raw 0x%04X)", c.AuthType, c.AuthTypeRaw)
	}
	if c.EncrTypeRaw != 0x0008 || len(c.EncrType) != 1 || c.EncrType[0] != "AES" {
		t.Errorf("EncrType = %v (raw 0x%04X)", c.EncrType, c.EncrTypeRaw)
	}
	if c.MACAddress != "00:11:22:33:44:55" {
		t.Errorf("MAC = %q", c.MACAddress)
	}
}

func TestDecodeHexRoundTrip(t *testing.T) {
	blob := buildCredentialBlob()
	res, err := DecodeHex(hex.EncodeToString(blob))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Credentials) != 1 || res.Credentials[0].SSID != "MyNetwork" {
		t.Errorf("hex round-trip mismatch: %+v", res)
	}
	// Separators must be tolerated.
	res2, err := DecodeHex("10:0e-00 04 10 45 00 00")
	if err != nil {
		t.Fatalf("separators should be tolerated: %v", err)
	}
	if len(res2.Credentials) != 1 {
		t.Errorf("want 1 credential from empty-SSID cred, got %d", len(res2.Credentials))
	}
}

func TestDecodeMixedAuthFlags(t *testing.T) {
	// 0x0022 = WPA2-PSK | WPA-PSK (mixed-mode), a real-world value.
	inner := tlv(attrAuthType, u16(0x0022))
	res, err := Decode(tlv(attrCredential, inner))
	if err != nil {
		t.Fatal(err)
	}
	got := res.Credentials[0].AuthType
	if len(got) != 2 {
		t.Fatalf("mixed auth should decode 2 flags, got %v", got)
	}
	if got[0] != "WPA-PSK" || got[1] != "WPA2-PSK" {
		t.Errorf("mixed auth flags = %v", got)
	}
}

func TestDecodeUnknownFlagBit(t *testing.T) {
	// 0x8000 is outside the documented WPS_AUTH_* set — must be surfaced,
	// never dropped.
	res, _ := Decode(tlv(attrCredential, tlv(attrAuthType, u16(0x8001))))
	got := res.Credentials[0].AuthType
	if len(got) != 2 || got[0] != "Open" || got[1] != "unknown(0x8000)" {
		t.Errorf("unknown auth bit handling: %v", got)
	}
}

func TestTopLevelNonCredential(t *testing.T) {
	// A Version attribute alongside no credential.
	blob := tlv(attrVersion, []byte{0x10})
	res, err := Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Credentials) != 0 || len(res.OtherAttrs) != 1 {
		t.Fatalf("want 0 creds + 1 other attr, got %+v", res)
	}
}

func TestEncryptedSettingsNoted(t *testing.T) {
	res, err := Decode(tlv(attrEncrSettings, []byte{0xAA, 0xBB, 0xCC, 0xDD}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.OtherAttrs) != 1 || res.OtherAttrs[0].Type == "0x1018" {
		t.Errorf("encrypted-settings should carry an explanatory note: %+v", res.OtherAttrs)
	}
}

func TestTruncatedTLVStops(t *testing.T) {
	// type=0x1045, length=0x00FF but only 2 value bytes present.
	blob := []byte{0x10, 0x45, 0x00, 0xFF, 0xAA, 0xBB}
	res, err := Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	// Truncated attribute is dropped (length runs past buffer), no panic.
	if len(res.Credentials) != 0 {
		t.Errorf("truncated TLV should yield no credential: %+v", res)
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := Decode([]byte{0x10, 0x45}); err == nil {
		t.Error("sub-4-byte blob should error")
	}
	if _, err := DecodeHex(""); err == nil {
		t.Error("empty hex should error")
	}
	if _, err := DecodeHex("zzzz"); err == nil {
		t.Error("non-hex should error")
	}
}
