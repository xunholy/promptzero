// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthn

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// build assembles an authData byte string from parts for the tests.
func build(rpHash []byte, flags byte, counter uint32, tail []byte) []byte {
	var b bytes.Buffer
	b.Write(rpHash) // caller passes 32 bytes
	b.WriteByte(flags)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], counter)
	b.Write(c[:])
	b.Write(tail)
	return b.Bytes()
}

func hash32(fill byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = fill
	}
	return h
}

// TestDecode_NoAttestedNoExt covers the assertion case: fixed prefix only.
func TestDecode_NoAttestedNoExt(t *testing.T) {
	ad, err := Decode(build(hash32(0xAB), 0x01|0x04, 42, nil)) // UP|UV
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !ad.Flags.UserPresent || !ad.Flags.UserVerified {
		t.Errorf("flags = %+v, want UP+UV", ad.Flags)
	}
	if ad.Flags.AttestedCredentialData || ad.Flags.ExtensionData {
		t.Errorf("AT/ED should be unset: %+v", ad.Flags)
	}
	if ad.SignCount != 42 {
		t.Errorf("sign count = %d, want 42", ad.SignCount)
	}
	if ad.RPIDHashHex != strings.Repeat("ab", 32) {
		t.Errorf("rp hash = %q", ad.RPIDHashHex)
	}
	if ad.AAGUID != "" || ad.CredentialIDHex != "" {
		t.Errorf("no attested data expected, got aaguid=%q credid=%q", ad.AAGUID, ad.CredentialIDHex)
	}
}

// TestDecode_AttestedCredential covers registration: AAGUID + cred ID + COSE key.
func TestDecode_AttestedCredential(t *testing.T) {
	aaguid := make([]byte, 16)
	for i := range aaguid {
		aaguid[i] = byte(i)
	}
	credID := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	coseKey := []byte{0xA1, 0x01, 0x02} // CBOR map {1:2} — 3 bytes

	var tail bytes.Buffer
	tail.Write(aaguid)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
	tail.Write(l[:])
	tail.Write(credID)
	tail.Write(coseKey)

	ad, err := Decode(build(hash32(0x11), 0x01|0x40, 7, tail.Bytes())) // UP|AT
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !ad.Flags.AttestedCredentialData {
		t.Fatal("AT flag should be set")
	}
	if ad.AAGUID != "00010203-0405-0607-0809-0a0b0c0d0e0f" {
		t.Errorf("aaguid = %q", ad.AAGUID)
	}
	if ad.CredentialIDLen != 4 || ad.CredentialIDHex != "deadbeef" {
		t.Errorf("cred id = %d/%q", ad.CredentialIDLen, ad.CredentialIDHex)
	}
	if ad.CredentialKeyLen != 3 || ad.CredentialKeyHex != "a10102" {
		t.Errorf("cose key = %d/%q, want 3/a10102", ad.CredentialKeyLen, ad.CredentialKeyHex)
	}
}

// TestDecode_AttestedPlusExtensions is the hard case: the COSE key and the
// extensions are both CBOR; the scanner must split them at the right byte.
func TestDecode_AttestedPlusExtensions(t *testing.T) {
	aaguid := make([]byte, 16)
	credID := []byte{0x01, 0x02}
	coseKey := []byte{0xA1, 0x01, 0x02} // 3-byte map
	exts := []byte{0xA0}                // empty CBOR map, 1 byte

	var tail bytes.Buffer
	tail.Write(aaguid)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
	tail.Write(l[:])
	tail.Write(credID)
	tail.Write(coseKey)
	tail.Write(exts)

	ad, err := Decode(build(hash32(0x22), 0x40|0x80, 0, tail.Bytes())) // AT|ED
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if ad.CredentialKeyHex != "a10102" {
		t.Errorf("cose key = %q, want a10102 (extensions must not be folded in)", ad.CredentialKeyHex)
	}
	if ad.ExtensionsHex != "a0" {
		t.Errorf("extensions = %q, want a0", ad.ExtensionsHex)
	}
}

func TestDecode_Errors(t *testing.T) {
	aaguid := make([]byte, 16)
	cases := []struct {
		name string
		data []byte
	}{
		{"too short", make([]byte, 36)},
		{"AT truncated header", build(hash32(0), 0x40, 0, aaguid[:8])},
		{"cred id len overruns", func() []byte {
			var tl bytes.Buffer
			tl.Write(aaguid)
			tl.Write([]byte{0xFF, 0xFF}) // claim 65535-byte cred ID
			return build(hash32(0), 0x40, 0, tl.Bytes())
		}()},
		{"ED set no bytes", build(hash32(0), 0x80, 0, nil)},
		{"trailing bytes (no AT/ED)", build(hash32(0), 0x01, 0, []byte{0xFF})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Decode(c.data); err == nil {
				t.Errorf("expected error for %s", c.name)
			}
		})
	}
}
