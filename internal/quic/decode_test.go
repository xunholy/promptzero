package quic

import (
	"strings"
	"testing"
)

func TestDecode_InitialPacket(t *testing.T) {
	// First byte 0xC0: long=1, fixed=1, type=0 Initial.
	// Version 0x00000001 (QUIC v1). DCID len 8, SCID len 0.
	// Token length VLI 0 (1 byte 0x00). Length VLI 4. Payload 4 bytes.
	in := "C0 00000001 08 0102030405060708 00 00 04 AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.IsLongHeader {
		t.Errorf("expected long header")
	}
	if r.LongPacketTypeName != "Initial" {
		t.Errorf("type: %q", r.LongPacketTypeName)
	}
	if r.VersionName != "QUIC v1 (RFC 9000)" {
		t.Errorf("version: %q", r.VersionName)
	}
	if r.DCIDLength != 8 || r.DCIDHex != "0102030405060708" {
		t.Errorf("DCID: len=%d hex=%q", r.DCIDLength, r.DCIDHex)
	}
	if r.SCIDLength != 0 {
		t.Errorf("SCID length: %d", r.SCIDLength)
	}
	if r.Initial == nil {
		t.Fatal("Initial body nil")
	}
	if r.Initial.TokenLength != 0 {
		t.Errorf("token length: %d", r.Initial.TokenLength)
	}
	if r.Initial.Length != 4 {
		t.Errorf("length: %d", r.Initial.Length)
	}
	if r.Initial.ProtectedPayloadLen != 4 || r.Initial.ProtectedPayloadHex != "AABBCCDD" {
		t.Errorf("payload: len=%d hex=%q",
			r.Initial.ProtectedPayloadLen, r.Initial.ProtectedPayloadHex)
	}
}

func TestDecode_ZeroRTTPacket(t *testing.T) {
	// First byte 0xD0 (type=1 0-RTT). DCID 4, SCID 4, Length VLI 10.
	in := "D0 00000001 04 AABBCCDD 04 11223344 0A FFFFFFFFFFFFFFFFFFFF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LongPacketTypeName != "0-RTT" {
		t.Errorf("type: %q", r.LongPacketTypeName)
	}
	if r.ZeroRTT == nil || r.ZeroRTT.Length != 10 {
		t.Errorf("zero_rtt: %+v", r.ZeroRTT)
	}
	if r.ZeroRTT.ProtectedPayloadLen != 10 {
		t.Errorf("payload len: %d", r.ZeroRTT.ProtectedPayloadLen)
	}
}

func TestDecode_HandshakePacket(t *testing.T) {
	// First byte 0xE0 (type=2). No DCID, no SCID, length 4.
	in := "E0 00000001 00 00 04 12345678"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LongPacketTypeName != "Handshake" {
		t.Errorf("type: %q", r.LongPacketTypeName)
	}
	if r.Handshake == nil || r.Handshake.Length != 4 {
		t.Errorf("handshake: %+v", r.Handshake)
	}
	if r.Handshake.ProtectedPayloadHex != "12345678" {
		t.Errorf("payload: %q", r.Handshake.ProtectedPayloadHex)
	}
}

func TestDecode_RetryPacket(t *testing.T) {
	// First byte 0xF0 (type=3). DCID 4, SCID 4. Token 4 bytes + 16 byte tag.
	in := "F0 00000001 04 AABBCCDD 04 11223344 DEADBEEF AABBCCDDEEFF00112233445566778899"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LongPacketTypeName != "Retry" {
		t.Errorf("type: %q", r.LongPacketTypeName)
	}
	if r.Retry == nil {
		t.Fatal("retry nil")
	}
	if r.Retry.RetryTokenLen != 4 || r.Retry.RetryTokenHex != "DEADBEEF" {
		t.Errorf("token: len=%d hex=%q", r.Retry.RetryTokenLen, r.Retry.RetryTokenHex)
	}
	if r.Retry.IntegrityTagHex != "AABBCCDDEEFF00112233445566778899" {
		t.Errorf("integrity tag: %q", r.Retry.IntegrityTagHex)
	}
}

func TestDecode_VersionNegotiation(t *testing.T) {
	// First byte high bit set (long header). Version 0. DCID 4, SCID 4,
	// then 2 supported versions.
	in := "C0 00000000 04 AABBCCDD 04 11223344 00000001 FF000022"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LongPacketTypeName != "Version Negotiation" {
		t.Errorf("type: %q", r.LongPacketTypeName)
	}
	if r.VersionNegotiation == nil {
		t.Fatal("VersionNegotiation nil")
	}
	if len(r.VersionNegotiation.SupportedVersions) != 2 {
		t.Fatalf("expected 2 versions, got %d",
			len(r.VersionNegotiation.SupportedVersions))
	}
	if r.VersionNegotiation.SupportedVersions[0] != 0x00000001 {
		t.Errorf("supported[0]: 0x%08X", r.VersionNegotiation.SupportedVersions[0])
	}
	if r.VersionNegotiation.SupportedVersions[1] != 0xFF000022 {
		t.Errorf("supported[1]: 0x%08X", r.VersionNegotiation.SupportedVersions[1])
	}
}

func TestDecode_ShortHeader_Note(t *testing.T) {
	// First byte 0x40 (short header). Should surface note, not error.
	in := "40 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.IsLongHeader {
		t.Errorf("short header detected as long")
	}
	if !strings.Contains(r.HeaderForm, "short") {
		t.Errorf("header form: %q", r.HeaderForm)
	}
	if len(r.Notes) == 0 {
		t.Errorf("expected note about short header")
	}
}

func TestDecode_VLITable(t *testing.T) {
	// Canonical Variable-Length Integer test vectors from
	// RFC 9000 §16. The same value 37 encoded in all four
	// prefix lengths, plus a non-trivial 4-byte example.
	cases := []struct {
		b        []byte
		wantVal  uint64
		wantUsed int
	}{
		{[]byte{0x25}, 37, 1},
		{[]byte{0x40, 0x25}, 37, 2},
		{[]byte{0x80, 0x00, 0x00, 0x25}, 37, 4},
		{[]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25}, 37, 8},
		{[]byte{0x9D, 0x7F, 0x3E, 0x7D}, 0x1D7F3E7D, 4},
	}
	for i, tc := range cases {
		v, used, err := readVLI(tc.b)
		if err != nil {
			t.Errorf("case %d: %v", i, err)
			continue
		}
		if v != tc.wantVal {
			t.Errorf("case %d: value got %d want %d", i, v, tc.wantVal)
		}
		if used != tc.wantUsed {
			t.Errorf("case %d: used got %d want %d", i, used, tc.wantUsed)
		}
	}
}

func TestDecode_GREASEVersion(t *testing.T) {
	// Version 0x0A0A0A0A should be flagged as GREASE.
	in := "C0 0A0A0A0A 00 00 00 04 AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.VersionName, "GREASE") {
		t.Errorf("expected GREASE, got %q", r.VersionName)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"odd hex":          "C00",
		"truncated header": "C0 00",
		"dcid too long":    "C0 00000001 15 " + strings.Repeat("00", 21),
		"bad hex":          "ZZ 00000001 00 00",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
