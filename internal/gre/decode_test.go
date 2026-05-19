package gre

import (
	"strings"
	"testing"
)

func TestDecode_BasicGRE_IPv4(t *testing.T) {
	// No optional fields; ProtocolType = IPv4.
	// Header: 00 00 08 00 (4 bytes), payload: 4 bytes.
	in := "00000800 AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Variant != "standard GRE (RFC 2784/2890)" {
		t.Errorf("variant: %q", r.Variant)
	}
	if r.Version != 0 {
		t.Errorf("version: %d", r.Version)
	}
	if r.ProtocolName != "IPv4" {
		t.Errorf("protocol: %q", r.ProtocolName)
	}
	if r.ChecksumPresent || r.KeyPresent || r.SequencePresent {
		t.Errorf("no optional fields should be set: %+v", r)
	}
	if r.HeaderBytes != 4 || r.PayloadLength != 4 {
		t.Errorf("sizes: hdr=%d pl=%d", r.HeaderBytes, r.PayloadLength)
	}
}

func TestDecode_GREWithKey(t *testing.T) {
	// K=1 → 4-byte Key field after the mandatory header.
	// Byte 0: 0x20 (K=1).
	in := "20000800 DEADBEEF AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.KeyPresent {
		t.Errorf("K should be set")
	}
	if r.Key == nil || *r.Key != 0xDEADBEEF {
		t.Errorf("key: %+v", r.Key)
	}
	if r.HeaderBytes != 8 {
		t.Errorf("header bytes: %d", r.HeaderBytes)
	}
}

func TestDecode_GREWithChecksum(t *testing.T) {
	// C=1 → 4-byte Checksum+Offset after mandatory header.
	in := "80000800 12340000 AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ChecksumPresent {
		t.Errorf("C should be set")
	}
	if r.Checksum == nil || *r.Checksum != 0x1234 {
		t.Errorf("checksum: %+v", r.Checksum)
	}
	if r.Offset == nil || *r.Offset != 0 {
		t.Errorf("offset: %+v", r.Offset)
	}
}

func TestDecode_GREWithKeyAndSequence(t *testing.T) {
	// K=1, S=1 (byte 0 = 0x30) → Key + Sequence.
	in := "30000800 DEADBEEF 00000001 AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.KeyPresent || !r.SequencePresent {
		t.Errorf("K and S should be set: %+v", r)
	}
	if r.Key == nil || *r.Key != 0xDEADBEEF {
		t.Errorf("key: %+v", r.Key)
	}
	if r.SequenceNumber == nil || *r.SequenceNumber != 1 {
		t.Errorf("seq: %+v", r.SequenceNumber)
	}
	if r.HeaderBytes != 12 {
		t.Errorf("header bytes: %d", r.HeaderBytes)
	}
}

func TestDecode_PPTPEnhancedGRE(t *testing.T) {
	// PPTP: V=1, K=1 always, optional S and A.
	// byte 0: 0x30 (K=1 S=1)
	// byte 1: 0x81 (A=1 V=1)
	// ProtocolType: 0x880B PPP
	// Key: PayloadLen=0x1234, Call ID=0x5678 → 0x12345678
	// Seq: 0x000000A0
	// Ack: 0x000000B0
	in := "3081 880B 12345678 000000A0 000000B0 AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Variant != "PPTP Enhanced GRE (RFC 2637)" {
		t.Errorf("variant: %q", r.Variant)
	}
	if r.Version != 1 {
		t.Errorf("version: %d", r.Version)
	}
	if r.ProtocolName != "PPP (PPP-in-GRE)" {
		t.Errorf("protocol: %q", r.ProtocolName)
	}
	if r.PPTPPayloadLen == nil || *r.PPTPPayloadLen != 0x1234 {
		t.Errorf("PPTP payload len: %+v", r.PPTPPayloadLen)
	}
	if r.PPTPCallID == nil || *r.PPTPCallID != 0x5678 {
		t.Errorf("PPTP Call ID: %+v", r.PPTPCallID)
	}
	if r.AckNumber == nil || *r.AckNumber != 0xB0 {
		t.Errorf("ack: %+v", r.AckNumber)
	}
}

func TestDecode_EoGRE(t *testing.T) {
	// EoGRE: ProtocolType = 0x6558 (Transparent Ethernet Bridging).
	// K=1 with VLAN-like Key for tenant separation.
	in := "20006558 00001234 AABBCCDDEEFF112233445566 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProtocolName != "Transparent Ethernet Bridging (EoGRE)" {
		t.Errorf("protocol: %q", r.ProtocolName)
	}
	if !r.KeyPresent || *r.Key != 0x00001234 {
		t.Errorf("key: %+v", r.Key)
	}
}

func TestDecode_IPv6Inner(t *testing.T) {
	in := "000086DD AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProtocolName != "IPv6" {
		t.Errorf("protocol: %q", r.ProtocolName)
	}
}

func TestDecode_AllOptionalFields(t *testing.T) {
	// C=1, K=1, S=1 → byte 0 = 0xB0.
	in := "B0000800 12340000 DEADBEEF 00000005 AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ChecksumPresent || !r.KeyPresent || !r.SequencePresent {
		t.Errorf("all optionals should be set: %+v", r)
	}
	if r.HeaderBytes != 16 {
		t.Errorf("header bytes: %d (want 16)", r.HeaderBytes)
	}
}

func TestDecode_RoutingBitDeprecatedNote(t *testing.T) {
	// R=1 (byte 0 = 0x40). Should surface a deprecation note.
	// R presence pulls 4 bytes of Checksum+Offset.
	in := "40000800 00000000 AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "deprecated") &&
			strings.Contains(n, "Routing") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected deprecated routing note in: %v", r.Notes)
	}
}

func TestProtocolNameTable(t *testing.T) {
	cases := map[int]string{
		0x0800: "IPv4",
		0x86DD: "IPv6",
		0x6558: "Transparent Ethernet Bridging (EoGRE)",
		0x880B: "PPP (PPP-in-GRE)",
		0x8847: "MPLS unicast",
		0x8848: "MPLS multicast",
		0x6559: "Raw Frame Relay",
		0x0806: "ARP",
	}
	for k, v := range cases {
		if got := protocolName(k); got != v {
			t.Errorf("protocolName(0x%04X): got %q want %q", k, got, v)
		}
	}
	if !strings.Contains(protocolName(0xFFFF), "uncatalogued") {
		t.Errorf("unknown protocol fallback")
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"odd hex":            "00000800AABBCCD",
		"short header":       "0000",
		"key truncated":      "20000800 DEAD",
		"seq truncated":      "10000800 0000",
		"checksum truncated": "80000800 1234",
		"bad hex":            "ZZ000800AABBCCDD",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
