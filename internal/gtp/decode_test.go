package gtp

import (
	"strings"
	"testing"
)

func TestDecode_BasicGPDU_IPv4(t *testing.T) {
	// Flags 0x30 = Version 1 + PT 1 + no flags. MsgType 0xFF (G-PDU).
	// Length 0x14 = 20 (inner IPv4 header), TEID 0x11223344.
	in := "30FF 0014 11223344" +
		"45000014 12340000 40110000 7F000001 7F000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 || r.ProtocolType != 1 {
		t.Errorf("version/PT: %d / %d", r.Version, r.ProtocolType)
	}
	if r.MessageTypeName != "G-PDU (user-plane data)" {
		t.Errorf("msg type: %q", r.MessageTypeName)
	}
	if r.TEID != 0x11223344 {
		t.Errorf("TEID: 0x%X", r.TEID)
	}
	if r.LengthDeclared != 20 {
		t.Errorf("length: %d", r.LengthDeclared)
	}
	if r.SequenceNumber != nil {
		t.Errorf("seq should be nil (no S flag): %+v", r.SequenceNumber)
	}
	if !strings.Contains(r.PayloadGuess, "IPv4") {
		t.Errorf("payload guess: %q", r.PayloadGuess)
	}
}

func TestDecode_WithSequenceNumber(t *testing.T) {
	// Flags 0x32 = V=1 + PT=1 + S=1. Optional block: Seq 0x1234,
	// NPDU 0x00, NextType 0x00. Then IPv4.
	in := "32FF 0018 11223344 1234 00 00" +
		"45000014 12340000 40110000 7F000001 7F000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.SequenceNumberFlag {
		t.Errorf("S flag should be set")
	}
	if r.SequenceNumber == nil || *r.SequenceNumber != 0x1234 {
		t.Errorf("seq: %+v", r.SequenceNumber)
	}
	if r.HeaderBytes != 12 {
		t.Errorf("header bytes: %d", r.HeaderBytes)
	}
}

func TestDecode_PDUSessionContainer_5G(t *testing.T) {
	// Flags 0x34 = V=1 + PT=1 + E=1. Optional block: Seq 0,
	// NPDU 0, NextType 0x85 (PDU Session Container, 5G N3/N9).
	// Ext: length 1 word (4 bytes), body 2 bytes (DL PDU + QFI 1),
	// next type 0x00. Then IPv4.
	in := "34FF 001C 11223344 0000 00 85" +
		"01 0001 00" +
		"45000014 12340000 40110000 7F000001 7F000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ExtensionHeaderFlag {
		t.Errorf("E flag should be set")
	}
	if r.NextExtensionType == nil || *r.NextExtensionType != 0x85 {
		val := uint8(0)
		if r.NextExtensionType != nil {
			val = *r.NextExtensionType
		}
		t.Errorf("next ext type: got 0x%02X", val)
	}
	if r.NextExtensionTypeName != "PDU Session Container (5G N3 / N9)" {
		t.Errorf("next ext type name: %q", r.NextExtensionTypeName)
	}
	if len(r.ExtensionHeaders) != 1 {
		t.Fatalf("expected 1 extension header, got %d", len(r.ExtensionHeaders))
	}
	eh := r.ExtensionHeaders[0]
	if eh.TypeName != "PDU Session Container (5G N3 / N9)" {
		t.Errorf("ext name: %q", eh.TypeName)
	}
	if eh.LengthBytes != 4 {
		t.Errorf("ext length bytes: %d", eh.LengthBytes)
	}
	if eh.BodyHex != "0001" {
		t.Errorf("ext body: %q", eh.BodyHex)
	}
	if eh.NextType != 0 {
		t.Errorf("ext next type: %d", eh.NextType)
	}
}

func TestDecode_EchoRequest(t *testing.T) {
	// MsgType 0x01 Echo Request, no payload, TEID 0.
	in := "30 01 0000 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageTypeName != "Echo Request" {
		t.Errorf("msg type: %q", r.MessageTypeName)
	}
}

func TestDecode_EndMarker(t *testing.T) {
	in := "30 FE 0000 11223344"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageTypeName != "End Marker" {
		t.Errorf("msg type: %q", r.MessageTypeName)
	}
	if r.TEID != 0x11223344 {
		t.Errorf("TEID: 0x%X", r.TEID)
	}
}

func TestDecode_InnerIPv6(t *testing.T) {
	// 40-byte IPv6 header inside G-PDU.
	in := "30FF 0028 11223344" +
		"60000000 0014 1140" +
		"00000000000000000000000000000001" +
		"00000000000000000000000000000002"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.PayloadGuess, "IPv6") {
		t.Errorf("payload guess: %q", r.PayloadGuess)
	}
}

func TestDecode_TwoExtensionHeaders(t *testing.T) {
	// E=1, NextType=Long PDCP (0x82), then PDU Session Container
	// (0x85), then no more (0x00).
	in := "34FF 0020 11223344 0000 00 82" +
		"01 0001 85" +
		"01 0002 00" +
		"45000014 12340000 40110000 7F000001 7F000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.ExtensionHeaders) != 2 {
		t.Fatalf("expected 2 extension headers, got %d", len(r.ExtensionHeaders))
	}
	if r.ExtensionHeaders[0].TypeName != "Long PDCP PDU Number" {
		t.Errorf("ext 0: %q", r.ExtensionHeaders[0].TypeName)
	}
	if r.ExtensionHeaders[1].TypeName != "PDU Session Container (5G N3 / N9)" {
		t.Errorf("ext 1: %q", r.ExtensionHeaders[1].TypeName)
	}
}

func TestDecode_MessageTypeTable(t *testing.T) {
	cases := map[int]string{
		0x01: "Echo Request",
		0x02: "Echo Response",
		0x1A: "Error Indication",
		0x1F: "Supported Extension Headers Notification",
		0xFE: "End Marker",
		0xFF: "G-PDU (user-plane data)",
	}
	for k, v := range cases {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(0x%02X): got %q want %q", k, got, v)
		}
	}
	if !strings.Contains(messageTypeName(0x55), "uncatalogued") {
		t.Errorf("unknown message type fallback")
	}
}

func TestDecode_ExtensionTypeTable(t *testing.T) {
	cases := map[int]string{
		0x00: "No more extension headers",
		0x84: "NR RAN Container (5G NG-U)",
		0x85: "PDU Session Container (5G N3 / N9)",
	}
	for k, v := range cases {
		if got := extensionTypeName(k); got != v {
			t.Errorf("extensionTypeName(0x%02X): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_VersionMismatchNote(t *testing.T) {
	// Version=2 (GTPv2-C) — surfaces a Note.
	in := "50FF 0000 11223344"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: %d", r.Version)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "version is 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected version note in: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"odd hex":            "30FF001",
		"short header":       "30FF",
		"optional truncated": "32FF 0010 11223344 12",
		"ext truncated":      "34FF 0010 11223344 0000 00 84 02 0001",
		"bad hex":            "ZZFF 0000 11223344",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
