package ipsec

import (
	"strings"
	"testing"
)

func TestDecodeESP_Basic(t *testing.T) {
	// SPI=0xCAFEBABE, Seq=1, 16 bytes of opaque encrypted
	// payload.
	in := "CAFEBABE 00000001 0102030405060708 090A0B0C0D0E0F10"
	r, err := DecodeESP(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("DecodeESP: %v", err)
	}
	if r.SPI != 0xCAFEBABE {
		t.Errorf("SPI: 0x%08X", r.SPI)
	}
	if r.SequenceNumber != 1 {
		t.Errorf("sequence: %d", r.SequenceNumber)
	}
	if r.EncryptedBytes != 16 {
		t.Errorf("encrypted bytes: %d", r.EncryptedBytes)
	}
	if r.EncryptedHex != "0102030405060708090A0B0C0D0E0F10" {
		t.Errorf("encrypted hex: %q", r.EncryptedHex)
	}
}

func TestDecodeESP_SPIReservedNote(t *testing.T) {
	// SPI=0 — reserved for local use.
	in := "00000000 00000001"
	r, err := DecodeESP(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("DecodeESP: %v", err)
	}
	if !strings.Contains(r.SPINote, "reserved for local use") {
		t.Errorf("expected reserved-for-local-use note, got %q", r.SPINote)
	}
	// SPI=42 — IANA-reserved.
	in = "0000002A 00000001"
	r, err = DecodeESP(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("DecodeESP: %v", err)
	}
	if !strings.Contains(r.SPINote, "IANA-reserved") {
		t.Errorf("expected IANA-reserved note, got %q", r.SPINote)
	}
}

func TestDecodeESP_PayloadCap(t *testing.T) {
	// 100-byte payload, capped to 32.
	in := "CAFEBABE 00000001 " + strings.Repeat("AA", 100)
	r, err := DecodeESP(in, DecodeOpts{MaxPayloadBytes: 32})
	if err != nil {
		t.Fatalf("DecodeESP: %v", err)
	}
	if r.EncryptedBytes != 100 {
		t.Errorf("encrypted bytes: %d", r.EncryptedBytes)
	}
	if r.EncryptedBytesShown != 32 {
		t.Errorf("bytes shown: %d", r.EncryptedBytesShown)
	}
}

func TestDecodeAH_HMACSHA1(t *testing.T) {
	// Typical AH with HMAC-SHA1-96 ICV (12 bytes).
	// Payload Length = 4 → total header = 24 bytes
	// (12 fixed + 12 ICV).
	// Next Header=6 (TCP), Reserved=0, SPI=0xCAFEBABE,
	// Seq=1, ICV=12 bytes.
	in := "06 04 0000 CAFEBABE 00000001 0102030405060708090A0B0C"
	r, err := DecodeAH(in)
	if err != nil {
		t.Fatalf("DecodeAH: %v", err)
	}
	if r.NextHeader != 6 {
		t.Errorf("next header: %d", r.NextHeader)
	}
	if r.NextHeaderName != "TCP" {
		t.Errorf("next header name: %q", r.NextHeaderName)
	}
	if r.PayloadLengthField != 4 {
		t.Errorf("payload length field: %d", r.PayloadLengthField)
	}
	if r.HeaderTotalBytes != 24 {
		t.Errorf("header total: %d", r.HeaderTotalBytes)
	}
	if r.ICVBytes != 12 {
		t.Errorf("ICV bytes: %d", r.ICVBytes)
	}
	if r.SPI != 0xCAFEBABE {
		t.Errorf("SPI: 0x%08X", r.SPI)
	}
	if r.ICVHex != "0102030405060708090A0B0C" {
		t.Errorf("ICV: %q", r.ICVHex)
	}
}

func TestDecodeAH_HMACSHA256(t *testing.T) {
	// AH with HMAC-SHA-256-128 ICV (16 bytes).
	// Payload Length = 5 → total = 28 bytes (12 + 16).
	in := "11 05 0000 CAFEBABE 00000064 0102030405060708 090A0B0C0D0E0F10"
	r, err := DecodeAH(in)
	if err != nil {
		t.Fatalf("DecodeAH: %v", err)
	}
	if r.NextHeader != 17 {
		t.Errorf("next header: %d", r.NextHeader)
	}
	if r.NextHeaderName != "UDP" {
		t.Errorf("next header name: %q", r.NextHeaderName)
	}
	if r.ICVBytes != 16 {
		t.Errorf("ICV bytes: %d", r.ICVBytes)
	}
	if r.SequenceNumber != 100 {
		t.Errorf("sequence: %d", r.SequenceNumber)
	}
}

func TestDecodeAH_ReservedNonZero_Note(t *testing.T) {
	// Reserved field non-zero — should surface a note.
	in := "06 04 ABCD CAFEBABE 00000001 0102030405060708090A0B0C"
	r, err := DecodeAH(in)
	if err != nil {
		t.Fatalf("DecodeAH: %v", err)
	}
	if r.Reserved == 0 {
		t.Fatalf("expected non-zero Reserved")
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "Reserved field") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Reserved note: %v", r.Notes)
	}
}

func TestDecodeAH_TunnelModeIPv4(t *testing.T) {
	// Next Header = 4 (IPv4 — tunnel mode inner).
	in := "04 04 0000 CAFEBABE 00000001 0102030405060708090A0B0C"
	r, err := DecodeAH(in)
	if err != nil {
		t.Fatalf("DecodeAH: %v", err)
	}
	if r.NextHeaderName != "IPv4 (tunnel mode inner header)" {
		t.Errorf("next header name: %q", r.NextHeaderName)
	}
}

func TestDecodeAH_TruncatedICV_Note(t *testing.T) {
	// PayloadLength=10 (header total = 48; ICV = 36) but
	// we only provide 12 bytes fixed + 4 bytes ICV.
	in := "06 0A 0000 CAFEBABE 00000001 01020304"
	r, err := DecodeAH(in)
	if err != nil {
		t.Fatalf("DecodeAH: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "declares") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected truncation note: %v", r.Notes)
	}
}

func TestDecodeAH_NextHeaderNameTable(t *testing.T) {
	cases := map[int]string{
		1:   "ICMP",
		2:   "IGMP",
		4:   "IPv4 (tunnel mode inner header)",
		6:   "TCP",
		17:  "UDP",
		41:  "IPv6 (tunnel mode inner header)",
		47:  "GRE",
		50:  "ESP (chained IPsec)",
		51:  "AH (chained IPsec)",
		58:  "ICMPv6",
		89:  "OSPF",
		132: "SCTP",
	}
	for k, v := range cases {
		if got := nextHeaderName(k); got != v {
			t.Errorf("nextHeaderName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecodeESP_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "CAFE BAB",
		"short":   "CAFE BABE",
		"bad hex": "ZZFE BABE 00000001",
	}
	for name, in := range cases {
		_, err := DecodeESP(in, DefaultDecodeOpts())
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestDecodeAH_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "06 04 000",
		"short":   "06 04 0000 CAFE",
		"bad hex": "ZZ 04 0000 CAFEBABE 00000001",
	}
	for name, in := range cases {
		_, err := DecodeAH(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
