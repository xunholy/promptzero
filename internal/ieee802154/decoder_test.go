package ieee802154

import (
	"strings"
	"testing"
)

// TestDecode_AckFrame parses a minimum-size Acknowledgment frame
// — 3 bytes with no FCS, or 5 bytes with FCS. The 2-byte Frame
// Control is 0x0200 (FrameType=2 Ack, all other flags clear),
// then 1-byte sequence number.
func TestDecode_AckFrame(t *testing.T) {
	got, err := Decode("02 00 7B")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.FrameTypeName != "Acknowledgment" {
		t.Errorf("FrameType = %q", got.FrameControl.FrameTypeName)
	}
	if got.SequenceNumber == nil || *got.SequenceNumber != 0x7B {
		t.Errorf("SequenceNumber = %v; want 0x7B", got.SequenceNumber)
	}
	if got.Destination != nil || got.Source != nil {
		t.Errorf("Ack frame should have no addressing: dest=%v src=%v",
			got.Destination, got.Source)
	}
}

// TestDecode_DataFrame_ShortAddresses pins a Data frame with
// short (16-bit) destination + source addresses.
//
// Wire bytes:
//
//	FC = 0x8841 little-endian-on-wire:
//	  bytes 0,1 = 41 88
//	  fc = 0x8841
//	  bits 0-2 = 1 (Data)
//	  bit 6 = 1 (PAN ID Compression)
//	  bits 10-11 = 2 (Dest = Short)
//	  bits 12-13 = 1 (Frame Version = 2006)
//	  bits 14-15 = 2 (Source = Short)
//	Sequence = 0x42
//	Dest PAN = 0xCAFE → wire 'FE CA'
//	Dest Addr = 0xBABE → wire 'BE BA'
//	Source Addr = 0xDEAD → wire 'AD DE' (no source PAN due to compression)
//	Payload = 'DEADBEEF'
func TestDecode_DataFrame_ShortAddresses(t *testing.T) {
	got, err := Decode("41 88 42 FE CA BE BA AD DE DEADBEEF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.FrameTypeName != "Data" {
		t.Errorf("FrameType = %q", got.FrameControl.FrameTypeName)
	}
	if !got.FrameControl.PANIDCompression {
		t.Error("PANIDCompression should be true")
	}
	if got.FrameControl.DestinationAddrModeName != "Short (16-bit)" ||
		got.FrameControl.SourceAddrModeName != "Short (16-bit)" {
		t.Errorf("addressing modes wrong: dest=%q src=%q",
			got.FrameControl.DestinationAddrModeName,
			got.FrameControl.SourceAddrModeName)
	}
	if *got.SequenceNumber != 0x42 {
		t.Errorf("SequenceNumber = 0x%X; want 0x42", *got.SequenceNumber)
	}
	if got.Destination == nil {
		t.Fatal("Destination is nil")
	}
	if got.Destination.PANID != "CAFE" {
		t.Errorf("Dest PAN = %q; want 'CAFE'", got.Destination.PANID)
	}
	if got.Destination.Short != "BABE" {
		t.Errorf("Dest Short = %q; want 'BABE'", got.Destination.Short)
	}
	if got.Source == nil {
		t.Fatal("Source is nil")
	}
	if got.Source.Short != "DEAD" {
		t.Errorf("Source Short = %q; want 'DEAD'", got.Source.Short)
	}
	// When PAN ID compressed, source borrows destination's PAN.
	if got.Source.PANID != "CAFE" {
		t.Errorf("Source PAN should mirror dest under compression; got %q",
			got.Source.PANID)
	}
	if got.PayloadHex != "DEADBEEF" {
		t.Errorf("PayloadHex = %q; want 'DEADBEEF'", got.PayloadHex)
	}
}

// TestDecode_DataFrame_ExtendedSource exercises the 64-bit EUI
// extended addressing mode with little-endian-on-wire rendering
// flipped to big-endian for display.
func TestDecode_DataFrame_ExtendedSource(t *testing.T) {
	// FC: Data (1), no compression, dest=Short, src=Extended,
	// frame ver 2006. fc bits: ft=1, destMode=2 (bits 10-11),
	// ver=1 (bits 12-13), srcMode=3 (bits 14-15).
	// = (3<<14) | (1<<12) | (2<<10) | 1
	// = 0xC000 | 0x1000 | 0x0800 | 0x0001 = 0xD801
	// Wire LE: 01 D8.
	// Sequence: 0x10
	// Dest PAN = 0x1234 → wire 34 12
	// Dest Addr (Short) = 0xABCD → wire CD AB
	// Source PAN = 0xBEEF → wire EF BE
	// Source Addr (Extended) wire: 08 07 06 05 04 03 02 01
	//   → render BE "0102030405060708"
	got, err := Decode("01 D8 10 34 12 CD AB EF BE 0807060504030201 AA BB")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Destination.PANID != "1234" {
		t.Errorf("Dest PAN = %q", got.Destination.PANID)
	}
	if got.Destination.Short != "ABCD" {
		t.Errorf("Dest Short = %q", got.Destination.Short)
	}
	if got.Source == nil {
		t.Fatal("Source nil")
	}
	if got.Source.PANID != "BEEF" {
		t.Errorf("Source PAN = %q; want 'BEEF'", got.Source.PANID)
	}
	if got.Source.Extended != "0102030405060708" {
		t.Errorf("Source Extended = %q; want '0102030405060708' (LE→BE)",
			got.Source.Extended)
	}
	if got.PayloadHex != "AABB" {
		t.Errorf("PayloadHex = %q", got.PayloadHex)
	}
}

// TestDecode_BeaconFrame parses a beacon frame (FrameType=0).
// Beacon: no destination address, source has Short + PAN.
func TestDecode_BeaconFrame(t *testing.T) {
	// FC: ft=0 (beacon), srcMode=2 (short). srcMode bits 14-15.
	// fc = (2<<14) | 0 = 0x8000. Wire LE: 00 80.
	// Sequence: 0x01
	// Source PAN = 0x1A2B → wire 2B 1A
	// Source Addr = 0x9999 → wire 99 99
	// Payload: superframe spec + GTS + pending + payload (we'll
	// just put a few bytes).
	got, err := Decode("00 80 01 2B 1A 99 99 FFFF00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.FrameTypeName != "Beacon" {
		t.Errorf("FrameType = %q", got.FrameControl.FrameTypeName)
	}
	if got.Destination != nil {
		t.Errorf("Beacon should have no destination; got %+v", got.Destination)
	}
	if got.Source == nil {
		t.Fatal("Source nil")
	}
	if got.Source.PANID != "1A2B" {
		t.Errorf("Source PAN = %q", got.Source.PANID)
	}
	if got.Source.Short != "9999" {
		t.Errorf("Source Short = %q", got.Source.Short)
	}
}

// TestDecode_WithFCS exercises the IncludeFCS option — the
// trailing 2 bytes are surfaced as FCSHex rather than payload.
func TestDecode_WithFCS(t *testing.T) {
	// Take the ACK frame above and append a 2-byte FCS.
	got, err := DecodeWithOptions("02 00 7B AB CD", DecodeOptions{IncludeFCS: true})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.FCSIncluded {
		t.Error("FCSIncluded should be true")
	}
	if got.FCSHex != "ABCD" {
		t.Errorf("FCSHex = %q; want 'ABCD'", got.FCSHex)
	}
}

// TestDecode_TruncatedFrame — empty / too-short.
func TestDecode_TruncatedFrame(t *testing.T) {
	if _, err := Decode("01"); err == nil {
		t.Error("want error for 1-byte input")
	}
	if _, err := Decode(""); err == nil {
		t.Error("want error for empty input")
	}
}

// TestDecode_TruncatedAddressing — frame declares short
// destination address but the bytes aren't there.
func TestDecode_TruncatedAddressing(t *testing.T) {
	// FC = 0x0840 (dest=Short, all else zero), seq = 0x01,
	// nothing follows. Should fail when reading PAN ID.
	_, err := Decode("40 08 01")
	if err == nil {
		t.Fatal("want error for missing dest PAN")
	}
}

// TestDecode_ReservedAddressMode rejects mode 1 explicitly.
func TestDecode_ReservedAddressMode(t *testing.T) {
	// FC: destMode = 1 (reserved). bits 10-11 = 01 → fc 0x0400.
	_, err := Decode("00 04 01")
	if err == nil {
		t.Fatal("want error for reserved address mode")
	}
	if !strings.Contains(err.Error(), "Reserved") {
		t.Errorf("err = %v; want 'Reserved' wording", err)
	}
}

// TestDecode_BadInput — empty / invalid hex.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode("ZZZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_ToleratesSeparators — ':' '-' '_' whitespace.
func TestDecode_ToleratesSeparators(t *testing.T) {
	for _, in := range []string{
		"41:88:42:FE:CA:BE:BA:AD:DE:DE:AD:BE:EF",
		"41-88-42-FE-CA-BE-BA-AD-DE-DE-AD-BE-EF",
		"  41 88 42 FE CA BE BA AD DE DE AD BE EF  ",
	} {
		got, err := Decode(in)
		if err != nil {
			t.Errorf("Decode(%q): %v", in, err)
			continue
		}
		if got.Destination == nil || got.Destination.Short != "BABE" {
			t.Errorf("Decode(%q): Destination = %v", in, got.Destination)
		}
	}
}

// TestDecode_FrameVersionNames pins the version-name table.
func TestDecode_FrameVersionNames(t *testing.T) {
	cases := map[int]string{
		0: "802.15.4-2003",
		1: "802.15.4-2006",
		2: "802.15.4-2015",
		3: "Reserved",
	}
	for v, want := range cases {
		if got := frameVersionName(v); got != want {
			t.Errorf("frameVersionName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestFrameTypeNames pins the frame-type name table.
func TestFrameTypeNames(t *testing.T) {
	cases := map[FrameType]string{
		FrameTypeBeacon:       "Beacon",
		FrameTypeData:         "Data",
		FrameTypeAck:          "Acknowledgment",
		FrameTypeMACCommand:   "MAC Command",
		FrameTypeMultipurpose: "Multipurpose",
		FrameTypeFragment:     "Fragment",
		FrameTypeExtended:     "Extended",
		FrameTypeReserved:     "Reserved",
	}
	for v, want := range cases {
		if got := v.String(); got != want {
			t.Errorf("FrameType(%d).String() = %q; want %q", v, got, want)
		}
	}
}

// TestAddressingModeNames pins the addressing-mode name table.
func TestAddressingModeNames(t *testing.T) {
	cases := map[AddressingMode]string{
		AddrModeNone:     "None",
		AddrModeShort:    "Short (16-bit)",
		AddrModeExtended: "Extended (64-bit)",
		AddrModeReserved: "Reserved",
	}
	for v, want := range cases {
		if got := v.String(); got != want {
			t.Errorf("AddressingMode(%d).String() = %q; want %q", v, got, want)
		}
	}
}

// TestSecurityHeaderLen spot-checks the per-KeyIdMode lengths.
func TestSecurityHeaderLen(t *testing.T) {
	// KeyIdMode 0 (implicit key): 1 + 4 + 0 = 5
	if got := securityHeaderLen(0x00); got != 5 {
		t.Errorf("KeyIdMode=0: %d; want 5", got)
	}
	// KeyIdMode 1 (1-byte index): 1 + 4 + 1 = 6
	if got := securityHeaderLen(0x08); got != 6 {
		t.Errorf("KeyIdMode=1: %d; want 6", got)
	}
	// KeyIdMode 2 (4-byte source + 1 idx): 1 + 4 + 5 = 10
	if got := securityHeaderLen(0x10); got != 10 {
		t.Errorf("KeyIdMode=2: %d; want 10", got)
	}
	// KeyIdMode 3 (8-byte source + 1 idx): 1 + 4 + 9 = 14
	if got := securityHeaderLen(0x18); got != 14 {
		t.Errorf("KeyIdMode=3: %d; want 14", got)
	}
}
