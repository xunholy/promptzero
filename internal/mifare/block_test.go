package mifare

import (
	"strings"
	"testing"
)

// TestDecodeBlock_DefaultTrailer pins the canonical "factory
// transport" trailer:
//
//	Key A = FFFFFFFFFFFF
//	Access bytes = FF 07 80  (data blocks 0-2 = transport,
//	  trailer = transport)
//	GPB = 69
//	Key B = FFFFFFFFFFFF
//
// This is the trailer every blank Mifare Classic 1K ships with.
// Access bytes 0xFF 0x07 0x80 decode to all blocks at access
// condition C1=0 C2=0 C3=0 (read/write/inc/dec with A|B), and
// trailer at C1=0 C2=0 C3=1 (Key A can write Key A, etc.).
// Wait — let me re-check: 0xFF 0x07 0x80 is the canonical
// transport which actually decodes to data blocks C1C2C3=000 and
// trailer C1C2C3=001 per AN10833 §6.6 (the test below confirms).
func TestDecodeBlock_DefaultTrailer(t *testing.T) {
	got, err := DecodeBlock("FFFFFFFFFFFF FF0780 69 FFFFFFFFFFFF", 3)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if got.Kind != KindTrailer {
		t.Fatalf("Kind = %q; want 'sector_trailer'", got.Kind)
	}
	if got.Trailer == nil {
		t.Fatal("Trailer field is nil")
	}
	if got.Trailer.KeyAHex != "FFFFFFFFFFFF" {
		t.Errorf("KeyAHex = %q; want all-F", got.Trailer.KeyAHex)
	}
	if got.Trailer.KeyBHex != "FFFFFFFFFFFF" {
		t.Errorf("KeyBHex = %q; want all-F", got.Trailer.KeyBHex)
	}
	if got.Trailer.GeneralByte != 0x69 {
		t.Errorf("GeneralByte = 0x%X; want 0x69", got.Trailer.GeneralByte)
	}
	if !got.Trailer.AccessValid {
		t.Fatal("default transport access bits should validate")
	}
	if got.Trailer.AccessBits == nil {
		t.Fatal("AccessBits should be populated when valid")
	}
	// All data blocks (0-2) at the transport key get C1C2C3 = 0/0/0.
	for i := 0; i < 3; i++ {
		b := got.Trailer.AccessBits.Blocks[i]
		if b.C1 != 0 || b.C2 != 0 || b.C3 != 0 {
			t.Errorf("Block %d C1C2C3 = %d/%d/%d; want 0/0/0",
				i, b.C1, b.C2, b.C3)
		}
		if b.Read != "A|B" || b.Write != "A|B" {
			t.Errorf("Block %d permissions read=%q write=%q; want A|B / A|B",
				i, b.Read, b.Write)
		}
	}
	// Trailer (block 3) at transport keys gets C1C2C3 = 0/0/1
	// (Key A can rewrite everything including Key A).
	tr := got.Trailer.AccessBits.Blocks[3]
	if tr.C1 != 0 || tr.C2 != 0 || tr.C3 != 1 {
		t.Errorf("Trailer C1C2C3 = %d/%d/%d; want 0/0/1", tr.C1, tr.C2, tr.C3)
	}
	if tr.TrailerAccess == nil {
		t.Fatal("TrailerAccess should be populated for trailer block")
	}
	if tr.TrailerAccess.KeyAWrite != "A" {
		t.Errorf("KeyAWrite = %q; want 'A'", tr.TrailerAccess.KeyAWrite)
	}
	if tr.TrailerAccess.KeyBWrite != "A" {
		t.Errorf("KeyBWrite = %q; want 'A'", tr.TrailerAccess.KeyBWrite)
	}
}

// TestDecodeBlock_ManufacturerWithValidBCC parses sector 0 block
// 0 from a real-ish dump. NUID = 04 89 5C 9F (4-byte UID);
// BCC = 04^89^5C^9F = 0x4E; SAK = 0x08; ATQA = 04 00 (Mifare
// Classic 1K signature).
func TestDecodeBlock_ManufacturerWithValidBCC(t *testing.T) {
	got, err := DecodeBlock("04 89 5C 9F 4E 08 04 00 ABCDEF0123456789", 0)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if got.Kind != KindManufacturer {
		t.Fatalf("Kind = %q; want 'manufacturer'", got.Kind)
	}
	if got.Manufacturer == nil {
		t.Fatal("Manufacturer field is nil")
	}
	if got.Manufacturer.NUIDHex != "04895C9F" {
		t.Errorf("NUIDHex = %q", got.Manufacturer.NUIDHex)
	}
	if got.Manufacturer.BCC != 0x4E {
		t.Errorf("BCC = 0x%X; want 0x4E", got.Manufacturer.BCC)
	}
	if !got.Manufacturer.BCCValid {
		t.Error("BCC integrity should pass: 04^89^5C^9F = 0x4E")
	}
	if got.Manufacturer.SAK != 0x08 {
		t.Errorf("SAK = 0x%X; want 0x08 (Mifare Classic 1K)", got.Manufacturer.SAK)
	}
	if got.Manufacturer.ATQA != "0400" {
		t.Errorf("ATQA = %q", got.Manufacturer.ATQA)
	}
	if got.Manufacturer.ICManufacturer != "NXP Semiconductors" {
		t.Errorf("ICManufacturer = %q; want NXP (first NUID byte 0x04 → NXP)",
			got.Manufacturer.ICManufacturer)
	}
}

// TestDecodeBlock_ManufacturerInvalidBCC catches a corrupted BCC
// (common after fuzzing or sloppy clones).
func TestDecodeBlock_ManufacturerInvalidBCC(t *testing.T) {
	got, err := DecodeBlock("04 89 5C 9F 00 08 04 00 ABCDEF0123456789", 0)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if got.Manufacturer.BCCValid {
		t.Error("BCC validity should be false for wrong BCC byte 00")
	}
}

// TestDecodeBlock_ValueBlock parses a value block holding +1234
// (LE int32 = 0xD2 04 00 00) at address 0x1A. The complement and
// duplicate structure is built deliberately so the integrity
// flags all pass.
func TestDecodeBlock_ValueBlock(t *testing.T) {
	// value 1234 = 0xD2 04 00 00 LE
	// ~value = 0x2D FB FF FF
	// addr = 0x1A, ~addr = 0xE5
	got, err := DecodeBlock("D2040000 2DFBFFFF D2040000 1A E5 1A E5", 4)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if got.Kind != KindValue {
		t.Fatalf("Kind = %q; want 'value'", got.Kind)
	}
	if got.Value == nil {
		t.Fatal("Value field is nil")
	}
	if got.Value.Value != 1234 {
		t.Errorf("Value = %d; want 1234", got.Value.Value)
	}
	if !got.Value.ValueValid {
		t.Error("ValueValid should be true for valid complement structure")
	}
	if got.Value.Address != 0x1A {
		t.Errorf("Address = 0x%X; want 0x1A", got.Value.Address)
	}
	if !got.Value.AddressValid {
		t.Error("AddressValid should be true")
	}
}

// TestDecodeBlock_ValueBlock_NegativeValue confirms the signed
// int32 conversion picks up negative numbers.
func TestDecodeBlock_ValueBlock_NegativeValue(t *testing.T) {
	// value = -1 = 0xFFFFFFFF LE
	// ~value = 0x00000000
	got, err := DecodeBlock("FFFFFFFF 00000000 FFFFFFFF 00 FF 00 FF", 4)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if got.Kind != KindValue {
		t.Fatalf("Kind = %q; want 'value'", got.Kind)
	}
	if got.Value.Value != -1 {
		t.Errorf("Value = %d; want -1", got.Value.Value)
	}
}

// TestDecodeBlock_DataBlock falls through to the data kind when
// the bytes don't match value structure or aren't a trailer.
// "Hello, World!" + 3 padding bytes = exactly 16 bytes.
func TestDecodeBlock_DataBlock(t *testing.T) {
	got, err := DecodeBlock("48656C6C6F2C20576F726C642100AABB", 1)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if got.Kind != KindData {
		t.Fatalf("Kind = %q; want 'data'", got.Kind)
	}
	if !strings.HasPrefix(got.ASCII, "Hello, World") {
		t.Errorf("ASCII = %q; want it to start with 'Hello, World'", got.ASCII)
	}
}

// TestDecodeBlock_NoIndexClassifiesGenerically — when index < 0
// the classifier can't recognise the manufacturer block but
// should still classify value vs data structurally.
func TestDecodeBlock_NoIndexClassifiesGenerically(t *testing.T) {
	// Value block bytes, but no index hint.
	got, err := DecodeBlock("D2040000 2DFBFFFF D2040000 1A E5 1A E5", -1)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if got.Kind != KindValue {
		t.Errorf("Kind = %q; want 'value' (structural classification)", got.Kind)
	}
	if got.Index != -1 {
		t.Errorf("Index = %d; want -1", got.Index)
	}
}

// TestDecodeBlock_HexLengthValidation rejects inputs that aren't
// exactly 16 bytes after separator stripping.
func TestDecodeBlock_HexLengthValidation(t *testing.T) {
	cases := []string{"", "AB", strings.Repeat("00", 17)}
	for _, in := range cases {
		_, err := DecodeBlock(in, 0)
		if err == nil {
			t.Errorf("DecodeBlock(%q) = nil; want error", in)
		}
	}
}

// TestDecodeDump_Small1KLayout decodes a 4-sector dump (16 blocks
// = 256 bytes) and verifies the manufacturer / trailer
// classification across multiple sectors.
func TestDecodeDump_Small1KLayout(t *testing.T) {
	// Build a 16-block dump:
	//   block 0: manufacturer
	//   blocks 1, 2: data
	//   block 3: default trailer
	//   blocks 4-7 similarly
	//   ... etc for 4 sectors
	const (
		manufacturer = "04895C9F8208040000000000000000FF"
		dataBlock    = "00000000000000000000000000000000"
		trailer      = "FFFFFFFFFFFFFF078069FFFFFFFFFFFF"
	)
	var sb strings.Builder
	for sector := 0; sector < 4; sector++ {
		for b := 0; b < 4; b++ {
			switch {
			case sector == 0 && b == 0:
				sb.WriteString(manufacturer)
			case b == 3:
				sb.WriteString(trailer)
			default:
				sb.WriteString(dataBlock)
			}
		}
	}
	got, err := DecodeDump(sb.String())
	if err != nil {
		t.Fatalf("DecodeDump: %v", err)
	}
	if len(got) != 16 {
		t.Fatalf("got %d blocks; want 16", len(got))
	}
	if got[0].Kind != KindManufacturer {
		t.Errorf("block 0 Kind = %q", got[0].Kind)
	}
	for _, idx := range []int{3, 7, 11, 15} {
		if got[idx].Kind != KindTrailer {
			t.Errorf("block %d Kind = %q; want trailer", idx, got[idx].Kind)
		}
		if got[idx].Sector != idx/4 {
			t.Errorf("block %d Sector = %d", idx, got[idx].Sector)
		}
	}
}

// TestDecodeDump_RejectsBadLengths surfaces a clear error when
// the dump's hex length isn't a 16-byte multiple.
func TestDecodeDump_RejectsBadLengths(t *testing.T) {
	if _, err := DecodeDump(""); err == nil {
		t.Error("empty dump: want error")
	}
	if _, err := DecodeDump("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"); err == nil {
		t.Error("31-byte length: want error")
	}
}

// TestDecodeAccessBits_Validity confirms the inversion check
// catches a mangled access-bits triple.
func TestDecodeAccessBits_Validity(t *testing.T) {
	// FF 07 80 = valid (default transport)
	if _, ok := decodeAccessBits(0xFF, 0x07, 0x80); !ok {
		t.Error("FF 07 80 should validate (default transport keys)")
	}
	// 00 00 00 = invalid (each nibble should be inverted form of another)
	if _, ok := decodeAccessBits(0x00, 0x00, 0x00); ok {
		t.Error("00 00 00 should fail inversion check")
	}
}

// TestIsTrailerIndex covers the 1K (4-block) and 4K large-sector
// (16-block) cases.
func TestIsTrailerIndex(t *testing.T) {
	for _, idx := range []int{3, 7, 11, 63, 127} {
		if !isTrailerIndex(idx) {
			t.Errorf("isTrailerIndex(%d) = false; want true", idx)
		}
	}
	for _, idx := range []int{0, 1, 2, 4, 128, 129} {
		if isTrailerIndex(idx) {
			t.Errorf("isTrailerIndex(%d) = true; want false", idx)
		}
	}
	// 4K large sectors: trailers at 143, 159, ..., 255
	for _, idx := range []int{143, 159, 175, 191, 207, 223, 239, 255} {
		if !isTrailerIndex(idx) {
			t.Errorf("isTrailerIndex(%d) = false; want true (4K trailer)", idx)
		}
	}
}

// TestSectorOf maps blocks to sectors for 1K and 4K layouts.
func TestSectorOf(t *testing.T) {
	cases := map[int]int{
		0:   0,
		3:   0,
		4:   1,
		63:  15,
		64:  16,
		127: 31,
		128: 32,
		143: 32,
		144: 33,
		255: 39,
	}
	for blk, want := range cases {
		if got := sectorOf(blk); got != want {
			t.Errorf("sectorOf(%d) = %d; want %d", blk, got, want)
		}
	}
}
