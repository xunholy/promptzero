// Package mifare decodes Mifare Classic 1K / 4K data dumps —
// manufacturer block (sector 0 block 0), sector trailer (last
// block of each sector), value blocks (recognized by their
// value+complement structure), and plain data blocks. Pure
// offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: Mifare Classic's block layouts are
// public — NXP application notes AN10833 (sector trailer and
// access conditions), AN10834 (value blocks), AN10927 (UID
// formats), and ISO/IEC 14443-3 (ATQA / SAK). Wrapping a FAP for
// this would require an SD-card install + a firmware-fork
// dependency for a pure parser. We implement natively so
// operators can paste a 16-byte block (or a 64-block 1K dump /
// 256-block 4K dump) and decode it offline.
//
// What this package covers:
//   - Block-kind classification (manufacturer, trailer, value,
//     data) based on block index + structural heuristics
//   - Sector-trailer decode: Key A, access bits, GPB, Key B,
//     plus the per-block permission expansion (read / write /
//     increment / decrement / transfer / restore allowed for
//     Key A only, Key B only, both, or neither)
//   - Value-block decode: value + complement + duplicate value
//     integrity check, signed 32-bit value, address byte +
//     complement check
//   - Manufacturer-block decode: NUID (4-byte UID), BCC, SAK,
//     ATQA, and the 8 trailing manufacturer-data bytes
//   - Dump walker that classifies every block of a 1K / 4K dump
//     in one pass
//
// What this package does NOT cover (deliberately out of scope):
//   - Reading the actual card (operators bring dumps from Flipper /
//     Proxmark3 / etc.)
//   - Cryptogram derivation or key recovery (covered by the
//     internal/crypto1 package's mfoc / mfcuk / mfkey32 paths)
//   - Mifare Plus / DESFire — separate specs with separate layouts
//   - Re-encode (round-tripping a decoded view back to 16 bytes —
//     happy to add if a caller materialises)
package mifare

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// BlockKind enumerates the block roles we recognise.
type BlockKind string

const (
	// KindManufacturer is sector 0 block 0 — the read-only NUID
	// / BCC / SAK / ATQA / manufacturer-data block.
	KindManufacturer BlockKind = "manufacturer"
	// KindTrailer is the last block of each sector — Key A,
	// access bits, GPB, Key B.
	KindTrailer BlockKind = "sector_trailer"
	// KindValue is a value-formatted block (value + complement +
	// duplicate value + address byte + complement structure).
	// We classify a block as value when the complement integrity
	// check passes.
	KindValue BlockKind = "value"
	// KindData is the catch-all for ordinary data blocks.
	KindData BlockKind = "data"
)

// Block is the structured decoded view of a 16-byte Mifare
// Classic block.
type Block struct {
	// Index is the block's absolute position in the dump (0..63
	// for 1K, 0..255 for 4K). -1 when decoding a single block
	// with no dump context.
	Index int `json:"index"`
	// Sector is the sector number containing this block. -1 when
	// Index is -1.
	Sector int `json:"sector"`
	// Kind is the recognised block role.
	Kind BlockKind `json:"kind"`
	// Hex is the operator-facing hex rendering of the raw 16
	// bytes, uppercase, no separators.
	Hex string `json:"hex"`
	// ASCII is the printable-ASCII rendering of the raw bytes
	// with '.' for non-printable. Useful for spotting strings in
	// data blocks.
	ASCII string `json:"ascii"`
	// Trailer is populated when Kind == KindTrailer.
	Trailer *Trailer `json:"trailer,omitempty"`
	// Value is populated when Kind == KindValue.
	Value *Value `json:"value,omitempty"`
	// Manufacturer is populated when Kind == KindManufacturer.
	Manufacturer *Manufacturer `json:"manufacturer,omitempty"`
}

// Trailer is the decoded sector-trailer view. KeyA / KeyB are
// hex-rendered for the JSON shape; AccessBits expands into the
// per-block permission table.
type Trailer struct {
	KeyAHex     string      `json:"key_a_hex"`
	AccessBytes string      `json:"access_bytes_hex"`
	GeneralByte int         `json:"general_purpose_byte"`
	KeyBHex     string      `json:"key_b_hex"`
	AccessValid bool        `json:"access_bits_valid"`
	AccessBits  *AccessBits `json:"access_bits,omitempty"`
}

// Value is the decoded value-block view.
type Value struct {
	// Value is the signed 32-bit value extracted from bytes 0-3.
	Value int32 `json:"value"`
	// ValueValid is true iff the value at bytes 0-3, its
	// complement at bytes 4-7, and the duplicate at bytes 8-11
	// all satisfy the complement integrity check.
	ValueValid bool `json:"value_integrity_valid"`
	// Address is the address byte (byte 12).
	Address int `json:"address"`
	// AddressValid mirrors ValueValid for the 4-byte address
	// structure (byte 12 / ~byte 13 / byte 14 / ~byte 15).
	AddressValid bool `json:"address_integrity_valid"`
}

// Manufacturer is the decoded manufacturer-block view. NUID can
// be either 4-byte (single-size UID) or part of a 7-byte UID
// chained across two CT (cascade tag) reads — this dump format
// only shows the first 4 bytes, so we render them and the BCC
// without trying to reconstruct a 7-byte UID. ATQA / SAK / IC
// manufacturer code are surfaced for cross-reference with the
// well-known tag-type tables.
type Manufacturer struct {
	NUIDHex         string `json:"nuid_hex"`
	BCC             int    `json:"bcc"`
	BCCValid        bool   `json:"bcc_valid"`
	SAK             int    `json:"sak"`
	ATQA            string `json:"atqa_hex"`
	ManufacturerHex string `json:"manufacturer_data_hex"`
	ICManufacturer  string `json:"ic_manufacturer,omitempty"`
}

// DecodeBlock decodes a single hex-encoded 16-byte Mifare Classic
// block. When index >= 0 the caller is telling us the block's
// position in the dump (so the manufacturer / trailer
// classification can use it); when index < 0 we classify from the
// block's structure alone (no manufacturer recognition without an
// index).
func DecodeBlock(hexBlob string, index int) (Block, error) {
	b, err := decodeHex16(hexBlob)
	if err != nil {
		return Block{}, err
	}
	return classifyBlock(b, index, sectorOf(index)), nil
}

// DecodeDump decodes a full 1K (64 blocks = 1024 bytes) or 4K
// (256 blocks = 4096 bytes) Mifare Classic dump. Returns one
// Block per 16-byte chunk; rejects inputs whose length isn't a
// 16-byte multiple. Accepts ':' / '-' / '_' / whitespace
// separators.
func DecodeDump(hexBlob string) ([]Block, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return nil, fmt.Errorf("mifare: empty input")
	}
	if len(cleaned)%32 != 0 {
		return nil, fmt.Errorf("mifare: dump length must be a multiple of 32 hex chars (16-byte blocks); got %d hex chars", len(cleaned))
	}
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("mifare: invalid hex: %w", err)
	}
	// Mifare Classic mini = 20 blocks, 1K = 64, 2K = 128, 4K =
	// 256 — the cards Flipper / Proxmark dump. We accept any
	// 16-byte multiple but the trailer-index classifier may not
	// match a real card layout for non-standard sizes.
	out := make([]Block, len(raw)/16)
	for i := 0; i < len(raw)/16; i++ {
		out[i] = classifyBlock(raw[i*16:(i+1)*16], i, sectorOf(i))
	}
	return out, nil
}

// classifyBlock is the shared classifier — pure function over
// bytes + index. Index = -1 means "no dump context"; in that
// case we never classify as manufacturer (no way to know without
// position) and trailer-classification falls back to structural
// hints only.
func classifyBlock(b []byte, index, sector int) Block {
	blk := Block{
		Index:  index,
		Sector: sector,
		Hex:    strings.ToUpper(hex.EncodeToString(b)),
		ASCII:  asciiPreview(b),
	}
	switch {
	case index == 0:
		blk.Kind = KindManufacturer
		blk.Manufacturer = decodeManufacturer(b)
	case index >= 0 && isTrailerIndex(index):
		blk.Kind = KindTrailer
		blk.Trailer = decodeTrailer(b)
	default:
		if v, ok := tryDecodeValue(b); ok {
			blk.Kind = KindValue
			blk.Value = v
		} else {
			blk.Kind = KindData
		}
	}
	return blk
}

// isTrailerIndex reports whether a block index is the trailer of
// its sector. For 1K (sectors 0-15, 4 blocks each) trailer = 3, 7,
// 11, ..., 63. For 4K, sectors 16-31 have 16 blocks each, so
// trailers from index 128 onward sit at 143, 159, 175, ..., 255.
func isTrailerIndex(idx int) bool {
	switch {
	case idx < 0:
		return false
	case idx < 128:
		return (idx+1)%4 == 0
	case idx <= 255:
		return (idx-128+1)%16 == 0
	default:
		// Beyond 4K: assume 4-block sectors.
		return (idx+1)%4 == 0
	}
}

// sectorOf returns the sector index for a block index, or -1 for
// idx < 0.
func sectorOf(idx int) int {
	switch {
	case idx < 0:
		return -1
	case idx < 128:
		return idx / 4
	case idx <= 255:
		return 32 + (idx-128)/16
	default:
		return -1
	}
}

// decodeManufacturer parses the 16-byte manufacturer block.
// Layout (per NXP AN10927):
//
//	NUID:4 + BCC:1 + SAK:1 + ATQA:2 + ManufacturerData:8
//
// BCC = XOR of the 4 NUID bytes. We surface a validity flag.
// The IC manufacturer code is byte 5 of a 7-byte UID — for the
// 4-byte UID case (most Mifare Classic 1K cards) the manufacturer
// byte sits later in the chained UID we don't have access to in
// this dump format, so we name it only when the first byte is
// the cascade tag 0x88 (then byte 1 is the manufacturer code).
func decodeManufacturer(b []byte) *Manufacturer {
	bcc := b[0] ^ b[1] ^ b[2] ^ b[3]
	m := &Manufacturer{
		NUIDHex:         strings.ToUpper(hex.EncodeToString(b[0:4])),
		BCC:             int(b[4]),
		BCCValid:        bcc == b[4],
		SAK:             int(b[5]),
		ATQA:            strings.ToUpper(hex.EncodeToString(b[6:8])),
		ManufacturerHex: strings.ToUpper(hex.EncodeToString(b[8:16])),
	}
	if b[0] == 0x88 {
		if name, ok := icManufacturers[b[1]]; ok {
			m.ICManufacturer = name
		}
	} else {
		// For non-cascade-tag UIDs, the IC manufacturer byte is
		// embedded later (in the chained anti-collision frames
		// not visible in a sector-0-block-0 dump). We still
		// surface a guess based on the first byte when it
		// matches a well-known manufacturer prefix.
		if name, ok := icManufacturers[b[0]]; ok {
			m.ICManufacturer = name
		}
	}
	return m
}

// icManufacturers maps a subset of ISO/IEC 7816-6 IC manufacturer
// codes to vendor names. Sourced from the IIN registry; covers
// the codes operators most often see in Mifare Classic dumps.
var icManufacturers = map[byte]string{
	0x02: "STMicroelectronics",
	0x04: "NXP Semiconductors",
	0x05: "Infineon Technologies",
	0x07: "Texas Instruments",
	0x08: "Fujitsu Microelectronics",
	0x09: "Matsushita Electronics",
	0x0B: "Hitachi",
	0x0E: "Mitsubishi",
	0x18: "Samsung Electronics",
	0x1B: "Hewlett-Packard",
	0x1C: "Tag-it (TI)",
	0x1F: "Renesas",
	0x22: "Inside Secure",
	0x23: "ON Semiconductor",
	0x24: "LG Semiconductors",
	0x28: "Toshiba",
	0x2B: "Atmel",
	0x33: "AMIC",
	0x34: "Mikron",
	0x35: "Solar Capacitor",
	0x49: "Synaptics",
}

// decodeTrailer parses the 16-byte sector trailer. Layout:
//
//	KeyA:6 + AccessBytes:3 + GPB:1 + KeyB:6
//
// AccessBytes is decoded via decodeAccessBits — that's the
// non-trivial bit: 3 bits per block (C1/C2/C3) packed across the
// 3 access bytes with their inversions for integrity checking.
func decodeTrailer(b []byte) *Trailer {
	tr := &Trailer{
		KeyAHex:     strings.ToUpper(hex.EncodeToString(b[0:6])),
		AccessBytes: strings.ToUpper(hex.EncodeToString(b[6:9])),
		GeneralByte: int(b[9]),
		KeyBHex:     strings.ToUpper(hex.EncodeToString(b[10:16])),
	}
	ab, valid := decodeAccessBits(b[6], b[7], b[8])
	tr.AccessValid = valid
	if valid {
		tr.AccessBits = &ab
	}
	return tr
}

// tryDecodeValue checks the value-block complement structure. A
// value block is 16 bytes:
//
//	Value:4 (LE int32) + ~Value:4 + Value:4 + Addr:1 + ~Addr:1 +
//	  Addr:1 + ~Addr:1
//
// Value is stored little-endian. The middle 4 bytes are an exact
// repeat of the first 4 bytes. ~Value is the bitwise complement.
// Address byte is at offset 12, with its complement at 13, repeat
// at 14, complement at 15.
//
// Returns (nil, false) when the structure doesn't match —
// almost all data blocks fail this check so it serves as the
// value-vs-data classifier.
func tryDecodeValue(b []byte) (*Value, bool) {
	v1 := binary.LittleEndian.Uint32(b[0:4])
	vInv := binary.LittleEndian.Uint32(b[4:8])
	v2 := binary.LittleEndian.Uint32(b[8:12])
	valueValid := (v1 == v2) && (v1^vInv == 0xFFFFFFFF)
	if !valueValid {
		return nil, false
	}
	addr := b[12]
	addrInv := b[13]
	addrDup := b[14]
	addrInv2 := b[15]
	addrValid := (addr == addrDup) && (addr^addrInv == 0xFF) && (addrInv == addrInv2)
	return &Value{
		Value:        int32(v1),
		ValueValid:   valueValid,
		Address:      int(addr),
		AddressValid: addrValid,
	}, true
}

// asciiPreview renders raw bytes as ASCII with '.' for
// non-printable. Useful when a "data" block is actually carrying
// a string an operator might recognise (NDEF tags, vendor
// fingerprints, etc.).
func asciiPreview(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7E {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// decodeHex16 strips separators and decodes exactly 16 bytes.
func decodeHex16(s string) ([]byte, error) {
	cleaned := stripSeparators(s)
	if cleaned == "" {
		return nil, fmt.Errorf("mifare: empty input")
	}
	if len(cleaned) != 32 {
		return nil, fmt.Errorf("mifare: block must be 16 bytes (32 hex chars); got %d hex chars", len(cleaned))
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("mifare: invalid hex: %w", err)
	}
	return b, nil
}

// stripSeparators mirrors the convention in internal/ble /
// internal/emv for operator-tolerant hex intake.
func stripSeparators(s string) string {
	repl := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		":", "",
		"-", "",
		"_", "",
	)
	return repl.Replace(strings.TrimSpace(s))
}
