// Package ble decodes BLE advertisement payloads — currently just
// Apple Continuity manufacturer-data — into operator-facing
// structures. Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: the Apple Continuity format is a
// reverse-engineered public spec — furiousMAC's project, hexway's
// AppleJuice writeups, AppleBleee and AppleAir-style scanners all
// document the same TLV layout. The dissector is a short walker
// (~150 LoC of bytes-to-field) over a byte slice. Wrapping a FAP
// for this would require an SD-card install + a firmware-fork
// dependency for a pure parser. Native delivers host-side analysis
// (paste a captured Apple manufacturer-data hex from a forum post
// or a Wireshark capture and decode without a Flipper attached),
// inline test coverage against published vectors, and a table the
// operator can extend without rebuilding firmware.
//
// What this package covers:
//   - Apple Continuity TLV walker (with separator-tolerant hex
//     intake; auto-strip of optional 4C00 manufacturer prefix and
//     full AD-structure prefix).
//   - Named action types per furiousMAC's catalog (0x02 iBeacon
//     through 0x12 Find My).
//   - Per-type field decoding for the well-documented action
//     types — Nearby Info, Nearby Action, Handoff, Tethering,
//     Proximity Pairing, AirDrop, Magic Switch.
//
// What this package does NOT cover (deliberately out of scope):
//   - Decryption of encrypted bodies (Handoff, ProximityPairing
//     past the public prefix) — Apple's session keys are not
//     publicly recoverable.
//   - Tag-name lookup for the 0xDF range or any vendor-private
//     types beyond Apple's set.
//   - Round-trip re-encode — happy to add if a caller materialises.
package ble

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// AppleManufacturerID is Apple's Bluetooth SIG company identifier.
// See https://www.bluetooth.com/specifications/assigned-numbers/.
const AppleManufacturerID = 0x004C

// ActionTLV is one decoded Continuity TLV entry. For documented
// action types Fields carries the parsed sub-fields by name; for
// unknown types Fields is nil and the operator has Hex.
type ActionTLV struct {
	// Type is the Action Type byte — 0x05 (AirDrop), 0x10 (Nearby
	// Info), etc. Stored as an int rather than byte so JSON renders
	// as a plain integer.
	Type int `json:"type"`
	// TypeHex is the operator-facing form of Type — uppercase,
	// always 2 chars, no 0x prefix ("05", "10"). Matches every
	// public reference's format.
	TypeHex string `json:"type_hex"`
	// Name is the canonical name for the action type, or
	// "Unknown" when the type isn't in our catalog. The walker
	// still records and returns unknown types so operators can
	// flag novel signatures.
	Name string `json:"name"`
	// Length is the declared payload length in bytes (the L byte
	// of the TLV).
	Length int `json:"length"`
	// Hex is the operator-facing hex rendering of Value — always
	// uppercase, no separators.
	Hex string `json:"hex"`
	// Value is the raw payload bytes.
	Value []byte `json:"-"`
	// Fields carries documented-action-type field decodes, keyed
	// by short snake_case names. Nil for unknown types or for
	// types whose body we don't dissect further.
	Fields map[string]any `json:"fields,omitempty"`
	// DecodeWarning is non-empty when the per-type decoder hit a
	// recoverable shape issue (e.g. payload shorter than the
	// documented minimum for that action). The TLV is still
	// returned so the operator can see the raw bytes; the warning
	// flags that Fields may be partial or missing.
	DecodeWarning string `json:"decode_warning,omitempty"`
}

// Continuity is the top-level decode result.
type Continuity struct {
	// TLVs is the ordered list of action-type entries pulled from
	// the payload. May be empty when the payload is empty after
	// prefix-stripping (legal but unusual — an empty 0x004C
	// manufacturer record).
	TLVs []ActionTLV `json:"tlvs"`
	// Count is len(TLVs) — surfaced for callers that consume the
	// JSON directly without needing to compute it.
	Count int `json:"count"`
	// StrippedPrefix records what the parser stripped from the
	// front of the input before walking ("none", "manufacturer",
	// "ad_structure"). Useful to confirm the parser interpreted
	// the input as the operator expected.
	StrippedPrefix string `json:"stripped_prefix"`
}

// Decode parses a hex-encoded Apple Continuity payload. Three input
// shapes are accepted; the parser strips any prefix it recognises:
//
//   - Bare TLVs:               10 02 1B 00
//   - With manufacturer ID:    4C 00 10 02 1B 00
//   - Full AD structure:       06 FF 4C 00 10 02 1B 00
//
// Separators (':' '-' '_' whitespace) are tolerated so callers can
// paste hex from Wireshark, btmon, etc., without preprocessing.
func Decode(hexBlob string) (Continuity, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Continuity{}, fmt.Errorf("ble: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Continuity{}, fmt.Errorf("ble: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant of Decode for callers that
// already have raw bytes. Same prefix-detection and walking logic.
func DecodeBytes(b []byte) (Continuity, error) {
	body, stripped := stripPrefix(b)
	if len(body) == 0 {
		return Continuity{
			TLVs:           nil,
			Count:          0,
			StrippedPrefix: stripped,
		}, nil
	}
	tlvs, err := walkTLVs(body)
	if err != nil {
		return Continuity{StrippedPrefix: stripped}, err
	}
	return Continuity{
		TLVs:           tlvs,
		Count:          len(tlvs),
		StrippedPrefix: stripped,
	}, nil
}

// stripPrefix detects the optional manufacturer-ID prefix and the
// optional full-AD-structure wrapper, returning (body, kind).
//
// AD-structure shape: 1-byte length (count of bytes that follow
// including the AD type), 1-byte AD type 0xFF (ManufacturerData),
// 2-byte little-endian manufacturer ID, payload. We only strip when
// the length and content line up exactly — partial matches are left
// alone so the caller sees the parser's "no recognised prefix"
// verdict via StrippedPrefix.
func stripPrefix(b []byte) ([]byte, string) {
	// Full AD structure: <len> FF 4C 00 ...
	if len(b) >= 4 && b[1] == 0xFF && b[2] == 0x4C && b[3] == 0x00 {
		declared := int(b[0])
		if 1+declared <= len(b) {
			return b[4 : 1+declared], "ad_structure"
		}
	}
	// Manufacturer ID only: 4C 00 ...
	if len(b) >= 2 && b[0] == 0x4C && b[1] == 0x00 {
		return b[2:], "manufacturer"
	}
	return b, "none"
}

// walkTLVs walks a payload of [type:1][length:1][value:length]
// entries. A malformed TLV (length exceeds remaining buffer)
// returns an error with the offset so the operator can correlate
// with the input hex.
func walkTLVs(b []byte) ([]ActionTLV, error) {
	var out []ActionTLV
	off := 0
	for off < len(b) {
		if off+1 >= len(b) {
			return out, fmt.Errorf("ble: TLV at offset %d missing length byte", off)
		}
		t := b[off]
		l := int(b[off+1])
		end := off + 2 + l
		if end > len(b) {
			return out, fmt.Errorf("ble: TLV at offset %d declares length %d, only %d bytes remain",
				off, l, len(b)-off-2)
		}
		val := b[off+2 : end]
		tlv := ActionTLV{
			Type:    int(t),
			TypeHex: fmt.Sprintf("%02X", t),
			Name:    actionTypeName(t),
			Length:  l,
			Hex:     strings.ToUpper(hex.EncodeToString(val)),
			Value:   val,
		}
		fields, warn := decodeFields(t, val)
		tlv.Fields = fields
		tlv.DecodeWarning = warn
		out = append(out, tlv)
		off = end
	}
	return out, nil
}

// stripSeparators removes whitespace and the punctuation we accept
// between hex characters. Mirrors emv.stripSeparators so operators
// get the same intake behaviour across our pure-decoder Specs.
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
