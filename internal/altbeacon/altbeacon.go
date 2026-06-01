// SPDX-License-Identifier: AGPL-3.0-or-later

// Package altbeacon decodes and builds AltBeacon BLE advertisements — the
// open, vendor-neutral beacon standard (github.com/AltBeacon/spec), the
// counterpart to Apple iBeacon and Google Eddystone.
//
// # Wrap-vs-native judgement
//
// Native. AltBeacon is a fully open public specification: a
// manufacturer-specific-data AD structure of a 2-byte company ID, the
// 0xBEAC beacon code, a 20-byte beacon ID, a 1-byte reference RSSI, and a
// 1-byte manufacturer-reserved value. Decoding and encoding are pure byte
// assembly with no crypto and no hardware — paste the hex from a btmon /
// Wireshark capture and decode offline, or build the payload an operator
// advertises from a beacon for a proximity test. Generation-only on the
// encode side: it advertises nothing and touches no radio, so it is Low
// risk like the other beacon codecs. Correctness is verifiable two ways:
// round-trip between Decode and Encode, and the canonical worked example in
// the AltBeacon spec (company 0x0118, beacon code BE AC, ref RSSI 0xC5).
//
// # Covered
//
//   - The full 24-byte AltBeacon body (beacon code + 20-byte beacon ID +
//     reference RSSI + mfg-reserved) behind any of three input framings:
//     the full advertising-data record (<len> FF <mfgid> ...), the bare
//     manufacturer-specific-data payload (<mfgid> BE AC ...), or a payload
//     that already starts at the 0xBEAC beacon code.
//   - The common interpretation of the 20-byte beacon ID as a 16-byte
//     proximity UUID + 2-byte major + 2-byte minor is surfaced alongside
//     the opaque 20-byte form, labelled as a convenience (the spec treats
//     the beacon ID as opaque).
package altbeacon

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// BeaconCode is the 0xBEAC marker that identifies an AltBeacon body,
// transmitted big-endian (BE AC).
const BeaconCode uint16 = 0xBEAC

// AltBeacon is the decoded view of an AltBeacon advertisement.
type AltBeacon struct {
	MfgID       uint16 `json:"mfg_id"`       // advertiser company ID (little-endian on the wire)
	MfgIDHex    string `json:"mfg_id_hex"`   // "0x0118"
	BeaconCode  string `json:"beacon_code"`  // always "0xBEAC" for a valid frame
	BeaconID    string `json:"beacon_id"`    // 20-byte opaque ID (hex)
	RefRSSI     int8   `json:"ref_rssi_dbm"` // reference RSSI at 1 m
	MfgReserved int    `json:"mfg_reserved"` // manufacturer-reserved byte
	OuterFormat string `json:"outer_format"` // ad_record | manufacturer_data | beacon_code
	Hex         string `json:"hex"`          // full payload as decoded (hex)
	CommonUUID  string `json:"common_uuid"`  // beacon ID bytes 0..15 as a dashed UUID (convenience)
	CommonMajor uint16 `json:"common_major"` // beacon ID bytes 16..17 (convenience)
	CommonMinor uint16 `json:"common_minor"` // beacon ID bytes 18..19 (convenience)
}

// Decode parses a hex-encoded AltBeacon advertisement. Three framings are
// accepted; the parser strips any prefix it recognises before the 0xBEAC
// beacon code: the full advertising-data record (<len> FF <mfgid> BE AC …),
// the bare manufacturer-specific-data payload (<mfgid> BE AC …), or a
// payload already starting at the beacon code (BE AC …, mfg ID unknown).
func Decode(hexStr string) (*AltBeacon, error) {
	b, err := parseHex(hexStr)
	if err != nil {
		return nil, err
	}
	mfgID, body, format, err := stripOuter(b)
	if err != nil {
		return nil, err
	}
	// body now starts at the beacon code: BE AC + 20 + 1 + 1 = 24 bytes.
	if len(body) < 24 {
		return nil, fmt.Errorf("altbeacon: body %d bytes after the company ID; need 24 (BE AC + 20-byte ID + RSSI + reserved)", len(body))
	}
	if binary.BigEndian.Uint16(body[0:2]) != BeaconCode {
		return nil, fmt.Errorf("altbeacon: beacon code is 0x%04X, want 0xBEAC", binary.BigEndian.Uint16(body[0:2]))
	}
	id := body[2:22]
	out := &AltBeacon{
		MfgID:       mfgID,
		MfgIDHex:    fmt.Sprintf("0x%04X", mfgID),
		BeaconCode:  "0xBEAC",
		BeaconID:    strings.ToUpper(hex.EncodeToString(id)),
		RefRSSI:     int8(body[22]),
		MfgReserved: int(body[23]),
		OuterFormat: format,
		Hex:         strings.ToUpper(hex.EncodeToString(b)),
		CommonUUID:  dashUUID(id[0:16]),
		CommonMajor: binary.BigEndian.Uint16(id[16:18]),
		CommonMinor: binary.BigEndian.Uint16(id[18:20]),
	}
	return out, nil
}

// stripOuter detects the framing and returns the company ID (0 when the
// input starts at the beacon code), the body starting at the beacon code,
// and the format name.
func stripOuter(b []byte) (mfgID uint16, body []byte, format string, err error) {
	// (a) advertising-data record: <len> FF <mfgid:2 LE> BE AC ...
	if len(b) >= 6 && b[1] == 0xFF && b[4] == 0xBE && b[5] == 0xAC {
		declaredLen := int(b[0])
		end := 1 + declaredLen
		// end must reach past the matched beacon code (>=6) and stay within
		// the buffer; a bogus short length would otherwise slice b[4:<4].
		if end < 6 || end > len(b) {
			return 0, nil, "", fmt.Errorf("altbeacon: advertising-data length %d inconsistent with a %d-byte buffer", declaredLen, len(b))
		}
		return binary.LittleEndian.Uint16(b[2:4]), b[4:end], "ad_record", nil
	}
	// (b) manufacturer data: <mfgid:2 LE> BE AC ...
	if len(b) >= 4 && b[2] == 0xBE && b[3] == 0xAC {
		return binary.LittleEndian.Uint16(b[0:2]), b[2:], "manufacturer_data", nil
	}
	// (c) already at the beacon code: BE AC ...
	if len(b) >= 2 && b[0] == 0xBE && b[1] == 0xAC {
		return 0, b, "beacon_code", nil
	}
	return 0, nil, "", fmt.Errorf("altbeacon: 0xBEAC beacon code not found (expected at offset 4 for an AD record, 2 for manufacturer data, or 0)")
}

// EncodeRequest describes an AltBeacon to build.
type EncodeRequest struct {
	MfgID       uint16 `json:"mfg_id"`       // advertiser company ID (default 0x0118 Radius Networks)
	BeaconID    string `json:"beacon_id"`    // 20-byte beacon ID as hex (required)
	RefRSSI     int8   `json:"ref_rssi_dbm"` // reference RSSI at 1 m
	MfgReserved int    `json:"mfg_reserved"` // manufacturer-reserved byte (0..255)
	// Wrap: "manufacturer" (default; <mfgid> BE AC …) or "ad" (the full
	// <len> FF <mfgid> BE AC … advertising-data record).
	Wrap string `json:"wrap,omitempty"`
}

// DefaultMfgID is the company ID used when none is supplied — Radius
// Networks (0x0118), the AltBeacon spec author, matching the spec example.
const DefaultMfgID uint16 = 0x0118

// Encode builds the bytes of an AltBeacon advertisement — the inverse of
// Decode, round-trip-verified against it. The beacon ID must be exactly 20
// bytes. Generation only; it advertises nothing.
func Encode(r EncodeRequest) ([]byte, error) {
	id, err := parseHex(r.BeaconID)
	if err != nil {
		return nil, fmt.Errorf("altbeacon: beacon_id: %w", err)
	}
	if len(id) != 20 {
		return nil, fmt.Errorf("altbeacon: beacon_id must be exactly 20 bytes; got %d", len(id))
	}
	if r.MfgReserved < 0 || r.MfgReserved > 0xFF {
		return nil, fmt.Errorf("altbeacon: mfg_reserved %d out of range (0..255)", r.MfgReserved)
	}
	mfg := r.MfgID
	if mfg == 0 {
		mfg = DefaultMfgID
	}
	// Manufacturer data: <mfgid:2 LE> BE AC <id:20> <rssi> <reserved>.
	mfgData := make([]byte, 0, 26)
	mfgData = binary.LittleEndian.AppendUint16(mfgData, mfg)
	mfgData = binary.BigEndian.AppendUint16(mfgData, BeaconCode)
	mfgData = append(mfgData, id...)
	mfgData = append(mfgData, byte(r.RefRSSI), byte(r.MfgReserved))

	switch strings.ToLower(strings.TrimSpace(r.Wrap)) {
	case "", "manufacturer":
		return mfgData, nil
	case "ad":
		// <len> FF <mfgData>, where len = 1 (FF) + len(mfgData).
		out := make([]byte, 0, 2+len(mfgData))
		out = append(out, byte(1+len(mfgData)), 0xFF)
		out = append(out, mfgData...)
		return out, nil
	default:
		return nil, fmt.Errorf("altbeacon: unknown wrap %q (manufacturer, ad)", r.Wrap)
	}
}

// dashUUID renders 16 bytes as a dashed 8-4-4-4-12 uppercase UUID.
func dashUUID(b []byte) string {
	if len(b) != 16 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	h := strings.ToUpper(hex.EncodeToString(b))
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// parseHex strips separators and a leading 0x, then hex-decodes.
func parseHex(s string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(s))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("altbeacon: empty hex input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("altbeacon: invalid hex: %w", err)
	}
	return b, nil
}
