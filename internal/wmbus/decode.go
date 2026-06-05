// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wmbus decodes the Wireless M-Bus (wM-Bus, EN 13757-4) radio
// link layer — the 868 MHz over-the-air framing that smart water / heat /
// gas / electricity meters broadcast and that a Flipper Sub-GHz (or SDR)
// capture lifts off the air. The wired M-Bus decoder (internal/mbus)
// already handles the shared application layer; this package adds the
// radio-specific frame: the length / control fields, the manufacturer +
// meter address, and the per-block CRC-16 that the wired bus does not
// use. Reading these telegrams enumerates the meters in radio range and
// validates frame integrity — the passive-recon start of a smart-meter
// RF assessment.
//
// # Wrap-vs-native judgement
//
//	Native. The wM-Bus radio frame (EN 13757-4 Format A) is a fixed
//	public structure: an L (length) field, then block 1 = C (control)
//	+ M (2-byte manufacturer) + A (6-byte address: 4-byte BCD ID +
//	version + device type) protected by a CRC-16, then 16-byte data
//	blocks each protected by their own CRC-16. The CRC is the EN 13757
//	polynomial 0x3D65 (init 0, final XOR 0xFFFF). All of that is
//	byte-field extraction plus that one CRC, reimplemented from the
//	standard — no new dependency, no shell-out.
//
// # What this covers
//
//   - The L field and the Format-A block layout, with EVERY block's
//     CRC-16 recomputed and reported valid / invalid.
//   - Block 1: the C field (+ name: SND-NR / SND-IR / …), the
//     manufacturer (FLAG 3-letter code from the M field), and the
//     address — the BCD meter ID, the version, and the device/medium
//     type (+ name: water / gas / heat / electricity / …).
//   - The de-chunked application payload (the blocks with their CRCs
//     stripped and concatenated) and its leading CI field — ready to
//     feed into mbus_decode for the full Variable-Data-Structure read.
//
// # Deliberately deferred
//
//	Format B framing (a single trailing CRC instead of per-block CRCs)
//	is detected by CRC mismatch and noted rather than mis-parsed. The
//	3-of-6 (mode T) / Manchester (mode S) line coding is upstream — feed
//	the line-decoded bytes. Application-layer (DIF/VIF) decode is
//	mbus_decode's job; the de-chunked payload is surfaced for it.
package wmbus

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded wM-Bus radio frame.
type Result struct {
	Length         int      `json:"length_field"`
	Format         string   `json:"format"`
	CField         string   `json:"c_field"`
	CFieldName     string   `json:"c_field_name"`
	Manufacturer   string   `json:"manufacturer"`
	ManufacturerID string   `json:"manufacturer_id"`
	MeterID        string   `json:"meter_id"`
	Version        int      `json:"version"`
	DeviceType     string   `json:"device_type"`
	DeviceTypeName string   `json:"device_type_name"`
	BlocksValid    bool     `json:"all_blocks_crc_valid"`
	BlockCount     int      `json:"block_count"`
	CIField        string   `json:"ci_field,omitempty"`
	PayloadHex     string   `json:"application_payload_hex,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

// Decode parses a Wireless M-Bus radio frame (Format A) from hex. The
// bytes must already be line-decoded (3-of-6 / Manchester removed).
func Decode(hexStr string) (*Result, error) {
	b, err := hex.DecodeString(stripSep(hexStr))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	// L + block1 (9 bytes) + CRC(2) minimum.
	if len(b) < 12 {
		return nil, fmt.Errorf("frame too short (%d bytes; minimum Format-A block 1 is 12)", len(b))
	}

	r := &Result{Length: int(b[0]), Format: "A"}
	// Block 1: L C M M A A A A V T (10 bytes) + CRC.
	block1 := b[0:10]
	crc1 := uint16(b[10])<<8 | uint16(b[11])
	r.BlockCount = 1
	allValid := crc16Wmbus(block1) == crc1

	r.CField = fmt.Sprintf("0x%02X", b[1])
	r.CFieldName = cFieldName(b[1])
	m := uint16(b[2]) | uint16(b[3])<<8
	r.Manufacturer = manufacturerFLAG(m)
	r.ManufacturerID = fmt.Sprintf("0x%04X", m)
	// Meter ID: 4-byte BCD, little-endian on the wire.
	r.MeterID = fmt.Sprintf("%02X%02X%02X%02X", b[7], b[6], b[5], b[4])
	r.Version = int(b[8])
	r.DeviceType = fmt.Sprintf("0x%02X", b[9])
	r.DeviceTypeName = deviceTypeName(b[9])

	// Data blocks: 16 data bytes + CRC each (last may be shorter). The
	// total application length is L - 9 (C + M + A).
	appLen := r.Length - 9
	if appLen < 0 {
		appLen = 0
	}
	var payload []byte
	pos := 12
	remaining := appLen
	for remaining > 0 && pos < len(b) {
		n := remaining
		if n > 16 {
			n = 16
		}
		if pos+n+2 > len(b) {
			r.Notes = append(r.Notes, "frame truncated mid data block")
			allValid = false
			break
		}
		chunk := b[pos : pos+n]
		crc := uint16(b[pos+n])<<8 | uint16(b[pos+n+1])
		if crc16Wmbus(chunk) != crc {
			allValid = false
		}
		payload = append(payload, chunk...)
		pos += n + 2
		remaining -= n
		r.BlockCount++
	}
	r.BlocksValid = allValid
	if len(payload) > 0 {
		r.CIField = fmt.Sprintf("0x%02X", payload[0])
		r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		r.Notes = append(r.Notes,
			"application_payload_hex is the de-chunked M-Bus application layer — feed it to mbus_decode for the Variable-Data-Structure read")
	}
	if !allValid {
		r.Notes = append(r.Notes,
			"one or more block CRC-16 checks FAILED — corrupt frame, Format B (single trailing CRC), or wrong line decoding")
	}
	return r, nil
}

func stripSep(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r', ',':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
