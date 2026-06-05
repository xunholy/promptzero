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
//   - The transport-protocol-layer (TPL) header after the CI field
//     (EN 13757-3): short (CI 0x7A) / long (0x72) / none (0x78), the
//     access number and status byte, and — the headline — the
//     ENCRYPTION MODE from the configuration word (plaintext vs
//     AES-128-CBC mode 5/7, with the encrypted-block count and the
//     bidirectional / accessibility / synchronous flags). Whether the
//     meter's data is readable or AES-encrypted is the first thing a
//     smart-meter assessment needs to know.
//   - The de-chunked application payload (the blocks with their CRCs
//     stripped and concatenated) and its leading CI field — ready to
//     feed into mbus_decode for the full Variable-Data-Structure read.
//
// # Deliberately deferred
//
//	Format B framing (a single trailing CRC instead of per-block CRCs)
//	is detected by CRC mismatch and noted rather than mis-parsed. The
//	3-of-6 (mode T) / Manchester (mode S) line coding is upstream — feed
//	the line-decoded bytes. AES decryption of an encrypted payload needs
//	the meter key (not carried in the frame). Application-layer (DIF/VIF)
//	decode is mbus_decode's job; the de-chunked payload is surfaced for it.
package wmbus

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded wM-Bus radio frame.
type Result struct {
	Length         int        `json:"length_field"`
	Format         string     `json:"format"`
	CField         string     `json:"c_field"`
	CFieldName     string     `json:"c_field_name"`
	Manufacturer   string     `json:"manufacturer"`
	ManufacturerID string     `json:"manufacturer_id"`
	MeterID        string     `json:"meter_id"`
	Version        int        `json:"version"`
	DeviceType     string     `json:"device_type"`
	DeviceTypeName string     `json:"device_type_name"`
	BlocksValid    bool       `json:"all_blocks_crc_valid"`
	BlockCount     int        `json:"block_count"`
	CIField        string     `json:"ci_field,omitempty"`
	Transport      *TPLHeader `json:"transport_header,omitempty"`
	PayloadHex     string     `json:"application_payload_hex,omitempty"`
	Notes          []string   `json:"notes,omitempty"`
}

// TPLHeader is the decoded transport-protocol-layer header (EN 13757-3)
// that follows the CI field. Its headline field is the encryption mode —
// whether the meter's data is plaintext or AES-encrypted.
type TPLHeader struct {
	HeaderType      string `json:"header_type"` // short / long / none
	AccessNumber    *int   `json:"access_number,omitempty"`
	Status          string `json:"status,omitempty"`
	ConfigWord      string `json:"config_word,omitempty"`
	EncryptionMode  int    `json:"encryption_mode"`
	EncryptionName  string `json:"encryption_name"`
	Encrypted       bool   `json:"encrypted"`
	EncryptedBlocks int    `json:"encrypted_blocks,omitempty"`
	Bidirectional   bool   `json:"bidirectional,omitempty"`
	Accessibility   bool   `json:"accessibility,omitempty"`
	Synchronous     bool   `json:"synchronous,omitempty"`
	// Long-header (CI 0x72) embedded address (may differ from the link layer).
	EmbeddedID           string `json:"embedded_id,omitempty"`
	EmbeddedManufacturer string `json:"embedded_manufacturer,omitempty"`
	EmbeddedVersion      *int   `json:"embedded_version,omitempty"`
	EmbeddedDeviceType   string `json:"embedded_device_type,omitempty"`
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
		r.Transport = decodeTPL(payload)
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

// decodeTPL decodes the transport-protocol-layer header that follows the
// CI field (EN 13757-3). payload[0] is the CI field.
func decodeTPL(payload []byte) *TPLHeader {
	ci := payload[0]
	switch ci {
	case 0x7A: // short header: ACC, STS, CFG(2)
		if len(payload) < 5 {
			return &TPLHeader{HeaderType: "short (truncated)"}
		}
		t := &TPLHeader{HeaderType: "short"}
		acc := int(payload[1])
		t.AccessNumber = &acc
		t.Status = fmt.Sprintf("0x%02X", payload[2])
		applyConfig(t, payload[3], payload[4])
		return t
	case 0x72: // long header: ID(4) M(2) ver type ACC STS CFG(2)
		if len(payload) < 13 {
			return &TPLHeader{HeaderType: "long (truncated)"}
		}
		t := &TPLHeader{HeaderType: "long"}
		t.EmbeddedID = fmt.Sprintf("%02X%02X%02X%02X", payload[4], payload[3], payload[2], payload[1])
		t.EmbeddedManufacturer = manufacturerFLAG(uint16(payload[5]) | uint16(payload[6])<<8)
		ver := int(payload[7])
		t.EmbeddedVersion = &ver
		t.EmbeddedDeviceType = deviceTypeName(payload[8])
		acc := int(payload[9])
		t.AccessNumber = &acc
		t.Status = fmt.Sprintf("0x%02X", payload[10])
		applyConfig(t, payload[11], payload[12])
		return t
	case 0x78: // no header, application data follows directly
		return &TPLHeader{HeaderType: "none", EncryptionName: "no security (plaintext)"}
	}
	return nil
}

// applyConfig decodes the 2-byte TPL configuration word (cfg1 low, cfg2
// high) into the encryption mode and flags.
func applyConfig(t *TPLHeader, cfg1, cfg2 byte) {
	cfg := uint16(cfg2)<<8 | uint16(cfg1)
	t.ConfigWord = fmt.Sprintf("0x%04X", cfg)
	t.Bidirectional = cfg&0x8000 != 0
	t.Accessibility = cfg&0x4000 != 0
	t.Synchronous = cfg&0x2000 != 0
	mode := int(cfg>>8) & 0x1F
	t.EncryptionMode = mode
	t.EncryptionName = encryptionName(mode)
	t.Encrypted = mode != 0
	if mode == 5 { // AES-CBC with IV carries the encrypted-block count
		t.EncryptedBlocks = int(cfg&0x00F0) >> 4
	}
}

// encryptionName names the well-documented TPL security modes; others are
// surfaced numerically rather than guessed.
func encryptionName(mode int) string {
	switch mode {
	case 0:
		return "no security (plaintext)"
	case 5:
		return "AES-128-CBC, dynamic IV (mode 5)"
	case 7:
		return "AES-128-CBC, no IV (mode 7)"
	}
	return fmt.Sprintf("security mode %d (see EN 13757-3)", mode)
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
