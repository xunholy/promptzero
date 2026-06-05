// SPDX-License-Identifier: AGPL-3.0-or-later

// Package osdp decodes OSDP (Open Supervised Device Protocol) packets —
// the SIA / IEC 60839-11-5 serial protocol that modern physical-access-
// control readers speak to their controllers (the secure successor to
// Wiegand). An OSDP bus dump is a sequence of these packets; dissecting
// them shows the poll/reply traffic, the card-read replies, the
// secure-channel handshake and any integrity failures — the staple of an
// access-control pentest / bus tap.
//
// # Wrap-vs-native judgement
//
//	Native. The OSDP packet is a fixed little-endian frame — optional
//	0xFF driver mark, 0x53 start-of-message, address byte (bit 7 =
//	reply direction, low 7 = PD address), 16-bit length, a control
//	byte (2-bit sequence number, CRC-vs-checksum flag, security-block
//	flag), an optional security control block, the command/reply code,
//	the data, and a trailer that is either a CRC-16/AUG-CCITT
//	(poly 0x1021, init 0x1D0F) or a 1-byte two's-complement checksum.
//	All of that is pure byte-field extraction plus one standard CRC,
//	so it is reimplemented here from the libosdp reference rather than
//	wrapped — no new dependency, no shell-out.
//
// # What this covers
//
//   - The full packet frame: mark / SOM / address (+ direction + PD
//     address) / length / control (sequence number, CRC-or-checksum
//     mode, secure-channel-block presence).
//   - The security control block (length + type + type meaning) when
//     present — the secure-channel handshake markers SCS_11..SCS_18.
//   - The command (CP->PD) and reply (PD->CP) code with its name.
//   - NAK replies: the error code with its meaning.
//   - Trailer integrity: the CRC-16/AUG-CCITT or checksum is recomputed
//     and reported as valid / invalid.
//   - Typed reply payloads for the codes with a well-defined plaintext
//     layout: osdp_RAW (card-read reader / format / bit-count / card
//     data — the actual badge), osdp_PDID (vendor / model / version /
//     serial / firmware device fingerprint), osdp_COM (address + baud
//     rate), osdp_KEYPAD (PIN key presses) and osdp_LSTATR (tamper +
//     power). Their wire layouts are ported from the libosdp reference
//     reply builder; see payload.go.
//
// # Deliberately deferred
//
//	Command (CP->PD) payload field decode (osdp_LED / BUZ / OUT / TEXT
//	parameters) is not broken out — the data is surfaced as hex and the
//	code name identifies it. Secure-channel-encrypted payloads
//	(SCS_17/18) cannot be decrypted without the session keys and are
//	surfaced as ciphertext.
package osdp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of one OSDP packet.
type Result struct {
	HasMark        bool   `json:"has_mark"`
	AddressByte    string `json:"address_byte"`
	PDAddress      int    `json:"pd_address"`
	Broadcast      bool   `json:"broadcast"`
	Direction      string `json:"direction"` // "command (CP->PD)" / "reply (PD->CP)"
	Length         int    `json:"length"`
	SequenceNumber int    `json:"sequence_number"`
	CheckMode      string `json:"check_mode"` // "crc" / "checksum"

	SecureBlock *SecureBlock `json:"secure_block,omitempty"`

	Code     string `json:"code"`
	CodeName string `json:"code_name"`
	DataHex  string `json:"data_hex,omitempty"`

	NAKError     *int   `json:"nak_error_code,omitempty"`
	NAKErrorName string `json:"nak_error_name,omitempty"`

	// Decoded reply payloads (PD->CP), when the code has a well-defined
	// plaintext layout (ported from the libosdp reference; see payload.go).
	CardRead    *CardRead    `json:"card_read,omitempty"`
	DeviceID    *DeviceID    `json:"device_id,omitempty"`
	ComConfig   *ComConfig   `json:"com_config,omitempty"`
	Keypad      *Keypad      `json:"keypad,omitempty"`
	LocalStatus *LocalStatus `json:"local_status,omitempty"`

	TrailerHex      string `json:"trailer_hex"`
	TrailerComputed string `json:"trailer_computed"`
	TrailerValid    bool   `json:"trailer_valid"`

	Notes []string `json:"notes,omitempty"`
}

// SecureBlock is the decoded security control block.
type SecureBlock struct {
	Length   int    `json:"length"`
	Type     string `json:"type"`
	TypeName string `json:"type_name"`
	DataHex  string `json:"data_hex,omitempty"`
}

// Decode parses one OSDP packet from hex. Accepts an optional leading
// 0xFF driver mark and ':'/'-'/'_'/whitespace separators.
func Decode(hexStr string) (*Result, error) {
	b, err := hex.DecodeString(stripSep(hexStr))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 6 {
		return nil, fmt.Errorf("packet too short (%d bytes; minimum is SOM + address + 2-byte length + control + checksum)", len(b))
	}

	r := &Result{}
	off := 0
	if b[0] == 0xFF {
		r.HasMark = true
		off = 1
	}
	if off+5 > len(b) {
		return nil, fmt.Errorf("truncated header")
	}
	if b[off] != 0x53 {
		return nil, fmt.Errorf("bad start-of-message byte 0x%02X (expected 0x53)", b[off])
	}

	addr := b[off+1]
	r.AddressByte = fmt.Sprintf("0x%02X", addr)
	r.PDAddress = int(addr & 0x7F)
	r.Broadcast = (addr & 0x7F) == 0x7F
	if addr&0x80 != 0 {
		r.Direction = "reply (PD->CP)"
	} else {
		r.Direction = "command (CP->PD)"
	}

	length := int(b[off+2]) | int(b[off+3])<<8
	r.Length = length
	if length < 6 || off+length > len(b) {
		return nil, fmt.Errorf("declared length %d inconsistent with %d available bytes", length, len(b)-off)
	}
	// The frame proper (SOM..trailer), excluding any mark.
	frame := b[off : off+length]

	control := frame[4]
	r.SequenceNumber = int(control & 0x03)
	crcMode := control&0x04 != 0
	trailerLen := 1
	r.CheckMode = "checksum"
	if crcMode {
		trailerLen = 2
		r.CheckMode = "crc"
	}

	pos := 5               // first byte after the control byte, within frame
	if control&0x08 != 0 { // security control block present
		if pos >= len(frame) {
			return nil, fmt.Errorf("truncated security control block")
		}
		sbLen := int(frame[pos])
		if sbLen < 2 || pos+sbLen > len(frame) {
			return nil, fmt.Errorf("invalid security control block length %d", sbLen)
		}
		sb := &SecureBlock{
			Length:   sbLen,
			Type:     fmt.Sprintf("0x%02X", frame[pos+1]),
			TypeName: scbTypeName(frame[pos+1]),
		}
		if sbLen > 2 {
			sb.DataHex = strings.ToUpper(hex.EncodeToString(frame[pos+2 : pos+sbLen]))
		}
		r.SecureBlock = sb
		pos += sbLen
	}

	if pos+trailerLen > len(frame) {
		return nil, fmt.Errorf("no room for command/reply code and trailer")
	}
	code := frame[pos]
	r.Code = fmt.Sprintf("0x%02X", code)
	if addr&0x80 != 0 {
		r.CodeName = replyName(code)
	} else {
		r.CodeName = commandName(code)
	}
	pos++

	dataEnd := len(frame) - trailerLen
	if dataEnd < pos {
		return nil, fmt.Errorf("trailer overlaps header")
	}
	data := frame[pos:dataEnd]
	if len(data) > 0 {
		r.DataHex = strings.ToUpper(hex.EncodeToString(data))
	}
	// NAK reply: the first data byte is the error code.
	if addr&0x80 != 0 && code == 0x41 && len(data) >= 1 {
		ec := int(data[0])
		r.NAKError = &ec
		r.NAKErrorName = nakErrorName(data[0])
	}
	// Typed reply payloads for codes with a well-defined plaintext layout.
	decodePayload(r, code, data, addr&0x80 != 0)

	trailer := frame[dataEnd:]
	r.TrailerHex = strings.ToUpper(hex.EncodeToString(trailer))
	covered := frame[:dataEnd]
	if crcMode {
		want := crc16AugCCITT(covered)
		r.TrailerComputed = fmt.Sprintf("%02X%02X", byte(want), byte(want>>8)) // little-endian
		got := uint16(trailer[0]) | uint16(trailer[1])<<8
		r.TrailerValid = got == want
	} else {
		want := checksum(covered)
		r.TrailerComputed = fmt.Sprintf("%02X", want)
		r.TrailerValid = trailer[0] == want
	}
	if !r.TrailerValid {
		r.Notes = append(r.Notes, "trailer integrity check FAILED (corrupt packet, wrong check mode, or truncated capture)")
	}
	if r.SecureBlock != nil {
		r.Notes = append(r.Notes, "secure-channel packet; an encrypted payload (SCS_17/18) cannot be decrypted without the session keys")
	}
	return r, nil
}

// crc16AugCCITT computes the OSDP trailer CRC (CRC-16/AUG-CCITT:
// polynomial 0x1021, initial value 0x1D0F, no reflection).
func crc16AugCCITT(data []byte) uint16 {
	crc := uint16(0x1D0F)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// checksum is the OSDP 1-byte trailer checksum: the two's complement of
// the 8-bit sum of the covered bytes.
func checksum(data []byte) byte {
	var sum int
	for _, b := range data {
		sum += int(b)
	}
	return byte(^(sum & 0xFF) + 1)
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
