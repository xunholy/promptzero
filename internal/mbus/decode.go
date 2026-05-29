// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mbus decodes M-Bus (Meter-Bus, EN 13757-2 link layer +
// EN 13757-3 application layer) frames — the European smart-metering
// protocol for electricity, gas, water, heat, and warm-water meters.
// The wired M-Bus link/application layers are shared with Wireless
// M-Bus (wM-Bus, 868 MHz), which a Flipper Sub-GHz capture can lift
// off the air; pasting the demodulated bytes here decodes the meter
// identity and command without a dedicated M-Bus master.
//
// # Wrap-vs-native judgement
//
// Native. M-Bus is defined by the public EN 13757 standard. The link
// layer is one of four fixed framings (single-character ACK, short,
// control, long), each a byte-counted structure with a trailing
// checksum and 0x16 stop byte. The application layer's Variable Data
// Structure carries a fixed header (BCD serial number, FLAG-encoded
// manufacturer, version, medium/device type, access number, status,
// signature) before the DIF/VIF data records. Every field is a
// fixed-format byte stream; dispatch is a set of small lookup tables.
//
// # What this package covers
//
//   - Link-layer frame classification: single-character ACK (0xE5),
//     short frame (0x10 ... 0x16), control frame (0x68 L L 0x68 ...
//     0x16 with L==3), long frame (0x68 L L 0x68 ... 0x16).
//   - L-field consistency (the two length bytes must match) and
//     total-length validation against the buffer.
//   - Checksum verification (arithmetic sum of C..end-of-user-data
//     mod 256) and the 0x16 stop byte.
//   - C-field (Control) function naming (SND_NKE, SND_UD, REQ_UD1,
//     REQ_UD2, RSP_UD, ACK) plus the master↔slave direction bit.
//   - A-field (Address) value plus classification (unconfigured /
//     primary / secondary-addressing / broadcast-no-reply /
//     broadcast-all-reply / reserved).
//   - CI-field (Control Information) application-selector naming.
//   - Variable Data Structure fixed header (CI 0x72 long 12-byte /
//     CI 0x7A short 4-byte): BCD identification (serial) number,
//     FLAG-encoded 3-letter manufacturer, version, medium/device
//     type with a name table, access number, status byte, signature.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - DIF/VIF data-record decoding (the metering values themselves):
//     the DIF data-field-coding × VIF unit/multiplier matrix is a
//     substantial separate walker. The raw data-record bytes are
//     surfaced so the operator can compare against EN 13757-3 §6.
//   - wM-Bus radio framing (mode S/T/C, 3-of-6 / Manchester line
//     coding, block-wise CRC): feed already-demodulated/de-coded
//     application bytes here.
//   - Encrypted application data (Mode 5 AES-CBC / Mode 7/9/13):
//     the status/configuration field is surfaced but the ciphertext
//     is not decrypted.
package mbus

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Frame is the decoded view of an M-Bus telegram.
type Frame struct {
	HexInput       string     `json:"hex_input"`
	FrameType      string     `json:"frame_type"`
	LengthField    *int       `json:"length_field,omitempty"`
	CField         *int       `json:"c_field,omitempty"`
	CFieldName     string     `json:"c_field_name,omitempty"`
	Direction      string     `json:"direction,omitempty"`
	AField         *int       `json:"a_field,omitempty"`
	AddressType    string     `json:"address_type,omitempty"`
	CIField        *int       `json:"ci_field,omitempty"`
	CIFieldName    string     `json:"ci_field_name,omitempty"`
	Header         *VDSHeader `json:"variable_data_header,omitempty"`
	DataRecordsHex string     `json:"data_records_hex,omitempty"`
	ChecksumValid  *bool      `json:"checksum_valid,omitempty"`
	Notes          []string   `json:"notes,omitempty"`
}

// VDSHeader is the fixed header of a Variable Data Structure response
// (the part before the DIF/VIF data records).
type VDSHeader struct {
	HeaderType     string `json:"header_type"`
	SerialNumber   string `json:"serial_number,omitempty"`
	Manufacturer   string `json:"manufacturer,omitempty"`
	ManufacturerID *int   `json:"manufacturer_id,omitempty"`
	Version        *int   `json:"version,omitempty"`
	Medium         *int   `json:"medium,omitempty"`
	MediumName     string `json:"medium_name,omitempty"`
	AccessNumber   int    `json:"access_number"`
	Status         int    `json:"status"`
	SignatureHex   string `json:"signature_hex,omitempty"`
}

// Decode parses a hex-encoded M-Bus telegram.
func Decode(hexBlob string) (*Frame, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw M-Bus telegram.
func DecodeBytes(b []byte) (*Frame, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("mbus: empty frame")
	}
	f := &Frame{HexInput: strings.ToUpper(hex.EncodeToString(b))}

	switch b[0] {
	case 0xE5:
		f.FrameType = "ACK (single character)"
		if len(b) != 1 {
			f.Notes = append(f.Notes,
				fmt.Sprintf("single-character ACK should be 1 byte; got %d", len(b)))
		}
		return f, nil
	case 0x10:
		return decodeShortFrame(b, f)
	case 0x68:
		return decodeLongOrControlFrame(b, f)
	default:
		return nil, fmt.Errorf("mbus: unrecognised start byte 0x%02X (want 0xE5 / 0x10 / 0x68)", b[0])
	}
}

// decodeShortFrame handles the 5-byte short frame:
// 0x10 [C] [A] [checksum] 0x16.
func decodeShortFrame(b []byte, f *Frame) (*Frame, error) {
	f.FrameType = "short"
	if len(b) != 5 {
		return nil, fmt.Errorf("mbus: short frame must be 5 bytes, got %d", len(b))
	}
	if b[4] != 0x16 {
		return nil, fmt.Errorf("mbus: short frame missing 0x16 stop byte (got 0x%02X)", b[4])
	}
	c, a := int(b[1]), int(b[2])
	f.setCField(c)
	f.setAField(a)
	want := (c + a) & 0xFF
	valid := want == int(b[3])
	f.ChecksumValid = &valid
	if !valid {
		f.Notes = append(f.Notes,
			fmt.Sprintf("checksum 0x%02X != computed 0x%02X", b[3], want))
	}
	return f, nil
}

// decodeLongOrControlFrame handles both the control frame (L==3) and
// the long frame: 0x68 [L] [L] 0x68 [C] [A] [CI] [user data] [chk] 0x16.
func decodeLongOrControlFrame(b []byte, f *Frame) (*Frame, error) {
	if len(b) < 6 {
		return nil, fmt.Errorf("mbus: long/control frame truncated (%d bytes)", len(b))
	}
	l1, l2 := int(b[1]), int(b[2])
	if l1 != l2 {
		return nil, fmt.Errorf("mbus: the two L-fields differ (0x%02X vs 0x%02X)", l1, l2)
	}
	if b[3] != 0x68 {
		return nil, fmt.Errorf("mbus: second start byte = 0x%02X; want 0x68", b[3])
	}
	lf := l1
	f.LengthField = &lf
	// Total frame = 4 (header) + L (C+A+CI+data) + 2 (checksum+stop).
	wantTotal := 4 + lf + 2
	if wantTotal != len(b) {
		return nil, fmt.Errorf(
			"mbus: L-field implies %d-byte frame but buffer is %d bytes", wantTotal, len(b))
	}
	if b[len(b)-1] != 0x16 {
		return nil, fmt.Errorf("mbus: frame missing 0x16 stop byte (got 0x%02X)", b[len(b)-1])
	}
	if lf < 3 {
		return nil, fmt.Errorf("mbus: L-field %d below the 3-byte C+A+CI minimum", lf)
	}

	if lf == 3 {
		f.FrameType = "control"
	} else {
		f.FrameType = "long"
	}

	// User-data block is b[4 : 4+lf]; checksum is b[4+lf].
	udStart := 4
	udEnd := 4 + lf
	c := int(b[udStart])
	a := int(b[udStart+1])
	ci := int(b[udStart+2])
	f.setCField(c)
	f.setAField(a)
	f.CIField = &ci
	f.CIFieldName = ciFieldName(ci)

	// Checksum over the user-data block (C..last data byte).
	sum := 0
	for i := udStart; i < udEnd; i++ {
		sum += int(b[i])
	}
	sum &= 0xFF
	valid := sum == int(b[udEnd])
	f.ChecksumValid = &valid
	if !valid {
		f.Notes = append(f.Notes,
			fmt.Sprintf("checksum 0x%02X != computed 0x%02X", b[udEnd], sum))
	}

	// Application payload begins after the CI field.
	payload := b[udStart+3 : udEnd]
	if hdr, rest := decodeVDSHeader(ci, payload); hdr != nil {
		f.Header = hdr
		if len(rest) > 0 {
			f.DataRecordsHex = strings.ToUpper(hex.EncodeToString(rest))
		}
	} else if len(payload) > 0 {
		f.DataRecordsHex = strings.ToUpper(hex.EncodeToString(payload))
	}
	return f, nil
}

// decodeVDSHeader decodes the Variable Data Structure fixed header for
// the CI fields that carry one (0x72 long 12-byte, 0x7A short 4-byte),
// returning the header and the remaining data-record bytes. Returns
// (nil, nil) when the CI field carries no such header or the payload
// is too short.
func decodeVDSHeader(ci int, p []byte) (*VDSHeader, []byte) {
	switch ci {
	case 0x72, 0x76:
		// Long header: 4 (ident) + 2 (manufacturer) + 1 (version) +
		// 1 (medium) + 1 (access) + 1 (status) + 2 (signature) = 12.
		if len(p) < 12 {
			return nil, nil
		}
		man := int(p[4]) | int(p[5])<<8
		ver := int(p[6])
		med := int(p[7])
		h := &VDSHeader{
			HeaderType:     "long (12-byte)",
			SerialNumber:   bcdLE(p[0:4]),
			Manufacturer:   manufacturerCode(man),
			ManufacturerID: &man,
			Version:        &ver,
			Medium:         &med,
			MediumName:     mediumName(med),
			AccessNumber:   int(p[8]),
			Status:         int(p[9]),
			SignatureHex:   strings.ToUpper(hex.EncodeToString(p[10:12])),
		}
		return h, p[12:]
	case 0x7A:
		// Short header: 1 (access) + 1 (status) + 2 (signature) = 4.
		if len(p) < 4 {
			return nil, nil
		}
		h := &VDSHeader{
			HeaderType:   "short (4-byte)",
			AccessNumber: int(p[0]),
			Status:       int(p[1]),
			SignatureHex: strings.ToUpper(hex.EncodeToString(p[2:4])),
		}
		return h, p[4:]
	default:
		return nil, nil
	}
}

func (f *Frame) setCField(c int) {
	f.CField = &c
	f.CFieldName = cFieldName(c)
	f.Direction = cFieldDirection(c)
}

func (f *Frame) setAField(a int) {
	f.AField = &a
	f.AddressType = addressType(a)
}

// bcdLE renders a little-endian BCD byte sequence (least-significant
// byte first) as a decimal string, most-significant digit first. A
// nibble outside 0-9 is rendered as a hex digit so a non-BCD field
// (e.g. an all-FF wildcard serial) still produces readable output.
func bcdLE(b []byte) string {
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%02X", b[i])
	}
	return sb.String()
}

// manufacturerCode decodes the FLAG-association 3-letter manufacturer
// code packed into a 16-bit field (5 bits per letter, +64 offset).
func manufacturerCode(man int) string {
	c1 := (man>>10)&0x1F + 64
	c2 := (man>>5)&0x1F + 64
	c3 := man&0x1F + 64
	if c1 < 'A' || c1 > 'Z' || c2 < 'A' || c2 > 'Z' || c3 < 'A' || c3 > 'Z' {
		return ""
	}
	return string([]byte{byte(c1), byte(c2), byte(c3)})
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("mbus: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("mbus: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
