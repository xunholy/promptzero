// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wps decodes the Wi-Fi Simple Configuration (WPS) data elements
// carried in the WPS vendor-specific Information Element of 802.11 beacons
// and probe responses (Microsoft OUI 00:50:F2, vendor type 0x04).
//
// # Wrap-vs-native judgement
//
// Native. The WSC attribute format is a public, fully-deterministic
// TLV — a 2-byte big-endian attribute type, a 2-byte big-endian length,
// then the value — documented in the Wi-Fi Simple Configuration Technical
// Specification and implemented identically by hostapd, wpa_supplicant,
// reaver, bully and wash. Decoding is a short walker over a byte slice with
// a static attribute-ID table; no crypto, no hardware, no SDR. The existing
// internal/ieee80211 vendor-IE decoder already identifies the WPS IE but
// leaves its body as opaque hex — this turns that body into the recon
// fields an operator needs to triage WPS attack surface: the protocol
// version, whether the AP is setup-locked (reaver/bully are useless against
// a locked AP), the active Device Password ID and config methods (PIN vs
// push-button), and the device identity strings.
//
// # No confidently-wrong output
//
// Only attribute IDs and enumerated values documented in the WSC spec are
// named; any unknown attribute type or out-of-range enum value is surfaced
// with its raw hex and numeric type rather than guessed. A truncated TLV
// stops the walk with the attributes parsed so far plus a note.
//
// # Deliberately deferred
//
// The WSC Vendor Extension subelements (attribute 0x1049 — Version2 etc.)
// are surfaced as raw hex rather than recursed into, and the cryptographic
// registration-protocol attributes (Enrollee/Registrar nonces, public keys,
// E-Hash/E-SNonce) are not interpreted — they appear only in the EAP-WSC
// exchange, not the beacon/probe IE this package targets, and carry no
// recon value decoded.
package wps

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Attribute is one decoded WSC data element.
type Attribute struct {
	Type     int    `json:"type"`              // 16-bit attribute ID
	TypeHex  string `json:"type_hex"`          // "0x104A"
	Name     string `json:"name"`              // canonical name, or "Unknown"
	Length   int    `json:"length"`            // value length in bytes
	ValueHex string `json:"value_hex"`         // raw value as hex
	Decoded  any    `json:"decoded,omitempty"` // interpreted value for known attributes
}

// WSC is the decoded view of a WPS information-element body.
type WSC struct {
	Attributes []Attribute `json:"attributes"`
	Count      int         `json:"count"`
	// Summary lifts the recon-relevant fields to the top level so an
	// operator can triage at a glance.
	Version          string   `json:"version,omitempty"`
	SetupState       string   `json:"setup_state,omitempty"`
	APSetupLocked    *bool    `json:"ap_setup_locked,omitempty"`
	DevicePasswordID string   `json:"device_password_id,omitempty"`
	DeviceName       string   `json:"device_name,omitempty"`
	Manufacturer     string   `json:"manufacturer,omitempty"`
	ModelName        string   `json:"model_name,omitempty"`
	Notes            []string `json:"notes,omitempty"`
}

// WSC attribute IDs (Wi-Fi Simple Configuration Technical Specification).
const (
	attrConfigMethods     = 0x1008
	attrDeviceName        = 0x1011
	attrDevicePasswordID  = 0x1012
	attrManufacturer      = 0x1021
	attrModelName         = 0x1023
	attrModelNumber       = 0x1024
	attrPrimaryDevType    = 0x1054
	attrRFBands           = 0x103C
	attrResponseType      = 0x103B
	attrSelectedRegistrar = 0x1041
	attrSerialNumber      = 0x1042
	attrSetupState        = 0x1044
	attrUUIDE             = 0x1047
	attrVendorExtension   = 0x1049
	attrVersion           = 0x104A
	attrSelRegConfig      = 0x1053
	attrAPSetupLocked     = 0x1057
)

var attrNames = map[int]string{
	attrConfigMethods:     "Config Methods",
	attrDeviceName:        "Device Name",
	attrDevicePasswordID:  "Device Password ID",
	attrManufacturer:      "Manufacturer",
	attrModelName:         "Model Name",
	attrModelNumber:       "Model Number",
	attrPrimaryDevType:    "Primary Device Type",
	attrRFBands:           "RF Bands",
	attrResponseType:      "Response Type",
	attrSelectedRegistrar: "Selected Registrar",
	attrSerialNumber:      "Serial Number",
	attrSetupState:        "Wi-Fi Protected Setup State",
	attrUUIDE:             "UUID-E",
	attrVendorExtension:   "Vendor Extension",
	attrVersion:           "Version",
	attrSelRegConfig:      "Selected Registrar Config Methods",
	attrAPSetupLocked:     "AP Setup Locked",
}

// configMethodBits maps Config-Methods bitmask bits to names (WSC spec).
var configMethodBits = []struct {
	bit  uint16
	name string
}{
	{0x0001, "USBA"},
	{0x0002, "Ethernet"},
	{0x0004, "Label"},
	{0x0008, "Display"},
	{0x0010, "External NFC Token"},
	{0x0020, "Integrated NFC Token"},
	{0x0040, "NFC Interface"},
	{0x0080, "Push Button"},
	{0x0100, "Keypad"},
	{0x0280, "Virtual Push Button"},
	{0x0480, "Physical Push Button"},
	{0x2008, "Virtual Display PIN"},
	{0x4008, "Physical Display PIN"},
}

var devicePasswordIDs = map[uint16]string{
	0x0000: "Default (PIN)",
	0x0001: "User-specified",
	0x0002: "Machine-specified",
	0x0003: "Rekey",
	0x0004: "PushButton",
	0x0005: "Registrar-specified",
}

// Decode parses a hex-encoded WPS IE body into its WSC attributes. The
// input may be the bare WSC attribute stream, the manufacturer payload
// prefixed with the OUI+type (00 50 F2 04 …), or the full vendor-specific
// Information Element (DD <len> 00 50 F2 04 …); the recognised prefix is
// stripped.
func Decode(hexStr string) (*WSC, error) {
	b, err := parseHex(hexStr)
	if err != nil {
		return nil, err
	}
	b = stripWPSPrefix(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("wps: empty WSC data after prefix stripping")
	}
	return DecodeBytes(b)
}

// DecodeBytes walks a bare WSC attribute stream.
func DecodeBytes(b []byte) (*WSC, error) {
	out := &WSC{}
	for i := 0; i+4 <= len(b); {
		typ := int(binary.BigEndian.Uint16(b[i : i+2]))
		ln := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+ln > len(b) {
			out.Notes = append(out.Notes,
				fmt.Sprintf("attribute 0x%04X declares %d bytes; only %d remain — stopping", typ, ln, len(b)-i))
			break
		}
		val := b[i : i+ln]
		i += ln
		a := Attribute{
			Type:     typ,
			TypeHex:  fmt.Sprintf("0x%04X", typ),
			Name:     attrName(typ),
			Length:   ln,
			ValueHex: strings.ToUpper(hex.EncodeToString(val)),
		}
		a.Decoded = decodeAttr(typ, val, out)
		out.Attributes = append(out.Attributes, a)
	}
	out.Count = len(out.Attributes)
	if out.Count == 0 {
		out.Notes = append(out.Notes, "no complete WSC attribute parsed")
	}
	return out, nil
}

func attrName(typ int) string {
	if n, ok := attrNames[typ]; ok {
		return n
	}
	return "Unknown"
}

// decodeAttr interprets the value of a known attribute and lifts
// recon-relevant fields into the WSC summary. Unknown or malformed values
// return nil (the raw hex is always retained on the Attribute).
func decodeAttr(typ int, val []byte, out *WSC) any {
	switch typ {
	case attrVersion:
		if len(val) == 1 {
			v := fmt.Sprintf("%d.%d", val[0]>>4, val[0]&0x0F)
			out.Version = v
			return v
		}
	case attrSetupState:
		if len(val) == 1 {
			s := map[byte]string{0x01: "Not Configured", 0x02: "Configured"}[val[0]]
			if s == "" {
				s = fmt.Sprintf("Reserved (0x%02X)", val[0])
			}
			out.SetupState = s
			return s
		}
	case attrAPSetupLocked:
		if len(val) == 1 {
			locked := val[0] == 0x01
			out.APSetupLocked = &locked
			return locked
		}
	case attrSelectedRegistrar:
		if len(val) == 1 {
			return val[0] == 0x01
		}
	case attrDevicePasswordID:
		if len(val) == 2 {
			id := binary.BigEndian.Uint16(val)
			name := devicePasswordIDs[id]
			if name == "" {
				name = fmt.Sprintf("0x%04X", id)
			}
			out.DevicePasswordID = name
			return name
		}
	case attrConfigMethods, attrSelRegConfig:
		if len(val) == 2 {
			return decodeConfigMethods(binary.BigEndian.Uint16(val))
		}
	case attrRFBands:
		if len(val) == 1 {
			return decodeRFBands(val[0])
		}
	case attrUUIDE:
		if len(val) == 16 {
			return strings.ToUpper(hex.EncodeToString(val))
		}
	case attrDeviceName:
		s := string(val)
		out.DeviceName = s
		return s
	case attrManufacturer:
		s := string(val)
		out.Manufacturer = s
		return s
	case attrModelName:
		s := string(val)
		out.ModelName = s
		return s
	case attrModelNumber, attrSerialNumber:
		return string(val)
	case attrPrimaryDevType:
		if len(val) == 8 {
			return fmt.Sprintf("category %d", binary.BigEndian.Uint16(val[0:2]))
		}
	}
	return nil
}

func decodeConfigMethods(mask uint16) []string {
	var methods []string
	for _, m := range configMethodBits {
		if mask&m.bit == m.bit {
			methods = append(methods, m.name)
		}
	}
	if methods == nil {
		return []string{fmt.Sprintf("none (0x%04X)", mask)}
	}
	return methods
}

func decodeRFBands(b byte) []string {
	var bands []string
	if b&0x01 != 0 {
		bands = append(bands, "2.4GHz")
	}
	if b&0x02 != 0 {
		bands = append(bands, "5GHz")
	}
	if b&0x04 != 0 {
		bands = append(bands, "60GHz")
	}
	if bands == nil {
		return []string{fmt.Sprintf("0x%02X", b)}
	}
	return bands
}

// stripWPSPrefix removes the full vendor-IE header or the OUI+type prefix
// if present, returning the bare WSC attribute stream.
func stripWPSPrefix(b []byte) []byte {
	// Full vendor-specific IE: DD <len> 00 50 F2 04 <wsc...>
	if len(b) >= 6 && b[0] == 0xDD && b[2] == 0x00 && b[3] == 0x50 && b[4] == 0xF2 {
		end := 2 + int(b[1])
		if end > len(b) {
			end = len(b)
		}
		body := b[2:end]
		// body = OUI(3) + type(1) + wsc
		if len(body) >= 4 {
			return body[4:]
		}
		return nil
	}
	// Manufacturer payload: 00 50 F2 04 <wsc...>
	if len(b) >= 4 && b[0] == 0x00 && b[1] == 0x50 && b[2] == 0xF2 && b[3] == 0x04 {
		return b[4:]
	}
	return b
}

func parseHex(s string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(s))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("wps: empty hex input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("wps: invalid hex: %w", err)
	}
	return b, nil
}
