// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wsc decodes Wi-Fi Simple Config (WSC / WPS) credential blobs —
// the TLV structure carried as the `application/vnd.wfa.wsc` MIME type.
//
// This is the payload behind a "tap-to-connect" Wi-Fi NFC tag (an NDEF
// MIME record) and the Credential carried in WPS Registrar protocol
// messages (M7/M8). Decoding it recovers the provisioned network's SSID,
// authentication / encryption types, and — the operative field for a
// pentest — the network key (the PSK). PromptZero's ndef package surfaces
// such a record's MIME type but did not parse the payload; this fills
// that gap and is also exposed standalone (a WPS exchange carries the same
// blob outside NDEF).
//
// Wrap-vs-native: native. The WSC attribute format is a flat sequence of
// big-endian (type:2, length:2, value) TLVs; the Credential attribute
// (0x100E) nests the same TLV grammar. No third-party dependency is
// warranted for fixed binary parsing. The attribute IDs and the
// authentication / encryption flag values are taken verbatim from the
// Wi-Fi Simple Config spec as published in hostap's src/wps/wps_defs.h
// (ATTR_* / WPS_AUTH_* / WPS_ENCR_*) — verified against that source, not
// recalled.
//
// Covered: the Credential attribute and its standard sub-attributes
// (SSID, Authentication Type, Encryption Type, Network Key, MAC Address,
// Network Index), plus any top-level non-Credential attributes surfaced
// raw. Deferred: WSC Version 2 vendor-extension subelements (0x1049 WFA
// vendor extension) are surfaced raw (type + length), not interpreted —
// their internal subelement framing is vendor-specific; and the M7/M8
// encrypted-settings attribute (0x1018) is AES-encrypted under a
// session key we do not have, so it is reported as present-but-encrypted
// rather than guessed at. No confidently-wrong output.
package wsc

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// WSC attribute type IDs (Wi-Fi Simple Config; hostap src/wps/wps_defs.h).
const (
	attrAuthType     = 0x1003
	attrCredential   = 0x100e
	attrEncrType     = 0x100f
	attrEncrSettings = 0x1018
	attrMACAddr      = 0x1020
	attrNetworkIndex = 0x1026
	attrNetworkKey   = 0x1027
	attrVendorExt    = 0x1049
	attrVersion      = 0x104a
	attrSSID         = 0x1045
)

// authFlags maps WPS_AUTH_* bits to names (hostap src/wps/wps.h).
var authFlags = []struct {
	bit  uint16
	name string
}{
	{0x0001, "Open"},
	{0x0002, "WPA-PSK"},
	{0x0004, "Shared"},
	{0x0008, "WPA-Enterprise"},
	{0x0010, "WPA2-Enterprise"},
	{0x0020, "WPA2-PSK"},
}

// encrFlags maps WPS_ENCR_* bits to names (hostap src/wps/wps.h).
var encrFlags = []struct {
	bit  uint16
	name string
}{
	{0x0001, "None"},
	{0x0002, "WEP"},
	{0x0004, "TKIP"},
	{0x0008, "AES"},
}

// Credential is one decoded WSC Credential attribute (a provisioned
// network). NetworkKey is the recovered PSK — the operative field.
type Credential struct {
	SSID          string   `json:"ssid,omitempty"`
	SSIDHex       string   `json:"ssid_hex,omitempty"`
	AuthTypeRaw   uint16   `json:"auth_type_raw"`
	AuthType      []string `json:"auth_type,omitempty"`
	EncrTypeRaw   uint16   `json:"encr_type_raw"`
	EncrType      []string `json:"encr_type,omitempty"`
	NetworkKey    string   `json:"network_key,omitempty"`
	NetworkKeyHex string   `json:"network_key_hex,omitempty"`
	MACAddress    string   `json:"mac_address,omitempty"`
	NetworkIndex  *int     `json:"network_index,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

// RawAttr is a top-level attribute that is not a Credential, surfaced
// without interpretation.
type RawAttr struct {
	Type   string `json:"type"`
	Length int    `json:"length"`
	Value  string `json:"value_hex,omitempty"`
}

// Result is the decoded WSC blob.
type Result struct {
	Credentials []Credential `json:"credentials"`
	OtherAttrs  []RawAttr    `json:"other_attributes,omitempty"`
	Notes       []string     `json:"notes,omitempty"`
}

// DecodeHex decodes a WSC blob supplied as a hex string (':' / '-' /
// whitespace separators ignored).
func DecodeHex(s string) (*Result, error) {
	clean := strings.NewReplacer(":", "", "-", "", " ", "", "\n", "", "\t", "").Replace(s)
	if clean == "" {
		return nil, fmt.Errorf("wsc: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("wsc: invalid hex: %w", err)
	}
	return Decode(b)
}

// Decode walks a WSC attribute blob and returns the decoded credentials.
func Decode(b []byte) (*Result, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("wsc: blob too short (%d bytes; need at least one 4-byte TLV header)", len(b))
	}
	res := &Result{}
	walk(b, func(typ uint16, val []byte) {
		switch typ {
		case attrCredential:
			res.Credentials = append(res.Credentials, decodeCredential(val))
		case attrVersion, attrEncrSettings, attrVendorExt:
			note := ""
			if typ == attrEncrSettings {
				note = " (encrypted settings — AES under a session key not available offline)"
			}
			res.OtherAttrs = append(res.OtherAttrs, RawAttr{
				Type:   fmt.Sprintf("0x%04X%s", typ, note),
				Length: len(val),
				Value:  hex.EncodeToString(val),
			})
		default:
			res.OtherAttrs = append(res.OtherAttrs, RawAttr{
				Type:   fmt.Sprintf("0x%04X", typ),
				Length: len(val),
				Value:  hex.EncodeToString(val),
			})
		}
	})
	if len(res.Credentials) == 0 && len(res.OtherAttrs) == 0 {
		res.Notes = append(res.Notes, "no well-formed WSC attributes found")
	}
	return res, nil
}

// walk iterates (type:2-BE, length:2-BE, value) TLVs, calling fn per
// attribute. A length that runs past the buffer stops the walk (the
// remainder is malformed); partial valid attributes are still reported.
func walk(b []byte, fn func(typ uint16, val []byte)) {
	for off := 0; off+4 <= len(b); {
		typ := binary.BigEndian.Uint16(b[off:])
		l := int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		if off+l > len(b) {
			return
		}
		fn(typ, b[off:off+l])
		off += l
	}
}

func decodeCredential(b []byte) Credential {
	var c Credential
	walk(b, func(typ uint16, val []byte) {
		switch typ {
		case attrSSID:
			c.SSID = string(val)
			c.SSIDHex = hex.EncodeToString(val)
		case attrAuthType:
			if len(val) == 2 {
				c.AuthTypeRaw = binary.BigEndian.Uint16(val)
				c.AuthType = decodeFlags(c.AuthTypeRaw, authFlags)
			} else {
				c.Notes = append(c.Notes, fmt.Sprintf("auth-type attribute has %d bytes, expected 2", len(val)))
			}
		case attrEncrType:
			if len(val) == 2 {
				c.EncrTypeRaw = binary.BigEndian.Uint16(val)
				c.EncrType = decodeFlags(c.EncrTypeRaw, encrFlags)
			} else {
				c.Notes = append(c.Notes, fmt.Sprintf("encr-type attribute has %d bytes, expected 2", len(val)))
			}
		case attrNetworkKey:
			c.NetworkKey = string(val)
			c.NetworkKeyHex = hex.EncodeToString(val)
		case attrMACAddr:
			if len(val) == 6 {
				c.MACAddress = formatMAC(val)
			} else {
				c.Notes = append(c.Notes, fmt.Sprintf("mac-address attribute has %d bytes, expected 6", len(val)))
			}
		case attrNetworkIndex:
			if len(val) == 1 {
				idx := int(val[0])
				c.NetworkIndex = &idx
			}
		}
	})
	return c
}

// decodeFlags expands a bitmask into the names of the set bits, noting any
// bits outside the documented set rather than dropping them silently.
func decodeFlags(v uint16, table []struct {
	bit  uint16
	name string
}) []string {
	var out []string
	known := uint16(0)
	for _, f := range table {
		if v&f.bit != 0 {
			out = append(out, f.name)
		}
		known |= f.bit
	}
	if extra := v &^ known; extra != 0 {
		out = append(out, fmt.Sprintf("unknown(0x%04X)", extra))
	}
	return out
}

func formatMAC(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}
