// eddystone.go — Google Eddystone BLE-beacon dissector. Service
// UUID 0xFEAA; frame types UID / URL / TLM / EID per the open
// specification at https://github.com/google/eddystone.
//
// Wrap-vs-native judgement: Eddystone is a fully open public spec
// — the frame layouts and URL-encoding tables are published in
// google/eddystone's protocol-specification.md files. The decoder
// is a one-byte frame-type switch over a service-data payload.
// Wrapping a FAP for this would add an SD-card install step + a
// firmware-fork dependency for a pure parser. We implement
// natively so operators can paste a service-data hex blob from
// btmon / Wireshark / NRF Connect and decode the frame without a
// Flipper attached.
//
// Pairs with Decode (the Apple Continuity walker). Together they
// cover the two highest-volume open BLE beacon catalogs: Apple's
// manufacturer-data set and Google's service-data set.

package ble

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// EddystoneServiceUUID is the 16-bit UUID Google assigned to
// Eddystone. Service-data fields prefixed with this UUID carry
// Eddystone frames.
const EddystoneServiceUUID uint16 = 0xFEAA

// EddystoneFrameType enumerates the four documented frame types.
type EddystoneFrameType byte

const (
	// FrameUID — 16-byte beacon ID (10-byte namespace + 6-byte
	// instance). 18-byte total payload.
	FrameUID EddystoneFrameType = 0x00
	// FrameURL — encoded URL up to ~17 bytes after the scheme
	// byte. Variable-length payload.
	FrameURL EddystoneFrameType = 0x10
	// FrameTLM — telemetry: battery voltage, temperature, advert
	// count, time-since-boot. 14-byte payload.
	FrameTLM EddystoneFrameType = 0x20
	// FrameEID — Ephemeral ID (rotating 8-byte token, requires
	// a server-side key to resolve). 10-byte payload.
	FrameEID EddystoneFrameType = 0x30
)

// Eddystone is the top-level decode result.
type Eddystone struct {
	// FrameType is the frame-type byte at offset 0 of the
	// service-data payload.
	FrameType int `json:"frame_type"`
	// FrameTypeHex is the operator-facing hex form ("00", "10",
	// "20", "30").
	FrameTypeHex string `json:"frame_type_hex"`
	// FrameName is the canonical name ("UID", "URL", "TLM",
	// "EID") or "Unknown" for out-of-catalog types.
	FrameName string `json:"frame_name"`
	// Fields carries the decoded per-frame-type fields. Nil for
	// unknown types or when DecodeWarning is set.
	Fields map[string]any `json:"fields,omitempty"`
	// Hex is the operator-facing hex rendering of the full
	// service-data payload (including the frame-type byte).
	Hex string `json:"hex"`
	// DecodeWarning is non-empty when the payload is shorter than
	// the documented minimum for its frame type. The frame type
	// and raw hex are still surfaced.
	DecodeWarning string `json:"decode_warning,omitempty"`
}

// DecodeEddystone parses a hex-encoded Eddystone service-data
// payload. Three input shapes are accepted; the parser strips any
// recognised prefix:
//
//   - Bare service data: 10 02 00 03 67 6F 6F (URL frame for "goo")
//   - With UUID prefix:  AA FE 10 02 00 03 67 6F 6F
//   - Full AD structure: 0A 16 AA FE 10 02 00 03 67 6F 6F
//
// (AD-type 0x16 = ServiceData16Bit; the UUID 0xFEAA is
// little-endian on the wire as AA FE.)
//
// Separators (':' '-' '_' whitespace) are tolerated.
func DecodeEddystone(hexBlob string) (Eddystone, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Eddystone{}, fmt.Errorf("ble: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Eddystone{}, fmt.Errorf("ble: invalid hex: %w", err)
	}
	body := stripEddystonePrefix(b)
	if len(body) == 0 {
		return Eddystone{}, fmt.Errorf("ble: Eddystone payload empty after prefix strip")
	}
	return decodeEddystoneBody(body), nil
}

// stripEddystonePrefix detects the optional AA FE service-UUID
// prefix and the optional full-AD-structure wrapper, returning the
// frame body.
//
// AD-structure shape: 1-byte length (count of bytes that follow
// including the AD type), 1-byte AD type 0x16 (ServiceData16Bit),
// 2-byte little-endian UUID AA FE, payload.
func stripEddystonePrefix(b []byte) []byte {
	// Full AD structure: <len> 16 AA FE ...
	if len(b) >= 4 && b[1] == 0x16 && b[2] == 0xAA && b[3] == 0xFE {
		declared := int(b[0])
		if 1+declared <= len(b) {
			return b[4 : 1+declared]
		}
	}
	// UUID only: AA FE ...
	if len(b) >= 2 && b[0] == 0xAA && b[1] == 0xFE {
		return b[2:]
	}
	return b
}

// decodeEddystoneBody dispatches on the frame-type byte and
// returns the structured result. Unknown frame types still get a
// Name="Unknown" entry with raw hex so operators can flag novel
// formats.
func decodeEddystoneBody(b []byte) Eddystone {
	t := b[0]
	out := Eddystone{
		FrameType:    int(t),
		FrameTypeHex: fmt.Sprintf("%02X", t),
		FrameName:    eddystoneFrameName(t),
		Hex:          strings.ToUpper(hex.EncodeToString(b)),
	}
	body := b[1:]
	switch t {
	case byte(FrameUID):
		out.Fields, out.DecodeWarning = decodeEddystoneUID(body)
	case byte(FrameURL):
		out.Fields, out.DecodeWarning = decodeEddystoneURL(body)
	case byte(FrameTLM):
		out.Fields, out.DecodeWarning = decodeEddystoneTLM(body)
	case byte(FrameEID):
		out.Fields, out.DecodeWarning = decodeEddystoneEID(body)
	}
	return out
}

// eddystoneFrameName maps the frame-type byte to its canonical
// name per the Eddystone spec.
func eddystoneFrameName(t byte) string {
	switch EddystoneFrameType(t) {
	case FrameUID:
		return "UID"
	case FrameURL:
		return "URL"
	case FrameTLM:
		return "TLM"
	case FrameEID:
		return "EID"
	}
	return "Unknown"
}

// decodeEddystoneUID parses a UID frame. Layout (after the
// frame-type byte):
//
//	tx_power:1 + namespace:10 + instance:6 + reserved:2
//
// Total 18 bytes; reserved trailing bytes may be absent on some
// implementations (we accept ≥17 = tx_power + 16-byte ID).
func decodeEddystoneUID(b []byte) (map[string]any, string) {
	if len(b) < 17 {
		return nil, fmt.Sprintf("UID payload %d bytes; want ≥17 (tx_power + 10-byte namespace + 6-byte instance)", len(b))
	}
	fields := map[string]any{
		"tx_power_dbm": int(int8(b[0])),
		"namespace":    hexString(b[1:11]),
		"instance":     hexString(b[11:17]),
	}
	if len(b) >= 19 {
		fields["reserved"] = hexString(b[17:19])
	}
	return fields, ""
}

// urlSchemes maps the scheme-prefix byte to its URL prefix per
// the Eddystone-URL spec.
var urlSchemes = [4]string{
	"http://www.",
	"https://www.",
	"http://",
	"https://",
}

// urlExpansions maps the URL-encoding-table bytes (0x00-0x0D) to
// their TLD expansions. 0x0E-0x20 and 0x7F-0xFF are reserved; all
// other bytes are passed through as ASCII.
var urlExpansions = map[byte]string{
	0x00: ".com/",
	0x01: ".org/",
	0x02: ".edu/",
	0x03: ".net/",
	0x04: ".info/",
	0x05: ".biz/",
	0x06: ".gov/",
	0x07: ".com",
	0x08: ".org",
	0x09: ".edu",
	0x0A: ".net",
	0x0B: ".info",
	0x0C: ".biz",
	0x0D: ".gov",
}

// decodeEddystoneURL parses a URL frame. Layout (after the
// frame-type byte):
//
//	tx_power:1 + scheme:1 + encoded_url:variable
//
// Returns the decoded URL string plus the scheme byte and tx
// power. Reserved bytes (0x0E-0x20, 0x7F-0xFF) are surfaced in a
// warnings list rather than silently dropped.
func decodeEddystoneURL(b []byte) (map[string]any, string) {
	if len(b) < 2 {
		return nil, fmt.Sprintf("URL payload %d bytes; want ≥2 (tx_power + scheme)", len(b))
	}
	scheme := b[1]
	if int(scheme) >= len(urlSchemes) {
		return map[string]any{
			"tx_power_dbm": int(int8(b[0])),
			"scheme":       int(scheme),
			"encoded_hex":  hexString(b[2:]),
		}, fmt.Sprintf("URL scheme byte 0x%02X out of documented range (0x00-0x03)", scheme)
	}
	var sb strings.Builder
	sb.WriteString(urlSchemes[scheme])
	var reserved []string
	for i, c := range b[2:] {
		if exp, ok := urlExpansions[c]; ok {
			sb.WriteString(exp)
			continue
		}
		// Reserved ranges per the spec.
		if c <= 0x20 || c == 0x7F || c >= 0x80 {
			reserved = append(reserved, fmt.Sprintf("offset %d: 0x%02X", i, c))
			continue
		}
		sb.WriteByte(c)
	}
	fields := map[string]any{
		"tx_power_dbm": int(int8(b[0])),
		"scheme":       int(scheme),
		"scheme_name":  urlSchemes[scheme],
		"url":          sb.String(),
	}
	if len(reserved) > 0 {
		fields["reserved_bytes"] = reserved
	}
	return fields, ""
}

// decodeEddystoneTLM parses a TLM (telemetry) frame. Layout
// (after the frame-type byte):
//
//	version:1 + battery_mV:2 + temperature_8.8:2 +
//	  adv_count:4 + sec_since_boot_100ms:4
//
// Total 13 bytes (so 14 including the frame-type byte). Version
// 0x00 is the unencrypted form documented in the spec. Version
// 0x01 (eTLM, encrypted telemetry) is recognised by name but not
// dissected — its body is AES-encrypted.
func decodeEddystoneTLM(b []byte) (map[string]any, string) {
	if len(b) < 13 {
		return nil, fmt.Sprintf("TLM payload %d bytes; want ≥13", len(b))
	}
	version := b[0]
	if version == 0x01 {
		return map[string]any{
			"version":        int(version),
			"version_name":   "eTLM (encrypted)",
			"encrypted_body": hexString(b[1:]),
		}, ""
	}
	battery := binary.BigEndian.Uint16(b[1:3])
	tempRaw := int16(binary.BigEndian.Uint16(b[3:5]))
	// 8.8 signed fixed point — divide by 256.
	tempC := float64(tempRaw) / 256.0
	advCount := binary.BigEndian.Uint32(b[5:9])
	sec100ms := binary.BigEndian.Uint32(b[9:13])
	return map[string]any{
		"version":         int(version),
		"battery_mv":      int(battery),
		"temperature_c":   tempC,
		"temperature_raw": int(tempRaw),
		"adv_count":       int(advCount),
		"uptime_100ms":    int(sec100ms),
		"uptime_seconds":  float64(sec100ms) / 10.0,
	}, ""
}

// decodeEddystoneEID parses an EID (ephemeral ID) frame. Layout
// (after the frame-type byte):
//
//	tx_power:1 + ephemeral_id:8
//
// The EID is a server-resolvable rotating token; we surface it as
// hex without attempting to decrypt (the spec's resolution
// protocol requires a per-beacon identity key the operator owns
// out-of-band).
func decodeEddystoneEID(b []byte) (map[string]any, string) {
	if len(b) < 9 {
		return nil, fmt.Sprintf("EID payload %d bytes; want ≥9 (tx_power + 8-byte EID)", len(b))
	}
	return map[string]any{
		"tx_power_dbm": int(int8(b[0])),
		"ephemeral_id": hexString(b[1:9]),
	}, ""
}
