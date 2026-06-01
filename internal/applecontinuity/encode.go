// SPDX-License-Identifier: AGPL-3.0-or-later

package applecontinuity

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// EncodeRequest describes one Apple Continuity message to build. Kind
// selects the message type. Currently "ibeacon" (type 0x02) is supported
// — the one Continuity message whose body is a fully deterministic,
// non-cryptographic, public layout.
type EncodeRequest struct {
	Kind string `json:"kind"`

	// iBeacon fields (kind=ibeacon).
	UUID    string `json:"uuid,omitempty"`
	Major   uint16 `json:"major,omitempty"`
	Minor   uint16 `json:"minor,omitempty"`
	TXPower int8   `json:"tx_power_dbm,omitempty"`

	// Wrap controls the framing of the returned bytes:
	//   "" / "tlv"       — the bare Continuity TLV (type, length, body);
	//                      the default.
	//   "manufacturer"   — prefixed with the 0x4C 0x00 Apple Company ID
	//                      (the manufacturer-data payload).
	//   "ad"             — the full advertising-data record
	//                      (<len>, 0xFF, 0x4C, 0x00, TLV) ready to drop
	//                      into an advertising payload.
	Wrap string `json:"wrap,omitempty"`
}

// Encode builds the raw bytes of an Apple Continuity message — the inverse
// of Decode. Currently the iBeacon message (type 0x02) is supported,
// round-trip-verified against Decode.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of the existing decoder. The iBeacon layout is
// Apple's public, universally-implemented format (company ID 0x004C,
// message type 0x02, length 0x15: 16-byte proximity UUID + big-endian
// major + big-endian minor + signed measured-power byte); encoding is pure
// byte assembly — no crypto, no hardware. It produces the manufacturer-data
// payload an operator advertises from a beacon (e.g. a spoofed iBeacon for
// a proximity test); generation only, no BLE TX, so it is Low risk like the
// decoder. Correctness is verifiable two ways: round-trip against Decode and
// the fixed iBeacon byte layout (02 15 <uuid> <major> <minor> <tx>).
//
// # Deliberately deferred
//
// The other Continuity message types are not encodable here: Handoff (0x0C),
// NearbyInfo (0x10), AirDrop (0x04), Proximity Pairing (0x06), and Hey-Siri
// (0x07) carry encrypted bodies / auth tags / device-derived hashes the
// operator cannot synthesise offline, and Nearby Action (0x0F) is the
// device-popup BLE-spam primitive this project does not generate by policy.
// iBeacon is the one Continuity message that is a clean, public,
// non-cryptographic deterministic layout.
func Encode(r EncodeRequest) ([]byte, error) {
	var tlv []byte
	var err error
	switch strings.ToLower(strings.TrimSpace(r.Kind)) {
	case "ibeacon":
		tlv, err = encodeIBeacon(r)
	default:
		return nil, fmt.Errorf("applecontinuity: unsupported kind %q (supported: ibeacon)", r.Kind)
	}
	if err != nil {
		return nil, err
	}
	return wrapContinuity(tlv, r.Wrap)
}

func encodeIBeacon(r EncodeRequest) ([]byte, error) {
	uuid, err := parseUUID(r.UUID)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 21)
	body = append(body, uuid...)
	body = binary.BigEndian.AppendUint16(body, r.Major)
	body = binary.BigEndian.AppendUint16(body, r.Minor)
	body = append(body, byte(r.TXPower))
	// TLV: type 0x02, length 0x15 (21).
	out := make([]byte, 0, 2+len(body))
	out = append(out, 0x02, byte(len(body)))
	out = append(out, body...)
	return out, nil
}

// wrapContinuity applies the requested framing around a bare Continuity TLV.
func wrapContinuity(tlv []byte, wrap string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(wrap)) {
	case "", "tlv":
		return tlv, nil
	case "manufacturer":
		out := []byte{0x4C, 0x00}
		return append(out, tlv...), nil
	case "ad":
		// length = 0xFF type(1) + company ID(2) + TLV.
		out := []byte{byte(3 + len(tlv)), 0xFF, 0x4C, 0x00}
		return append(out, tlv...), nil
	default:
		return nil, fmt.Errorf("applecontinuity: unknown wrap %q (tlv, manufacturer, ad)", wrap)
	}
}

// parseUUID decodes a 16-byte proximity UUID from hex, tolerating dashes,
// separators, and a leading 0x.
func parseUUID(s string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(s))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("applecontinuity: uuid is required (16 bytes hex)")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("applecontinuity: uuid is not valid hex: %w", err)
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("applecontinuity: uuid must be exactly 16 bytes; got %d", len(b))
	}
	return b, nil
}
