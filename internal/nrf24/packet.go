// Package nrf24 decodes Nordic NRF24L01 Enhanced Shockburst
// (ESB) packets and the Logitech Unifying / Mousejack payload
// variants that ride on top of them. Pure offline parser; no
// transport, no hardware.
//
// Wrap-vs-native judgement: NRF24L01 ESB is a public Nordic
// data-sheet specification, Logitech Unifying is a
// reverse-engineered public format (Bastille's Mousejack
// research). The walker is bit-level decoding over a documented
// (address + PCF + payload + CRC) shape. Wrapping a FAP for
// this would require an SD-card install + a firmware-fork
// dependency for a pure parser. Native delivers offline
// analysis — operators paste a packet body captured by their
// Crazyradio / nRF Sniffer / Marauder NRF24 module and
// inspect every field without re-running the capture.
//
// Pairs with the existing nrf24_* Specs (nrf24_sniff_start,
// nrf24_list_targets, nrf24_mousejack_start, nrf24_payload_build)
// — those drive the sniffer; this is the host-side analyst
// entry point.
//
// What this package covers:
//   - Address-aware packet framing: caller supplies address
//     length (3/4/5 bytes); decoder extracts the address from
//     the packet head
//   - PCF (Packet Control Field) decode: 6-bit payload length +
//     2-bit Packet ID (PID) + 1-bit NO_ACK flag — packed into
//     the byte after the address per Nordic's data sheet
//   - Payload extraction up to PayloadLength bytes
//   - CRC walk (1 or 2 bytes per ESB configuration)
//   - Logitech Unifying / Mousejack payload-type recognition for
//     the well-known report-type bytes (HID / encrypted keyboard
//     / plaintext keyboard / mouse / set-keepalive / etc.)
//
// What this package does NOT cover (deliberately out of scope):
//   - Raw bit-stream demodulation (operators bring pre-deframed
//     packets; deframing is the firmware's job)
//   - CRC computation (the decoder surfaces the captured CRC
//     bytes; validation against the computed CRC over address +
//     PCF + payload would require knowing the polynomial, which
//     is documented but adds complexity for the operator's
//     normal use)
//   - Logitech Unifying decryption (XOR with the rolling key
//     requires the pairing-derived secret)
//   - Mousejack injection (offensive; handled by
//     nrf24_mousejack_start)
package nrf24

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// PacketControlField is the decoded 9-bit PCF, surfaced as
// per-field values for callers that want to render or filter.
type PacketControlField struct {
	// Raw is the full 9-bit value packed into a uint16 (high
	// bit is the PID's high bit and so on).
	Raw int `json:"raw"`
	// PayloadLength is the 6-bit length field (0-32).
	PayloadLength int `json:"payload_length"`
	// PID is the 2-bit Packet ID (0-3, wraps modulo 4).
	PID int `json:"pid"`
	// NoAck is the bit-0 NO_ACK flag (when set, the receiver
	// won't send an auto-acknowledgement).
	NoAck bool `json:"no_ack"`
}

// Packet is the top-level decoded NRF24 ESB packet.
type Packet struct {
	// AddressHex is the operator-facing rendering of the
	// captured RF address (uppercase, no separators).
	AddressHex string `json:"address_hex"`
	// AddressLength is the byte count of the address field
	// (3 / 4 / 5).
	AddressLength int `json:"address_length"`
	// PCF is the decoded Packet Control Field.
	PCF PacketControlField `json:"pcf"`
	// PayloadHex is the captured payload (uppercase hex,
	// no separators).
	PayloadHex string `json:"payload_hex"`
	// CRCHex is the captured CRC bytes (1 or 2 bytes,
	// uppercase hex).
	CRCHex string `json:"crc_hex,omitempty"`
	// CRCLength is the byte count of the CRC field (1 or 2).
	CRCLength int `json:"crc_length"`
	// Logitech is populated when the payload matches a known
	// Logitech Unifying / Mousejack report-type byte. nil
	// otherwise.
	Logitech *LogitechReport `json:"logitech,omitempty"`
}

// LogitechReport is the recognised view of a Logitech Unifying
// payload. The full reverse-engineered protocol has more fields
// (encrypted key data, AES-CTR nonces) that we don't decode
// further here — the operator gets the report type + raw body
// for cross-reference with Bastille's Mousejack research.
type LogitechReport struct {
	// DeviceIndex is byte 0 of the payload (which device on the
	// Unifying receiver this report is for, 0-7).
	DeviceIndex int `json:"device_index"`
	// ReportType is byte 1 — the documented Logitech Unifying
	// report type.
	ReportType    int    `json:"report_type"`
	ReportTypeHex string `json:"report_type_hex"`
	// ReportName is the canonical Logitech name when in our
	// table.
	ReportName string `json:"report_name,omitempty"`
	// BodyHex is the rest of the payload after the 2-byte
	// header.
	BodyHex string `json:"body_hex,omitempty"`
}

// DecodeOptions configures the packet walker.
type DecodeOptions struct {
	// AddressLength selects 3 / 4 / 5-byte address. Default 5
	// (the NRF24L01 power-on default).
	AddressLength int
	// CRCLength selects 1 / 2-byte CRC. Default 2 (the most
	// common configuration on Logitech Unifying devices).
	CRCLength int
}

// Decode parses a hex-encoded NRF24 ESB packet body (address +
// PCF + payload + CRC). Tolerates ':' / '-' / '_' / whitespace
// separators.
func Decode(hexBlob string, opts DecodeOptions) (Packet, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Packet{}, fmt.Errorf("nrf24: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Packet{}, fmt.Errorf("nrf24: invalid hex: %w", err)
	}
	return DecodeBytes(b, opts)
}

// DecodeBytes is the byte-slice variant of Decode.
func DecodeBytes(b []byte, opts DecodeOptions) (Packet, error) {
	addrLen := opts.AddressLength
	if addrLen == 0 {
		addrLen = 5
	}
	if addrLen < 3 || addrLen > 5 {
		return Packet{}, fmt.Errorf("nrf24: address length must be 3, 4, or 5 (got %d)", addrLen)
	}
	crcLen := opts.CRCLength
	if crcLen == 0 {
		crcLen = 2
	}
	if crcLen != 1 && crcLen != 2 {
		return Packet{}, fmt.Errorf("nrf24: CRC length must be 1 or 2 (got %d)", crcLen)
	}
	// Minimum packet: address + 1 PCF byte + 0 payload + CRC.
	// The PCF actually spans 9 bits across 2 bytes, but for
	// deframed input the operator gives us byte-aligned bytes
	// — first byte after address holds the 8 high bits of the
	// PCF (PayloadLength + PID's high bit), second byte's
	// high bit is the PID's low bit, then NO_ACK in bit 6,
	// then payload bytes start at bit 5 of byte 1. Most
	// deframers re-align this so PCF lives in byte 0 (PayloadLen
	// in bits 7..2, PID in bits 1..0, NO_ACK in next byte bit 7).
	// We follow the Nordic data sheet's "PCF + Payload" byte
	// layout: PCF byte 1 holds [PayloadLength (6) | PID (2)];
	// the NO_ACK is bit 7 of the next byte but most operators
	// see it merged into PCF by the deframer. We follow the
	// simpler interpretation: 1 PCF byte = [PayloadLen (6) |
	// PID (2)] and a separate flag byte; if the operator only
	// has the single PCF byte, NO_ACK reads from bit 0 of the
	// next byte (the first payload byte's high bit).
	minLen := addrLen + 1 + crcLen
	if len(b) < minLen {
		return Packet{}, fmt.Errorf("nrf24: packet %d bytes < %d-byte minimum (addr %d + PCF 1 + CRC %d)",
			len(b), minLen, addrLen, crcLen)
	}
	out := Packet{
		AddressHex:    hexString(b[:addrLen]),
		AddressLength: addrLen,
		CRCLength:     crcLen,
	}
	pcfByte := b[addrLen]
	out.PCF = PacketControlField{
		Raw:           int(pcfByte),
		PayloadLength: int((pcfByte >> 2) & 0x3F),
		PID:           int(pcfByte & 0x03),
		// NO_ACK is technically the next bit (bit 9 of the PCF),
		// but on deframed captures it's commonly merged into
		// the PCF byte. When the PCF byte alone fully describes
		// the frame, NO_ACK isn't reliably recoverable; we
		// surface it as "false" by default. Callers with
		// bit-aligned input can override.
		NoAck: false,
	}
	payloadStart := addrLen + 1
	payloadEnd := payloadStart + out.PCF.PayloadLength
	if payloadEnd+crcLen > len(b) {
		return out, fmt.Errorf("nrf24: PCF declares payload length %d, but only %d bytes remain after PCF (need %d for payload + %d CRC)",
			out.PCF.PayloadLength, len(b)-payloadStart, out.PCF.PayloadLength, crcLen)
	}
	payload := b[payloadStart:payloadEnd]
	out.PayloadHex = hexString(payload)
	if crcLen > 0 {
		out.CRCHex = hexString(b[payloadEnd : payloadEnd+crcLen])
	}
	// Logitech Unifying recognition: payload starts with
	// device-index byte + report-type byte. We look up the
	// report-type byte against the known table; if it matches,
	// surface the structured view.
	if len(payload) >= 2 {
		if name, ok := logitechReportTypes[payload[1]]; ok {
			out.Logitech = &LogitechReport{
				DeviceIndex:   int(payload[0]),
				ReportType:    int(payload[1]),
				ReportTypeHex: fmt.Sprintf("%02X", payload[1]),
				ReportName:    name,
				BodyHex:       hexString(payload[2:]),
			}
		}
	}
	return out, nil
}

// logitechReportTypes maps the well-known Logitech Unifying
// report-type bytes to canonical names. Source: Bastille's
// Mousejack research + RF Storm's KeySniffer documentation.
//
// The Unifying protocol uses byte 1 of the payload (post-device-
// index) as the report-type selector. Each type has a specific
// body layout (HID Boot Keyboard report, Mouse XY+buttons,
// HID++ command, etc.).
var logitechReportTypes = map[byte]string{
	0x40: "HID Boot Keyboard report",
	0x4D: "Mouse movement report",
	0x4E: "Mouse movement (deprecated form)",
	0x4F: "Encrypted keyboard report",
	0x50: "HID++ short message",
	0x51: "HID++ long message",
	0xC1: "Set / get keepalive",
	0xC2: "Plaintext keyboard report (legacy)",
	0xD3: "Pairing request / response",
	0xDF: "Pairing notification",
}

// hexString renders bytes as uppercase no-separator hex.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// stripSeparators mirrors the convention across our pure-decoder
// packages.
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
