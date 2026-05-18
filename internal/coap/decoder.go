// Package coap decodes Constrained Application Protocol (RFC
// 7252) packets — the application-layer protocol used by
// constrained IoT devices (6LoWPAN, Thread, OpenThread,
// Zigbee IP). Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: CoAP is a fully public IETF
// specification (RFC 7252). The walker is bit-level decoding
// over a 4-byte fixed header + variable-length token +
// option list + optional payload. Wrapping a FAP for this
// would require an SD-card install + a firmware-fork
// dependency for a pure parser. Native delivers offline
// analysis — operators paste a captured CoAP packet from
// Wireshark / any UDP sniffer and inspect every field without
// re-running the capture.
//
// Pairs with the existing IoT decoders:
//   - mqtt_packet_decode for MQTT (the IP-side broker protocol)
//   - zigbee_zcl_decode for the Zigbee application layer
//   - ieee802154_decode + zigbee_nwk_decode + zigbee_aps_decode
//     for the underlying mesh stack
//
// Together they cover the IoT application-layer + mesh-network
// surface.
//
// What this package covers:
//   - Fixed header decode: 2-bit version + 2-bit type
//     (Confirmable / Non-Confirmable / Acknowledgement / Reset)
//   - 4-bit token length + 8-bit code + 16-bit message ID
//   - Code decode: request methods (GET / POST / PUT / DELETE
//     / FETCH / PATCH / iPATCH) + response codes (2.01 Created
//     / 2.04 Changed / 2.05 Content / 4.04 Not Found / 5.00
//     Internal Server Error / etc.) with documented names
//   - Token extraction (0-8 bytes)
//   - Option list walking with delta + length nibble encoding
//     (delta extension byte 13 = +1 byte extension, 14 = +2
//     byte extension; same encoding for length)
//   - Per-option-number name lookup for the documented options
//     (Uri-Host, Uri-Port, Uri-Path, Uri-Query, Content-Format,
//     Accept, Max-Age, ETag, If-Match, If-None-Match, Location-
//     Path, Location-Query, Observe, Block1/2, Size1/2, Proxy-
//     Uri, Proxy-Scheme)
//   - Payload extraction (after the 0xFF marker)
//
// What this package does NOT cover (deliberately out of scope):
//   - CoAP over DTLS unwrap (operators bring the decrypted
//     CoAP payload post-DTLS)
//   - Option-value type interpretation past the raw bytes
//     (e.g. Block1/2 size+M+NUM extraction would be a
//     follow-on)
//   - Observe / OSCORE security extensions
//   - CoAP over TCP (RFC 8323)
package coap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Type is the 2-bit message type field at bits 5..4 of byte 0.
type Type int

const (
	// TypeConfirmable — server must ACK; client retransmits.
	TypeConfirmable Type = 0
	// TypeNonConfirmable — fire-and-forget; no ACK.
	TypeNonConfirmable Type = 1
	// TypeAcknowledgement — response to a Confirmable request.
	TypeAcknowledgement Type = 2
	// TypeReset — message could not be processed; reset peer.
	TypeReset Type = 3
)

func (t Type) String() string {
	switch t {
	case TypeConfirmable:
		return "Confirmable"
	case TypeNonConfirmable:
		return "Non-Confirmable"
	case TypeAcknowledgement:
		return "Acknowledgement"
	case TypeReset:
		return "Reset"
	}
	return "Unknown"
}

// Header is the decoded 4-byte CoAP fixed header.
type Header struct {
	Raw int `json:"raw"`
	// Version (bits 7..6 of byte 0) — should be 1.
	Version int `json:"version"`
	// Type (bits 5..4 of byte 0).
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	// TokenLength (bits 3..0 of byte 0) — 0..8 bytes.
	TokenLength int `json:"token_length"`
	// Code (byte 1) — request method or response code packed as
	// (class << 5) | (detail). 0.01..0.04 = requests; 2.xx /
	// 4.xx / 5.xx = responses.
	Code     int    `json:"code"`
	CodeText string `json:"code_text"`
	CodeName string `json:"code_name"`
	// MessageID (bytes 2..3, big-endian).
	MessageID int `json:"message_id"`
}

// Option is one decoded CoAP option entry.
type Option struct {
	// Number is the absolute option number (computed by summing
	// the delta nibbles across the option list).
	Number int `json:"number"`
	// Name is the canonical option name when in our catalog,
	// "" otherwise.
	Name string `json:"name,omitempty"`
	// Length is the option value length in bytes.
	Length int `json:"length"`
	// ValueHex is the operator-facing hex rendering of the
	// value bytes. Always populated.
	ValueHex string `json:"value_hex,omitempty"`
	// ValueString is the UTF-8 string interpretation when the
	// option is a documented string type (Uri-Host, Uri-Path,
	// Uri-Query, Location-Path, etc.).
	ValueString string `json:"value_string,omitempty"`
	// ValueUint is the unsigned-integer interpretation when the
	// option is a documented uint type (Uri-Port, Content-Format,
	// Accept, Max-Age, etc.). nil for non-uint options.
	ValueUint *uint64 `json:"value_uint,omitempty"`
}

// Packet is the top-level decoded CoAP packet.
type Packet struct {
	Header Header `json:"header"`
	// TokenHex is the 0-8 byte token, hex-rendered.
	TokenHex string `json:"token_hex,omitempty"`
	// Options is the ordered list of decoded options.
	Options []Option `json:"options,omitempty"`
	// PayloadHex is the payload after the 0xFF marker.
	PayloadHex string `json:"payload_hex,omitempty"`
	// PayloadString is the UTF-8 string interpretation when
	// printable.
	PayloadString string `json:"payload_string,omitempty"`
}

// Decode parses a hex-encoded CoAP packet. Tolerates ':' / '-'
// / '_' / whitespace separators.
func Decode(hexBlob string) (Packet, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Packet{}, fmt.Errorf("coap: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Packet{}, fmt.Errorf("coap: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant of Decode.
func DecodeBytes(b []byte) (Packet, error) {
	if len(b) < 4 {
		return Packet{}, fmt.Errorf("coap: packet %d bytes < 4-byte minimum (fixed header)", len(b))
	}
	v := int(b[0]>>6) & 0x03
	t := int(b[0]>>4) & 0x03
	tkl := int(b[0]) & 0x0F
	if tkl > 8 {
		return Packet{}, fmt.Errorf("coap: invalid TKL %d (max 8)", tkl)
	}
	code := int(b[1])
	hdr := Header{
		Raw:         int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3]),
		Version:     v,
		Type:        t,
		TypeName:    Type(t).String(),
		TokenLength: tkl,
		Code:        code,
		CodeText:    codeText(code),
		CodeName:    codeName(code),
		MessageID:   int(binary.BigEndian.Uint16(b[2:4])),
	}
	out := Packet{Header: hdr}
	off := 4
	if off+tkl > len(b) {
		return out, fmt.Errorf("coap: TKL %d exceeds remaining %d bytes", tkl, len(b)-off)
	}
	if tkl > 0 {
		out.TokenHex = hexString(b[off : off+tkl])
	}
	off += tkl
	// Options + payload
	optNum := 0
	for off < len(b) {
		// Payload marker
		if b[off] == 0xFF {
			off++
			if off < len(b) {
				payload := b[off:]
				out.PayloadHex = hexString(payload)
				if isASCII(payload) {
					out.PayloadString = string(payload)
				}
			}
			return out, nil
		}
		// Option header: 4-bit delta + 4-bit length
		delta := int(b[off]>>4) & 0x0F
		length := int(b[off]) & 0x0F
		off++
		dExt, err := readExtension(delta, b, &off)
		if err != nil {
			return out, fmt.Errorf("coap: option delta extension: %w", err)
		}
		lExt, err := readExtension(length, b, &off)
		if err != nil {
			return out, fmt.Errorf("coap: option length extension: %w", err)
		}
		optNum += dExt
		if off+lExt > len(b) {
			return out, fmt.Errorf("coap: option value truncated (want %d bytes, have %d)",
				lExt, len(b)-off)
		}
		val := b[off : off+lExt]
		opt := Option{
			Number:   optNum,
			Name:     optionName(optNum),
			Length:   lExt,
			ValueHex: hexString(val),
		}
		// Type-specific interpretation
		switch optionType(optNum) {
		case "string":
			opt.ValueString = string(val)
		case "uint":
			u := bytesToUint(val)
			opt.ValueUint = &u
		}
		out.Options = append(out.Options, opt)
		off += lExt
	}
	return out, nil
}

// readExtension reads a CoAP delta or length extension. Per RFC
// 7252 §3.1: nibble 13 = +1 byte extension (value + 13),
// nibble 14 = +2 byte extension (value + 269), nibble 15 = reserved.
func readExtension(nibble int, b []byte, off *int) (int, error) {
	switch nibble {
	case 13:
		if *off >= len(b) {
			return 0, fmt.Errorf("missing 1-byte extension")
		}
		v := int(b[*off]) + 13
		*off++
		return v, nil
	case 14:
		if *off+2 > len(b) {
			return 0, fmt.Errorf("missing 2-byte extension")
		}
		v := int(binary.BigEndian.Uint16(b[*off:*off+2])) + 269
		*off += 2
		return v, nil
	case 15:
		return 0, fmt.Errorf("reserved nibble 15")
	}
	return nibble, nil
}

// codeText returns the standard CoAP "c.dd" notation (e.g.
// "0.01" for GET, "2.05" for Content, "4.04" for Not Found).
func codeText(code int) string {
	class := (code >> 5) & 0x07
	detail := code & 0x1F
	return fmt.Sprintf("%d.%02d", class, detail)
}

// codeName maps CoAP codes to their canonical names per RFC
// 7252 §12 + RFC 8132 (FETCH/PATCH/iPATCH).
func codeName(code int) string {
	switch code {
	case 0x00:
		return "Empty"
	// Request methods (class 0)
	case 0x01:
		return "GET"
	case 0x02:
		return "POST"
	case 0x03:
		return "PUT"
	case 0x04:
		return "DELETE"
	case 0x05:
		return "FETCH"
	case 0x06:
		return "PATCH"
	case 0x07:
		return "iPATCH"
	// 2.xx Success
	case 0x41:
		return "Created (2.01)"
	case 0x42:
		return "Deleted (2.02)"
	case 0x43:
		return "Valid (2.03)"
	case 0x44:
		return "Changed (2.04)"
	case 0x45:
		return "Content (2.05)"
	case 0x5F:
		return "Continue (2.31)"
	// 4.xx Client Error
	case 0x80:
		return "Bad Request (4.00)"
	case 0x81:
		return "Unauthorized (4.01)"
	case 0x82:
		return "Bad Option (4.02)"
	case 0x83:
		return "Forbidden (4.03)"
	case 0x84:
		return "Not Found (4.04)"
	case 0x85:
		return "Method Not Allowed (4.05)"
	case 0x86:
		return "Not Acceptable (4.06)"
	case 0x88:
		return "Request Entity Incomplete (4.08)"
	case 0x8C:
		return "Precondition Failed (4.12)"
	case 0x8D:
		return "Request Entity Too Large (4.13)"
	case 0x8F:
		return "Unsupported Content-Format (4.15)"
	// 5.xx Server Error
	case 0xA0:
		return "Internal Server Error (5.00)"
	case 0xA1:
		return "Not Implemented (5.01)"
	case 0xA2:
		return "Bad Gateway (5.02)"
	case 0xA3:
		return "Service Unavailable (5.03)"
	case 0xA4:
		return "Gateway Timeout (5.04)"
	case 0xA5:
		return "Proxying Not Supported (5.05)"
	}
	return ""
}

// optionName maps documented option numbers to names per RFC
// 7252 §5.10 + RFC 7641 (Observe) + RFC 7959 (Block).
func optionName(n int) string {
	switch n {
	case 1:
		return "If-Match"
	case 3:
		return "Uri-Host"
	case 4:
		return "ETag"
	case 5:
		return "If-None-Match"
	case 6:
		return "Observe"
	case 7:
		return "Uri-Port"
	case 8:
		return "Location-Path"
	case 11:
		return "Uri-Path"
	case 12:
		return "Content-Format"
	case 14:
		return "Max-Age"
	case 15:
		return "Uri-Query"
	case 17:
		return "Accept"
	case 20:
		return "Location-Query"
	case 23:
		return "Block2"
	case 27:
		return "Block1"
	case 28:
		return "Size2"
	case 35:
		return "Proxy-Uri"
	case 39:
		return "Proxy-Scheme"
	case 60:
		return "Size1"
	}
	return ""
}

// optionType returns "string" / "uint" / "" depending on the
// documented value type per RFC 7252 §5.10. Returns "" for
// opaque or unknown options.
func optionType(n int) string {
	switch n {
	case 3, 8, 11, 15, 20, 35, 39:
		// Uri-Host, Location-Path, Uri-Path, Uri-Query,
		// Location-Query, Proxy-Uri, Proxy-Scheme
		return "string"
	case 6, 7, 12, 14, 17, 23, 27, 28, 60:
		// Observe, Uri-Port, Content-Format, Max-Age, Accept,
		// Block2, Block1, Size2, Size1
		return "uint"
	}
	return ""
}

// bytesToUint converts a CoAP variable-length uint (big-endian,
// 0-4 bytes) to a uint64.
func bytesToUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = (v << 8) | uint64(c)
	}
	return v
}

// hexString renders bytes as uppercase no-separator hex.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// isASCII reports whether all bytes are printable ASCII.
func isASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return len(b) > 0
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
