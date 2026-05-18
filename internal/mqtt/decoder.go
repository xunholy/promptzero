// Package mqtt decodes MQTT v3.1.1 control packets — the
// application-layer protocol underneath most IoT smart-home /
// industrial-sensor / broker setups. Pure offline parser; no
// transport, no hardware.
//
// Wrap-vs-native judgement: MQTT v3.1.1 is a fully public OASIS
// specification (mqtt-v3.1.1-os.html). The walker is bit-level
// decoding over a 2-5 byte fixed header + per-packet-type
// variable header + payload. Wrapping a FAP for this would
// require an SD-card install + a firmware-fork dependency for a
// pure parser. Native delivers offline analysis — operators
// paste a captured MQTT packet from Wireshark / mosquitto_sub /
// any MQTT sniffer and inspect every field without re-running
// the capture.
//
// Pairs with the existing IoT decoders (zigbee_zcl_decode for
// Zigbee application commands, nrf24_packet_decode for NRF24
// HID, ble_gap_decode for BLE advertisements) — MQTT is the
// IP-side application-layer protocol IoT devices speak to their
// brokers.
//
// What this package covers:
//   - MQTT v3.1.1 control packet types (CONNECT, CONNACK,
//     PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBSCRIBE,
//     SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP,
//     DISCONNECT)
//   - Fixed header decode (4-bit packet type + 4-bit flags +
//     variable-byte-integer remaining length, 1-4 bytes)
//   - Per-packet-type variable header decode:
//   - CONNECT: protocol name + version + flags + keepalive +
//     payload (client ID, will topic/message, username,
//     password — strings prefixed with 2-byte length)
//   - CONNACK: session present flag + return code with
//     documented name
//   - PUBLISH: topic name + optional packet ID (QoS > 0) +
//     payload
//   - SUBSCRIBE / UNSUBSCRIBE: packet ID + topic filter list
//   - SUBACK: packet ID + per-filter return codes
//   - Pub*ACK / PUBREC / PUBREL / PUBCOMP / UNSUBACK:
//     packet ID
//   - PINGREQ / PINGRESP / DISCONNECT: header-only
//
// What this package does NOT cover (deliberately out of scope):
//   - MQTT v5 properties (those add new variable-header
//     structures past the v3.1.1 baseline — separate Spec when
//     a caller materialises with v5 traffic)
//   - TLS unwrap (operators bring the decrypted MQTT payload
//     post-TLS)
//   - Authentication validation (client ID / username / password
//     are surfaced but not checked against any catalog)
//   - Will message decoding (the Will topic + Will message are
//     surfaced as raw bytes; their interpretation is
//     application-specific)
package mqtt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// PacketType is the 4-bit control packet type field at bits
// 7..4 of the first byte.
type PacketType int

const (
	PacketTypeReserved    PacketType = 0
	PacketTypeCONNECT     PacketType = 1
	PacketTypeCONNACK     PacketType = 2
	PacketTypePUBLISH     PacketType = 3
	PacketTypePUBACK      PacketType = 4
	PacketTypePUBREC      PacketType = 5
	PacketTypePUBREL      PacketType = 6
	PacketTypePUBCOMP     PacketType = 7
	PacketTypeSUBSCRIBE   PacketType = 8
	PacketTypeSUBACK      PacketType = 9
	PacketTypeUNSUBSCRIBE PacketType = 10
	PacketTypeUNSUBACK    PacketType = 11
	PacketTypePINGREQ     PacketType = 12
	PacketTypePINGRESP    PacketType = 13
	PacketTypeDISCONNECT  PacketType = 14
	PacketTypeAUTH        PacketType = 15 // MQTT v5 only
)

func (t PacketType) String() string {
	switch t {
	case PacketTypeCONNECT:
		return "CONNECT"
	case PacketTypeCONNACK:
		return "CONNACK"
	case PacketTypePUBLISH:
		return "PUBLISH"
	case PacketTypePUBACK:
		return "PUBACK"
	case PacketTypePUBREC:
		return "PUBREC"
	case PacketTypePUBREL:
		return "PUBREL"
	case PacketTypePUBCOMP:
		return "PUBCOMP"
	case PacketTypeSUBSCRIBE:
		return "SUBSCRIBE"
	case PacketTypeSUBACK:
		return "SUBACK"
	case PacketTypeUNSUBSCRIBE:
		return "UNSUBSCRIBE"
	case PacketTypeUNSUBACK:
		return "UNSUBACK"
	case PacketTypePINGREQ:
		return "PINGREQ"
	case PacketTypePINGRESP:
		return "PINGRESP"
	case PacketTypeDISCONNECT:
		return "DISCONNECT"
	case PacketTypeAUTH:
		return "AUTH (MQTT v5)"
	}
	return "Reserved"
}

// FixedHeader is the decoded MQTT fixed header.
type FixedHeader struct {
	Raw int `json:"raw"`
	// PacketType (bits 7..4 of byte 0).
	PacketType     int    `json:"packet_type"`
	PacketTypeName string `json:"packet_type_name"`
	// Flags (bits 3..0). PUBLISH uses them for DUP / QoS / RETAIN;
	// other packets have spec-mandated fixed values.
	Flags int `json:"flags"`
	// RemainingLength is the variable-byte-integer length of the
	// rest of the packet (variable header + payload).
	RemainingLength int `json:"remaining_length"`
}

// PublishFlags is the PUBLISH-specific flag decode.
type PublishFlags struct {
	DUP    bool `json:"dup"`
	QoS    int  `json:"qos"`
	Retain bool `json:"retain"`
}

// Packet is the top-level decoded MQTT control packet.
type Packet struct {
	FixedHeader FixedHeader `json:"fixed_header"`
	// PublishFlags is populated when PacketType == PUBLISH.
	PublishFlags *PublishFlags `json:"publish_flags,omitempty"`
	// CONNECT fields
	ProtocolName    string `json:"protocol_name,omitempty"`
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	ConnectFlagsRaw int    `json:"connect_flags_raw,omitempty"`
	UsernameFlag    bool   `json:"username_flag,omitempty"`
	PasswordFlag    bool   `json:"password_flag,omitempty"`
	WillRetain      bool   `json:"will_retain,omitempty"`
	WillQoS         int    `json:"will_qos,omitempty"`
	WillFlag        bool   `json:"will_flag,omitempty"`
	CleanSession    bool   `json:"clean_session,omitempty"`
	KeepAlive       int    `json:"keep_alive,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	WillTopic       string `json:"will_topic,omitempty"`
	WillMessage     string `json:"will_message,omitempty"`
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	// CONNACK fields
	SessionPresent bool   `json:"session_present,omitempty"`
	ReturnCode     int    `json:"return_code,omitempty"`
	ReturnCodeName string `json:"return_code_name,omitempty"`
	// PUBLISH fields
	TopicName     string `json:"topic_name,omitempty"`
	PacketID      int    `json:"packet_id,omitempty"`
	PayloadHex    string `json:"payload_hex,omitempty"`
	PayloadString string `json:"payload_string,omitempty"`
	// SUBSCRIBE / UNSUBSCRIBE fields
	TopicFilters []TopicFilter `json:"topic_filters,omitempty"`
	// SUBACK fields
	SubReturnCodes []int `json:"sub_return_codes,omitempty"`
}

// TopicFilter is one subscription filter (with optional QoS for
// SUBSCRIBE).
type TopicFilter struct {
	Filter string `json:"filter"`
	QoS    int    `json:"qos,omitempty"`
}

// Decode parses a hex-encoded MQTT control packet. Tolerates
// ':' / '-' / '_' / whitespace separators.
func Decode(hexBlob string) (Packet, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Packet{}, fmt.Errorf("mqtt: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Packet{}, fmt.Errorf("mqtt: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant of Decode.
func DecodeBytes(b []byte) (Packet, error) {
	if len(b) < 2 {
		return Packet{}, fmt.Errorf("mqtt: packet %d bytes < 2-byte minimum (type + remaining length)",
			len(b))
	}
	pt := int(b[0]>>4) & 0x0F
	flags := int(b[0] & 0x0F)
	remLen, lenBytes, err := decodeVarLen(b[1:])
	if err != nil {
		return Packet{}, err
	}
	hdr := FixedHeader{
		Raw:             int(b[0]),
		PacketType:      pt,
		PacketTypeName:  PacketType(pt).String(),
		Flags:           flags,
		RemainingLength: remLen,
	}
	out := Packet{FixedHeader: hdr}
	off := 1 + lenBytes
	if off+remLen > len(b) {
		return out, fmt.Errorf("mqtt: declared remaining length %d exceeds available %d bytes",
			remLen, len(b)-off)
	}
	body := b[off : off+remLen]
	switch PacketType(pt) {
	case PacketTypeCONNECT:
		return decodeConnect(out, body)
	case PacketTypeCONNACK:
		return decodeConnack(out, body)
	case PacketTypePUBLISH:
		return decodePublish(out, flags, body)
	case PacketTypePUBACK, PacketTypePUBREC, PacketTypePUBREL, PacketTypePUBCOMP,
		PacketTypeUNSUBACK:
		if len(body) < 2 {
			return out, fmt.Errorf("mqtt: %s packet ID truncated", hdr.PacketTypeName)
		}
		out.PacketID = int(binary.BigEndian.Uint16(body[0:2]))
	case PacketTypeSUBSCRIBE:
		return decodeSubscribe(out, body)
	case PacketTypeSUBACK:
		return decodeSuback(out, body)
	case PacketTypeUNSUBSCRIBE:
		return decodeUnsubscribe(out, body)
	case PacketTypePINGREQ, PacketTypePINGRESP, PacketTypeDISCONNECT:
		// Header-only packets — no body decode needed.
	}
	return out, nil
}

// decodeVarLen parses an MQTT variable-byte integer (1-4 bytes,
// each with the top bit as a continuation flag). Returns the
// decoded value + the number of bytes consumed.
func decodeVarLen(b []byte) (int, int, error) {
	value := 0
	multiplier := 1
	for i := 0; i < 4 && i < len(b); i++ {
		v := b[i]
		value += int(v&0x7F) * multiplier
		if v&0x80 == 0 {
			return value, i + 1, nil
		}
		multiplier *= 128
	}
	return 0, 0, fmt.Errorf("mqtt: malformed variable-byte integer (continuation past 4 bytes)")
}

// readString parses an MQTT-style string — 2-byte big-endian
// length prefix followed by length bytes of UTF-8.
func readString(b []byte) (string, int, error) {
	if len(b) < 2 {
		return "", 0, fmt.Errorf("mqtt: string length prefix missing")
	}
	l := int(binary.BigEndian.Uint16(b[0:2]))
	if 2+l > len(b) {
		return "", 0, fmt.Errorf("mqtt: string body truncated (want %d bytes, have %d)",
			l, len(b)-2)
	}
	return string(b[2 : 2+l]), 2 + l, nil
}

// decodeConnect parses the CONNECT packet body.
func decodeConnect(out Packet, body []byte) (Packet, error) {
	// Protocol name + version + flags + keepalive
	pn, n, err := readString(body)
	if err != nil {
		return out, fmt.Errorf("mqtt CONNECT: protocol name: %w", err)
	}
	out.ProtocolName = pn
	off := n
	if off+4 > len(body) {
		return out, fmt.Errorf("mqtt CONNECT: header truncated")
	}
	out.ProtocolVersion = int(body[off])
	off++
	flags := body[off]
	out.ConnectFlagsRaw = int(flags)
	out.UsernameFlag = flags&0x80 != 0
	out.PasswordFlag = flags&0x40 != 0
	out.WillRetain = flags&0x20 != 0
	out.WillQoS = int((flags >> 3) & 0x03)
	out.WillFlag = flags&0x04 != 0
	out.CleanSession = flags&0x02 != 0
	off++
	out.KeepAlive = int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	// Payload: Client ID + optional Will Topic + Will Message +
	// optional Username + Password.
	cid, n, err := readString(body[off:])
	if err != nil {
		return out, fmt.Errorf("mqtt CONNECT: client ID: %w", err)
	}
	out.ClientID = cid
	off += n
	if out.WillFlag {
		wt, n, err := readString(body[off:])
		if err != nil {
			return out, fmt.Errorf("mqtt CONNECT: will topic: %w", err)
		}
		out.WillTopic = wt
		off += n
		wm, n, err := readString(body[off:])
		if err != nil {
			return out, fmt.Errorf("mqtt CONNECT: will message: %w", err)
		}
		out.WillMessage = wm
		off += n
	}
	if out.UsernameFlag {
		un, n, err := readString(body[off:])
		if err != nil {
			return out, fmt.Errorf("mqtt CONNECT: username: %w", err)
		}
		out.Username = un
		off += n
	}
	if out.PasswordFlag {
		pw, n, err := readString(body[off:])
		if err != nil {
			return out, fmt.Errorf("mqtt CONNECT: password: %w", err)
		}
		out.Password = pw
		off += n
	}
	_ = off
	return out, nil
}

// decodeConnack parses the CONNACK packet body.
func decodeConnack(out Packet, body []byte) (Packet, error) {
	if len(body) < 2 {
		return out, fmt.Errorf("mqtt CONNACK: body %d < 2 bytes", len(body))
	}
	out.SessionPresent = body[0]&0x01 != 0
	out.ReturnCode = int(body[1])
	out.ReturnCodeName = connackReturnCodeName(body[1])
	return out, nil
}

// decodePublish parses the PUBLISH packet body. PUBLISH uses the
// fixed-header flag nibble for DUP / QoS / RETAIN.
func decodePublish(out Packet, flags int, body []byte) (Packet, error) {
	out.PublishFlags = &PublishFlags{
		DUP:    flags&0x08 != 0,
		QoS:    (flags >> 1) & 0x03,
		Retain: flags&0x01 != 0,
	}
	topic, n, err := readString(body)
	if err != nil {
		return out, fmt.Errorf("mqtt PUBLISH: topic: %w", err)
	}
	out.TopicName = topic
	off := n
	// Packet ID only present when QoS > 0
	if out.PublishFlags.QoS > 0 {
		if off+2 > len(body) {
			return out, fmt.Errorf("mqtt PUBLISH: packet ID truncated")
		}
		out.PacketID = int(binary.BigEndian.Uint16(body[off : off+2]))
		off += 2
	}
	if off < len(body) {
		out.PayloadHex = strings.ToUpper(hex.EncodeToString(body[off:]))
		if isASCII(body[off:]) {
			out.PayloadString = string(body[off:])
		}
	}
	return out, nil
}

// decodeSubscribe parses the SUBSCRIBE packet body.
func decodeSubscribe(out Packet, body []byte) (Packet, error) {
	if len(body) < 2 {
		return out, fmt.Errorf("mqtt SUBSCRIBE: packet ID truncated")
	}
	out.PacketID = int(binary.BigEndian.Uint16(body[0:2]))
	off := 2
	for off < len(body) {
		topic, n, err := readString(body[off:])
		if err != nil {
			return out, fmt.Errorf("mqtt SUBSCRIBE: filter: %w", err)
		}
		off += n
		if off >= len(body) {
			return out, fmt.Errorf("mqtt SUBSCRIBE: QoS byte truncated")
		}
		qos := int(body[off])
		off++
		out.TopicFilters = append(out.TopicFilters, TopicFilter{
			Filter: topic,
			QoS:    qos,
		})
	}
	return out, nil
}

// decodeSuback parses the SUBACK packet body.
func decodeSuback(out Packet, body []byte) (Packet, error) {
	if len(body) < 2 {
		return out, fmt.Errorf("mqtt SUBACK: packet ID truncated")
	}
	out.PacketID = int(binary.BigEndian.Uint16(body[0:2]))
	for i := 2; i < len(body); i++ {
		out.SubReturnCodes = append(out.SubReturnCodes, int(body[i]))
	}
	return out, nil
}

// decodeUnsubscribe parses the UNSUBSCRIBE packet body.
func decodeUnsubscribe(out Packet, body []byte) (Packet, error) {
	if len(body) < 2 {
		return out, fmt.Errorf("mqtt UNSUBSCRIBE: packet ID truncated")
	}
	out.PacketID = int(binary.BigEndian.Uint16(body[0:2]))
	off := 2
	for off < len(body) {
		topic, n, err := readString(body[off:])
		if err != nil {
			return out, fmt.Errorf("mqtt UNSUBSCRIBE: filter: %w", err)
		}
		off += n
		out.TopicFilters = append(out.TopicFilters, TopicFilter{
			Filter: topic,
		})
	}
	return out, nil
}

// connackReturnCodeName maps CONNACK return codes (per MQTT
// v3.1.1 §3.2.2.3) to their names.
func connackReturnCodeName(c byte) string {
	switch c {
	case 0:
		return "Connection Accepted"
	case 1:
		return "Connection Refused, unacceptable protocol version"
	case 2:
		return "Connection Refused, identifier rejected"
	case 3:
		return "Connection Refused, server unavailable"
	case 4:
		return "Connection Refused, bad username or password"
	case 5:
		return "Connection Refused, not authorized"
	}
	return "Reserved"
}

// isASCII reports whether all bytes are printable ASCII.
// Used to decide whether to surface a PayloadString alongside
// PayloadHex.
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
