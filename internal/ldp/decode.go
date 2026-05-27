// Package ldp decodes LDP (Label Distribution Protocol) PDUs per RFC 5036.
// LDP runs on TCP/646 (session messages) and UDP/646 (Hello discovery). It
// distributes MPLS label bindings between Label Switching Routers (LSRs),
// forming the control plane of MPLS networks.
//
// LDP is the **MPLS control plane** — it distributes label bindings that
// govern packet forwarding at the MPLS switching layer. Without LDP, MPLS
// forwarding tables remain empty and traffic cannot traverse the MPLS core.
//
// Security relevance:
//
//   - **No default authentication** — LDP TCP/646 sessions are unauthenticated.
//     TCP MD5 authentication (RFC 2385) is optional and often omitted. An
//     attacker that can inject TCP segments can manipulate the label space.
//
//   - **LDP session hijacking** allows label manipulation — traffic
//     redirection at the MPLS layer without touching IP routing.
//
//   - **Hello messages on UDP/646** disclose LSR IDs (router loopback IPs)
//     and transport addresses — the full LSR topology is visible passively.
//
//   - **Label Mapping messages** disclose FEC-to-label bindings — the
//     complete MPLS forwarding topology is exposed.
//
//   - **LDP is the signalling protocol for MPLS VPNs** (L3VPN, L2VPN,
//     VPLS). Compromising LDP = compromising the MPLS switching plane,
//     enabling traffic interception across provider VPNs.
//
//   - **LSR IDs** are router loopback addresses — reachable loopbacks are
//     implicit LDP transport endpoints.
//
// Wrap-vs-native judgement
//
//	Native. RFC 5036 is publicly available. The LDP PDU header is a tight
//	10-byte binary header followed by messages, each with a 4-byte header
//	plus TLV parameters. No crypto at the parse layer.
//
// What this package covers
//
//   - **10-byte LDP PDU header**: version (must be 1), pdu_length, lsr_id
//     (dotted-quad), label_space.
//
//   - **LDP message header**: message_type (15-bit, with unknown_bit),
//     message_length, message_id. First message only.
//
//   - **13-entry message type name table**: Notification (0x0001), Hello
//     (0x0100), Initialization (0x0200), KeepAlive (0x0201), Address
//     (0x0300), Address Withdraw (0x0301), Label Mapping (0x0400), Label
//     Request (0x0401), Label Withdraw (0x0402), Label Release (0x0403),
//     Label Abort Request (0x0404).
//
//   - **TLV walker**: unknown_bit(1) + forward_bit(1) + type(14 bits) +
//     length(2 BE) + value for all TLVs in the first message; surfaces
//     tlv_count.
//
//   - **Common Hello Parameters TLV (0x0500)**: hold_time, targeted,
//     request_targeted.
//
//   - **IPv4 Transport Address TLV (0x0501)**: transport_address
//     (dotted-quad).
//
//   - **Common Session Parameters TLV (0x0600)**: keepalive_time,
//     max_pdu_length, receiver_lsr_id (dotted-quad).
//
//   - **Generic Label TLV (0x0300)**: label value (for Label Mapping).
//
//   - **Classification flags**: is_hello, is_initialization, is_keepalive,
//     is_label_mapping, is_notification.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **FEC TLV (0x0001)**: FEC element type dispatch, prefix length,
//     and address bytes.
//
//   - **Address List TLV (0x0100)**: address-family and address list.
//
//   - **Status TLV (0x0400) in Notification messages**: status code,
//     E/F bits, message ID.
//
//   - **ATM Label / Frame Relay Label TLVs**: legacy label encoding.
//
//   - **Path Vector / Hop Count TLVs**: loop-detection parameters.
//
//   - **Multiple PDUs** per buffer: only the first PDU and its first
//     message are decoded.
//
//   - **TCP MD5 authentication**: the authentication is at the TCP layer,
//     not within LDP PDU bytes.
package ldp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the structured decode of an LDP PDU.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// PDU header fields
	Version    int    `json:"version"`
	PDULength  int    `json:"pdu_length"`
	LSRID      string `json:"lsr_id"`
	LabelSpace int    `json:"label_space"`

	// First message header
	MessageType     int    `json:"message_type"`
	MessageTypeName string `json:"message_type_name"`
	MessageLength   int    `json:"message_length"`
	MessageID       uint32 `json:"message_id"`

	// Classification
	IsHello          bool `json:"is_hello"`
	IsInitialization bool `json:"is_initialization"`
	IsKeepalive      bool `json:"is_keepalive"`
	IsLabelMapping   bool `json:"is_label_mapping"`
	IsNotification   bool `json:"is_notification"`

	// TLV summary
	TLVCount int `json:"tlv_count"`

	// Common Hello Parameters TLV (0x0500)
	HasHelloParams  bool `json:"has_hello_params"`
	HoldTime        int  `json:"hold_time,omitempty"`
	Targeted        bool `json:"targeted,omitempty"`
	RequestTargeted bool `json:"request_targeted,omitempty"`

	// IPv4 Transport Address TLV (0x0501)
	HasTransportAddress bool   `json:"has_transport_address"`
	TransportAddress    string `json:"transport_address,omitempty"`

	// Common Session Parameters TLV (0x0600)
	HasSessionParams bool   `json:"has_session_params"`
	KeepaliveTime    int    `json:"keepalive_time,omitempty"`
	MaxPDULength     int    `json:"max_pdu_length,omitempty"`
	ReceiverLSRID    string `json:"receiver_lsr_id,omitempty"`

	// Generic Label TLV (0x0300)
	HasGenericLabel bool   `json:"has_generic_label"`
	LabelValue      uint32 `json:"label_value,omitempty"`
}

const ldpPDUHeaderSize = 10
const ldpMsgHeaderSize = 8

// Decode parses an LDP PDU from a hex string.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < ldpPDUHeaderSize {
		return nil, fmt.Errorf("ldp pdu header truncated (%d bytes; need %d)", len(b), ldpPDUHeaderSize)
	}

	r := &Result{TotalBytes: len(b)}

	// Parse 10-byte LDP PDU header.
	r.Version = int(binary.BigEndian.Uint16(b[0:2]))
	r.PDULength = int(binary.BigEndian.Uint16(b[2:4]))
	r.LSRID = net.IP(b[4:8]).String()
	r.LabelSpace = int(binary.BigEndian.Uint16(b[8:10]))

	// Require LDP version 1.
	if r.Version != 1 {
		return nil, fmt.Errorf("ldp version %d not supported (expected 1)", r.Version)
	}

	// Parse first message header (8 bytes: type(2) + length(2) + id(4)).
	off := ldpPDUHeaderSize
	if off+ldpMsgHeaderSize > len(b) {
		return nil, fmt.Errorf("ldp message header truncated (%d bytes available; need %d)", len(b)-off, ldpMsgHeaderSize)
	}

	// Message type: high bit is unknown_bit (ignored); low 15 bits are the type.
	rawType := binary.BigEndian.Uint16(b[off : off+2])
	r.MessageType = int(rawType & 0x7FFF)
	r.MessageTypeName = messageTypeName(r.MessageType)
	r.MessageLength = int(binary.BigEndian.Uint16(b[off+2 : off+4]))
	r.MessageID = binary.BigEndian.Uint32(b[off+4 : off+8])

	// Classify by message type.
	switch r.MessageType {
	case 0x0001:
		r.IsNotification = true
	case 0x0100:
		r.IsHello = true
	case 0x0200:
		r.IsInitialization = true
	case 0x0201:
		r.IsKeepalive = true
	case 0x0400:
		r.IsLabelMapping = true
	}

	// Walk TLVs in the first message body.
	// TLV offset starts after the message header (type+length+id = 8 bytes).
	// The message body length = r.MessageLength - 4 (the message_id field).
	tlvStart := off + ldpMsgHeaderSize
	// MessageLength covers: message_id(4) + TLVs. So TLV region ends at:
	// off+2 (past type) +2 (past length) + r.MessageLength = off+4+r.MessageLength
	tlvEnd := off + 4 + r.MessageLength
	if tlvEnd > len(b) {
		tlvEnd = len(b)
	}

	tlvOff := tlvStart
	for tlvOff+4 <= tlvEnd {
		// TLV type: high 2 bits are unknown_bit and forward_bit; low 14 bits are type.
		rawTLVType := binary.BigEndian.Uint16(b[tlvOff : tlvOff+2])
		tlvType := int(rawTLVType & 0x3FFF)
		tlvLen := int(binary.BigEndian.Uint16(b[tlvOff+2 : tlvOff+4]))
		if tlvOff+4+tlvLen > tlvEnd {
			// Truncated TLV value; stop walking.
			break
		}

		r.TLVCount++
		value := b[tlvOff+4 : tlvOff+4+tlvLen]
		decodeTLV(r, tlvType, value)

		tlvOff += 4 + tlvLen
	}

	return r, nil
}

func decodeTLV(r *Result, tlvType int, value []byte) {
	switch tlvType {
	case 0x0300: // Generic Label
		decodeGenericLabelTLV(r, value)
	case 0x0500: // Common Hello Parameters
		decodeCommonHelloParamsTLV(r, value)
	case 0x0501: // IPv4 Transport Address
		decodeIPv4TransportAddressTLV(r, value)
	case 0x0600: // Common Session Parameters
		decodeCommonSessionParamsTLV(r, value)
	}
}

func decodeGenericLabelTLV(r *Result, value []byte) {
	// Generic Label TLV value: 4-byte label value (only low 20 bits are the label).
	if len(value) < 4 {
		return
	}
	r.HasGenericLabel = true
	r.LabelValue = binary.BigEndian.Uint32(value[0:4]) & 0x000FFFFF
}

func decodeCommonHelloParamsTLV(r *Result, value []byte) {
	// Common Hello Parameters TLV value (RFC 5036 §3.5.2):
	// hold_time (2 BE) + flags (2 BE)
	// flags: bit 15 (high) = T (targeted), bit 14 = R (request_targeted)
	if len(value) < 4 {
		return
	}
	r.HasHelloParams = true
	r.HoldTime = int(binary.BigEndian.Uint16(value[0:2]))
	flags := binary.BigEndian.Uint16(value[2:4])
	r.Targeted = flags&0x8000 != 0
	r.RequestTargeted = flags&0x4000 != 0
}

func decodeIPv4TransportAddressTLV(r *Result, value []byte) {
	// IPv4 Transport Address TLV value: 4-byte IPv4 address.
	if len(value) < 4 {
		return
	}
	r.HasTransportAddress = true
	r.TransportAddress = net.IP(value[0:4]).String()
}

func decodeCommonSessionParamsTLV(r *Result, value []byte) {
	// Common Session Parameters TLV value (RFC 5036 §3.5.3):
	// protocol_version (2 BE) + keepalive_time (2 BE) + flags (1) +
	// path_vector_limit (1) + max_pdu_length (2 BE) +
	// receiver_lsr_id (4) + receiver_label_space (2 BE)
	// Total: 14 bytes minimum.
	if len(value) < 14 {
		return
	}
	r.HasSessionParams = true
	r.KeepaliveTime = int(binary.BigEndian.Uint16(value[2:4]))
	r.MaxPDULength = int(binary.BigEndian.Uint16(value[6:8]))
	r.ReceiverLSRID = net.IP(value[8:12]).String()
}

func messageTypeName(t int) string {
	switch t {
	case 0x0001:
		return "Notification"
	case 0x0100:
		return "Hello"
	case 0x0200:
		return "Initialization"
	case 0x0201:
		return "KeepAlive"
	case 0x0300:
		return "Address"
	case 0x0301:
		return "Address Withdraw"
	case 0x0400:
		return "Label Mapping"
	case 0x0401:
		return "Label Request"
	case 0x0402:
		return "Label Withdraw"
	case 0x0403:
		return "Label Release"
	case 0x0404:
		return "Label Abort Request"
	}
	return fmt.Sprintf("msg_type_0x%04x", t)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
