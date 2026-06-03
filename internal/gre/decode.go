// Package gre decodes Generic Routing Encapsulation packets
// per RFC 2784 (base) + RFC 2890 (Key + Sequence Number) +
// RFC 2637 (PPTP Enhanced GRE, Version=1).
//
// Wrap-vs-native judgement
//
//	Native. All three RFCs are fully public; GRE is a tight
//	bit-packed header with optional fields gated by flag
//	bits. No crypto, no compression, no varints. Operators
//	paste IP-payload bytes (protocol number 47 in the outer
//	IP header) from a `tcpdump -X proto 47` line, a
//	Wireshark Follow-IP-Stream view, or any GRE-emitting
//	tool and get the documented header plus encapsulated
//	protocol identification for routing into a downstream
//	decoder.
//
// What this package covers
//
//   - **4-byte mandatory header** (RFC 2784 §2):
//
//   - byte 0: C (Checksum present, bit 7), R (Routing
//     present — deprecated, bit 6), K (Key present, bit 5),
//     S (Sequence Number present, bit 4), s (Strict Source
//     Route — deprecated, bit 3), Recur (Recursion Control
//     — deprecated, bits 0-2).
//
//   - byte 1: Flags (5 bits) + Version (3 bits). Version
//     0 = standard GRE; Version 1 = PPTP Enhanced GRE.
//
//   - bytes 2-3: Protocol Type (EtherType of the
//     encapsulated payload). **8-entry name table**:
//
//   - 0x0800 IPv4
//
//   - 0x86DD IPv6
//
//   - 0x6558 Transparent Ethernet Bridging (L2 tunnel,
//     EoGRE)
//
//   - 0x880B PPP (PPP-in-GRE)
//
//   - 0x8847 MPLS unicast
//
//   - 0x8848 MPLS multicast
//
//   - 0x6559 Raw Frame Relay
//
//   - 0x0806 ARP
//
//   - **Optional fields** (gated by flag bits, in this order):
//
//   - If C or R set: 4 bytes = 16-bit Checksum + 16-bit
//     Offset (Offset is only meaningful when R is set; R
//     is deprecated).
//
//   - If K set (RFC 2890): 4 bytes Key (used to demultiplex
//     multiple GRE tunnels between the same endpoints).
//
//   - If S set (RFC 2890): 4 bytes Sequence Number (for
//     in-order delivery; rarely used in practice).
//
//   - **PPTP Enhanced GRE** (RFC 2637, Version=1) — Microsoft
//     PPTP overloads the K bit + Key field: the 4 bytes are
//     interpreted as PayloadLength (uint16 BE) + Call ID
//     (uint16 BE). PPTP additionally adds an Acknowledgement
//     Number (4 bytes) when the A bit (bit 7 of byte 1) is
//     set. PPTP always has K=1, S is optional, A is optional.
//
//   - **Recognised variant**: surfaces 'standard GRE
//     (RFC 2784)' for V=0 or 'PPTP Enhanced GRE (RFC 2637)'
//     for V=1.
//
//   - **Encapsulated payload bytes** are surfaced as hex. When the
//     protocol type marks the payload as IPv4 (0x0800) or IPv6
//     (0x86DD), the inner packet is decoded in place via
//     internal/ipdecode, so the tunnelled flow's addresses /
//     protocol / ports surface directly (a payload that does not
//     parse as IP is reported with an error and left as hex). Other
//     payload kinds (Transparent Ethernet, PPP, MPLS, …) are left as
//     hex for the appropriate downstream decoder.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IP framing — feed the IP-payload bytes after the outer
//     IPv4 / IPv6 header strip (IP protocol number 47 for GRE).
//
//   - Inner payload decoding — operators pipe the post-GRE
//     bytes to `ip_packet_decode` (for IPv4/IPv6 payloads),
//     to a future Ethernet decoder (for TEB payloads), to
//     `arp_decode` (for ARP), etc.
//
//   - Routing field (R bit) body — the RFC 1701 routing
//     entries are deprecated and we only surface the
//     Checksum + Offset bytes.
//
//   - PPP frame dissection inside PPTP — the post-Ack PPP
//     frame is a separate Spec.
package gre

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ipdecode"
)

// Result is the top-level decoded view.
type Result struct {
	Variant         string `json:"variant"`
	Version         int    `json:"version"`
	ChecksumPresent bool   `json:"checksum_present"`
	RoutingPresent  bool   `json:"routing_present"`
	KeyPresent      bool   `json:"key_present"`
	SequencePresent bool   `json:"sequence_present"`
	StrictSource    bool   `json:"strict_source_route"`
	Recur           int    `json:"recursion_control"`
	AckPresent      bool   `json:"ack_present,omitempty"`
	FlagsByte0Hex   string `json:"flags_byte0_hex"`
	FlagsByte1Hex   string `json:"flags_byte1_hex"`
	ProtocolType    int    `json:"protocol_type"`
	ProtocolTypeHex string `json:"protocol_type_hex"`
	ProtocolName    string `json:"protocol_name"`

	Checksum       *uint16 `json:"checksum,omitempty"`
	Offset         *uint16 `json:"offset,omitempty"`
	Key            *uint32 `json:"key,omitempty"`
	KeyHex         string  `json:"key_hex,omitempty"`
	SequenceNumber *uint32 `json:"sequence_number,omitempty"`
	AckNumber      *uint32 `json:"ack_number,omitempty"`

	PPTPPayloadLen *uint16 `json:"pptp_payload_length,omitempty"`
	PPTPCallID     *uint16 `json:"pptp_call_id,omitempty"`

	HeaderBytes      int              `json:"header_bytes"`
	PayloadLength    int              `json:"payload_length"`
	PayloadHex       string           `json:"payload_hex,omitempty"`
	InnerPacket      *ipdecode.Packet `json:"inner_packet,omitempty"`
	InnerDecodeError string           `json:"inner_decode_error,omitempty"`
	TotalBytes       int              `json:"total_bytes"`
	Notes            []string         `json:"notes,omitempty"`
}

// Decode parses a GRE packet from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("GRE header truncated (%d bytes; need ≥4)", len(b))
	}

	r := &Result{
		TotalBytes:      len(b),
		FlagsByte0Hex:   fmt.Sprintf("0x%02X", b[0]),
		FlagsByte1Hex:   fmt.Sprintf("0x%02X", b[1]),
		ChecksumPresent: b[0]&0x80 != 0,
		RoutingPresent:  b[0]&0x40 != 0,
		KeyPresent:      b[0]&0x20 != 0,
		SequencePresent: b[0]&0x10 != 0,
		StrictSource:    b[0]&0x08 != 0,
		Recur:           int(b[0] & 0x07),
		AckPresent:      b[1]&0x80 != 0,
		Version:         int(b[1] & 0x07),
		ProtocolType:    int(binary.BigEndian.Uint16(b[2:4])),
	}
	r.ProtocolTypeHex = fmt.Sprintf("0x%04X", r.ProtocolType)
	r.ProtocolName = protocolName(r.ProtocolType)

	switch r.Version {
	case 0:
		r.Variant = "standard GRE (RFC 2784/2890)"
	case 1:
		r.Variant = "PPTP Enhanced GRE (RFC 2637)"
	default:
		r.Variant = fmt.Sprintf("unknown version %d", r.Version)
	}

	if r.RoutingPresent {
		r.Notes = append(r.Notes,
			"R (Routing Present) bit is set — the RFC 1701 source routing entries are "+
				"deprecated and the field is parsed here only for header length accounting")
	}
	if r.StrictSource {
		r.Notes = append(r.Notes,
			"s (Strict Source Route) bit is set — this is a deprecated RFC 1701 field")
	}

	off := 4
	// Checksum + Offset (4 bytes when C or R is set).
	if r.ChecksumPresent || r.RoutingPresent {
		if off+4 > len(b) {
			return nil, fmt.Errorf("checksum/offset field truncated")
		}
		csum := binary.BigEndian.Uint16(b[off : off+2])
		offs := binary.BigEndian.Uint16(b[off+2 : off+4])
		r.Checksum = &csum
		r.Offset = &offs
		off += 4
	}
	// Key (4 bytes when K is set).
	if r.KeyPresent {
		if off+4 > len(b) {
			return nil, fmt.Errorf("key field truncated")
		}
		key := binary.BigEndian.Uint32(b[off : off+4])
		r.Key = &key
		r.KeyHex = fmt.Sprintf("0x%08X", key)
		// PPTP Enhanced GRE: split Key into PayloadLength + Call ID.
		if r.Version == 1 {
			pl := uint16(key >> 16)
			cid := uint16(key & 0xFFFF)
			r.PPTPPayloadLen = &pl
			r.PPTPCallID = &cid
		}
		off += 4
	}
	// Sequence Number (4 bytes when S is set).
	if r.SequencePresent {
		if off+4 > len(b) {
			return nil, fmt.Errorf("sequence number field truncated")
		}
		seq := binary.BigEndian.Uint32(b[off : off+4])
		r.SequenceNumber = &seq
		off += 4
	}
	// Acknowledgement Number (PPTP Enhanced GRE only, when A is set).
	if r.Version == 1 && r.AckPresent {
		if off+4 > len(b) {
			return nil, fmt.Errorf("ack number field truncated")
		}
		ack := binary.BigEndian.Uint32(b[off : off+4])
		r.AckNumber = &ack
		off += 4
	}

	r.HeaderBytes = off
	r.PayloadLength = len(b) - off
	if r.PayloadLength > 0 {
		payload := b[off:]
		if r.PayloadLength > 256 {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload[:256])) + "..."
		} else {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		}
		// When the protocol type marks the encapsulated payload as IP,
		// decode it in place via internal/ipdecode so the inner flow's
		// addresses / protocol / ports surface directly. Other payload
		// kinds (Transparent Ethernet, PPP, MPLS, …) are left as hex —
		// no confidently-wrong output.
		if r.ProtocolType == 0x0800 || r.ProtocolType == 0x86DD {
			if pkt, err := ipdecode.DecodeBytes(payload); err == nil {
				r.InnerPacket = pkt
			} else {
				r.InnerDecodeError = err.Error()
			}
		}
	}
	return r, nil
}

func protocolName(t int) string {
	switch t {
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0x6558:
		return "Transparent Ethernet Bridging (EoGRE)"
	case 0x880B:
		return "PPP (PPP-in-GRE)"
	case 0x8847:
		return "MPLS unicast"
	case 0x8848:
		return "MPLS multicast"
	case 0x6559:
		return "Raw Frame Relay"
	case 0x0806:
		return "ARP"
	}
	return fmt.Sprintf("EtherType 0x%04X (uncatalogued)", t)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
