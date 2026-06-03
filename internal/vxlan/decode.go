// Package vxlan decodes Virtual Extensible LAN packets per
// RFC 7348, plus per-vendor variants: Cisco's Group-Based
// Policy (VXLAN-GBP, draft-smith-vxlan-group-policy) and the
// Generic Protocol Extension (VXLAN-GPE, draft-ietf-nvo3-
// vxlan-gpe).
//
// Wrap-vs-native judgement
//
//	Native. RFC 7348 is fully public; the VXLAN header is
//	a tight 8-byte field plus the encapsulated original
//	Ethernet frame. No crypto, no compression, no varints.
//	Operators paste UDP-payload bytes (standard UDP dest
//	port 4789) from a Wireshark Follow-UDP-Stream view, a
//	`tcpdump -X udp port 4789` line, or any VXLAN-emitting
//	tool and get the documented header plus the inner
//	Ethernet header peek for routing into a downstream
//	decoder.
//
// What this package covers
//
//   - **8-byte VXLAN header** (RFC 7348 §5):
//
//   - byte 0: Flags. Bit 3 (I-flag, mask 0x08) MUST be 1
//     in standard VXLAN to indicate the VNI is valid; the
//     other 7 bits are reserved and MUST be 0. VXLAN-GBP
//     (Cisco extension) overloads bit 0 as G (Group Policy
//     Applied) and bit 4 as D (Don't Learn).
//
//   - bytes 1-3: Reserved 1 (24 bits, must be 0 in
//     standard VXLAN). VXLAN-GBP overloads as 16-bit
//     Group Policy ID (with 8 reserved bits).
//
//   - bytes 4-6: VNI (24-bit VXLAN Network Identifier;
//     like a 24-bit VLAN ID, 16M possible).
//
//   - byte 7: Reserved 2 (must be 0 in standard VXLAN).
//     VXLAN-GPE overloads as Next Protocol (1 IPv4 /
//     2 IPv6 / 3 Ethernet / 4 NSH / 5 MPLS).
//
//   - **RFC 7348 conformance check**: surfaces a Note when
//     the I-flag is not set or when reserved bits are
//     non-zero (which the operator can investigate as
//     middlebox abuse / non-standard variant / corrupt
//     frame).
//
//   - **Variant detection**: if the I-flag is set AND any
//     reserved bits are non-zero, attempt to interpret as
//     VXLAN-GBP or VXLAN-GPE based on the pattern.
//
//   - **Inner Ethernet**: the bytes after the VXLAN header are
//     the encapsulated original Ethernet frame. We surface the
//     dst MAC, src MAC, and EtherType (with name lookup against
//     the same 10-entry table used by `vlan_decode`). When the
//     EtherType is IPv4 (0x0800) or IPv6 (0x86DD) the inner L3
//     packet is decoded in place via internal/ipdecode, so the
//     overlaid flow's addresses / protocol / ports surface
//     directly; a payload that does not parse as IP is reported
//     with an error and left as hex. Non-IP EtherTypes (ARP,
//     802.1Q, MPLS, …) are left for their own decoders.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP / IP framing — feed the UDP payload bytes after
//     the outer IP+UDP headers (standard outer UDP dest port
//     4789).
//
//   - Inner Ethernet payloads other than IP (802.1Q VLAN tags,
//     ARP, MPLS, …) — left for `vlan_decode` / their own
//     decoders; only IPv4 / IPv6 inner frames are decoded here.
//
//   - VXLAN-GPE Next Protocol body dissection — only the
//     Next Protocol byte is decoded; the body is the
//     encapsulated IPv4 / IPv6 / Ethernet payload.
//
//   - Geneve (RFC 8926) — a different overlay with a TLV
//     options block; a future Spec.
//
//   - VXLAN flooding / BUM (Broadcast / Unknown unicast /
//     Multicast) replication semantics — this is a per-
//     packet decoder, not a session tracker.
package vxlan

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ipdecode"
)

// Result is the top-level decoded view.
type Result struct {
	Flags         int            `json:"flags"`
	FlagsHex      string         `json:"flags_hex"`
	IFlag         bool           `json:"i_flag"`
	Reserved1Hex  string         `json:"reserved_1_hex"`
	Reserved1Zero bool           `json:"reserved_1_zero"`
	VNI           uint32         `json:"vni"`
	Reserved2     int            `json:"reserved_2"`
	Reserved2Zero bool           `json:"reserved_2_zero"`
	Variant       string         `json:"variant"`
	InnerEthernet *InnerEthernet `json:"inner_ethernet,omitempty"`
	GBP           *GBPFields     `json:"vxlan_gbp,omitempty"`
	GPE           *GPEFields     `json:"vxlan_gpe,omitempty"`
	TotalBytes    int            `json:"total_bytes"`
	Notes         []string       `json:"notes,omitempty"`
}

// InnerEthernet is the peek at the encapsulated Ethernet
// frame's header (dst MAC + src MAC + EtherType).
type InnerEthernet struct {
	DstMAC           string           `json:"dst_mac"`
	SrcMAC           string           `json:"src_mac"`
	EtherType        int              `json:"ether_type"`
	EtherTypeHex     string           `json:"ether_type_hex"`
	EtherTypeName    string           `json:"ether_type_name"`
	PayloadOffset    int              `json:"payload_offset"`
	RemainingBytes   int              `json:"remaining_bytes"`
	InnerPacket      *ipdecode.Packet `json:"inner_packet,omitempty"`
	InnerDecodeError string           `json:"inner_decode_error,omitempty"`
}

// GBPFields is the Cisco Group-Based Policy extension overlay.
type GBPFields struct {
	GroupPolicyApplied bool   `json:"group_policy_applied"`
	DontLearn          bool   `json:"dont_learn"`
	GroupPolicyID      int    `json:"group_policy_id"`
	GroupPolicyIDHex   string `json:"group_policy_id_hex"`
}

// GPEFields is the Generic Protocol Extension overlay.
type GPEFields struct {
	NextProtocol     int    `json:"next_protocol"`
	NextProtocolName string `json:"next_protocol_name"`
}

// Decode parses a VXLAN packet from hex.
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
	if len(b) < 8 {
		return nil, fmt.Errorf("VXLAN header truncated (%d bytes; need ≥8)", len(b))
	}

	r := &Result{
		Flags:         int(b[0]),
		FlagsHex:      fmt.Sprintf("0x%02X", b[0]),
		IFlag:         b[0]&0x08 != 0,
		Reserved1Hex:  fmt.Sprintf("0x%02X%02X%02X", b[1], b[2], b[3]),
		Reserved1Zero: b[1] == 0 && b[2] == 0 && b[3] == 0,
		VNI:           uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6]),
		Reserved2:     int(b[7]),
		Reserved2Zero: b[7] == 0,
		TotalBytes:    len(b),
	}

	r.Variant = classifyVariant(r)

	if !r.IFlag {
		r.Notes = append(r.Notes,
			"I-flag (bit 3) is NOT set — RFC 7348 requires the I-flag to be set "+
				"in standard VXLAN to indicate the VNI is valid. This may be a "+
				"non-VXLAN packet, a malformed frame, or a non-standard variant.")
	}
	if !r.Reserved1Zero && r.Variant == "standard VXLAN (RFC 7348)" {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Reserved-1 field non-zero (%s) — standard VXLAN requires bytes 1-3 to "+
				"be zero. Investigate as middlebox abuse, GBP overlay, or corrupt frame.",
			r.Reserved1Hex))
	}
	if !r.Reserved2Zero && r.Variant == "standard VXLAN (RFC 7348)" {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Reserved-2 field non-zero (0x%02X) — standard VXLAN requires byte 7 to "+
				"be zero. Investigate as GPE overlay (Next Protocol field) or corrupt frame.",
			r.Reserved2))
	}

	// VXLAN-GBP extraction.
	if r.Variant == "VXLAN-GBP (Cisco Group-Based Policy)" {
		gbp := &GBPFields{
			GroupPolicyApplied: b[0]&0x80 != 0,
			DontLearn:          b[0]&0x40 != 0,
			GroupPolicyID:      int(binary.BigEndian.Uint16(b[2:4])),
		}
		gbp.GroupPolicyIDHex = fmt.Sprintf("0x%04X", gbp.GroupPolicyID)
		r.GBP = gbp
	}

	// VXLAN-GPE extraction.
	if r.Variant == "VXLAN-GPE (Generic Protocol Extension)" {
		r.GPE = &GPEFields{
			NextProtocol:     r.Reserved2,
			NextProtocolName: gpeNextProtocolName(r.Reserved2),
		}
	}

	// Inner Ethernet peek (only for standard VXLAN and VXLAN-GBP;
	// VXLAN-GPE may encapsulate non-Ethernet payloads).
	if r.Variant != "VXLAN-GPE (Generic Protocol Extension)" && len(b) >= 8+14 {
		eth := decodeInnerEthernet(b[8:])
		r.InnerEthernet = eth
	}

	return r, nil
}

func classifyVariant(r *Result) string {
	if !r.IFlag {
		return "non-VXLAN (I-flag not set)"
	}
	// VXLAN-GBP: bits 0 (G) or 4 (D) set in flags byte AND
	// the middle 16 bits of reserved-1 are interpretable as
	// a Group Policy ID.
	gFlag := r.Flags&0x80 != 0
	dFlag := r.Flags&0x40 != 0
	if (gFlag || dFlag) && r.Reserved2 == 0 {
		return "VXLAN-GBP (Cisco Group-Based Policy)"
	}
	// VXLAN-GPE: Reserved-2 byte is non-zero AND in the
	// documented Next Protocol range.
	if r.Reserved2 != 0 && r.Reserved2 <= 5 {
		return "VXLAN-GPE (Generic Protocol Extension)"
	}
	return "standard VXLAN (RFC 7348)"
}

func decodeInnerEthernet(b []byte) *InnerEthernet {
	if len(b) < 14 {
		return nil
	}
	ie := &InnerEthernet{
		DstMAC:         formatMAC(b[0:6]),
		SrcMAC:         formatMAC(b[6:12]),
		EtherType:      int(binary.BigEndian.Uint16(b[12:14])),
		PayloadOffset:  14,
		RemainingBytes: len(b) - 14,
	}
	ie.EtherTypeHex = fmt.Sprintf("0x%04X", ie.EtherType)
	ie.EtherTypeName = etherTypeName(ie.EtherType)
	// When the inner frame carries IP, decode the L3 packet in place via
	// internal/ipdecode so the encapsulated flow's addresses / protocol /
	// ports surface directly. Non-IP EtherTypes (ARP, 802.1Q VLAN tags,
	// MPLS, …) are left for their own decoders — no confidently-wrong output.
	if (ie.EtherType == 0x0800 || ie.EtherType == 0x86DD) && len(b) > 14 {
		if pkt, err := ipdecode.DecodeBytes(b[14:]); err == nil {
			ie.InnerPacket = pkt
		} else {
			ie.InnerDecodeError = err.Error()
		}
	}
	return ie
}

func gpeNextProtocolName(p int) string {
	switch p {
	case 1:
		return "IPv4"
	case 2:
		return "IPv6"
	case 3:
		return "Ethernet"
	case 4:
		return "NSH (Network Service Header)"
	case 5:
		return "MPLS"
	}
	return fmt.Sprintf("uncatalogued Next Protocol %d", p)
}

func etherTypeName(t int) string {
	switch t {
	case 0x0800:
		return "IPv4"
	case 0x0806:
		return "ARP"
	case 0x86DD:
		return "IPv6"
	case 0x8035:
		return "RARP"
	case 0x8100:
		return "802.1Q VLAN C-tag"
	case 0x88A8:
		return "802.1ad VLAN S-tag (QinQ)"
	case 0x8847:
		return "MPLS unicast"
	case 0x8848:
		return "MPLS multicast"
	case 0x8863:
		return "PPPoE Discovery"
	case 0x8864:
		return "PPPoE Session"
	case 0x888E:
		return "EAPOL (802.1X)"
	case 0x88CC:
		return "LLDP"
	case 0x88E5:
		return "MACsec (802.1AE)"
	}
	if t < 0x0600 {
		return fmt.Sprintf("length field (%d; 802.3 LLC frame)", t)
	}
	return fmt.Sprintf("EtherType 0x%04X (uncatalogued)", t)
}

func formatMAC(b []byte) string {
	if len(b) != 6 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		b[0], b[1], b[2], b[3], b[4], b[5])
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
