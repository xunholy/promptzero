// Package geneve decodes Generic Network Virtualization
// Encapsulation packets per RFC 8926.
//
// Wrap-vs-native judgement
//
//	Native. RFC 8926 is fully public; Geneve is an 8-byte
//	fixed header plus a TLV options block plus the
//	encapsulated original payload. No crypto, no
//	compression, no varints. Operators paste UDP-payload
//	bytes (standard UDP dest port 6081) from a Wireshark
//	Follow-UDP-Stream view, a `tcpdump -X udp port 6081`
//	line, an OVS / VMware NSX-T debug capture, or any
//	Geneve-emitting tool and get the documented header +
//	options + inner protocol identification.
//
// What this package covers
//
//   - **8-byte fixed header** (RFC 8926 §3.4):
//
//   - byte 0: Version (2 bits, currently 0) + Option
//     Length (6 bits, in 4-byte words; 0 means no options,
//     up to 0x3F = 252 bytes of options).
//
//   - byte 1: O (OAM packet, bit 7) + C (Critical options
//     present, bit 6) + 6 reserved bits (must be 0).
//
//   - bytes 2-3: Protocol Type (EtherType of the
//     encapsulated payload). 0x6558 Transparent Ethernet
//     Bridging is the canonical case (VMware NSX-T, OVN);
//     0x0800 IPv4 / 0x86DD IPv6 / 0x8847 MPLS unicast /
//     0x894F NSH are also catalogued.
//
//   - bytes 4-6: VNI (24-bit Virtual Network Identifier;
//     like a 24-bit VLAN ID, 16M possible).
//
//   - byte 7: Reserved (must be 0).
//
//   - **TLV options walker** — each option is 4-byte
//     aligned:
//
//   - bytes 0-1: Option Class (16-bit BE; IANA assigned).
//     Class 0x0000-0x00FF = IETF standardised, 0x0100+ =
//     vendor (often a Private Enterprise Number).
//
//   - byte 2: Type (8 bits; bit 7 = C critical option
//     flag, bits 0-6 = type-within-class).
//
//   - byte 3: Reserved (3 bits) + Option Length (5 bits,
//     in 4-byte words; max 124 bytes of option data).
//
//   - bytes 4+: Option Data (Length × 4 bytes).
//
//   - **Option Class name table** — 6-entry catalogue of
//     well-known classes:
//
//   - 0x0000 Reserved
//
//   - 0x0100 Linux (used by OVN / OVS)
//
//   - 0x0101 VMware (NSX-T)
//
//   - 0x0102 Mellanox / NVIDIA
//
//   - 0x0103 Cisco
//
//   - 0x0104 Oracle
//
//   - **Inner payload decode** — for Protocol Type 0x6558
//     (Transparent Ethernet Bridging), surface the encapsulated
//     dst MAC + src MAC + inner EtherType (13-entry name table),
//     and when that EtherType is IPv4/IPv6 decode the inner L3
//     packet in place via internal/ipdecode. For Protocol Type
//     0x0800 / 0x86DD the inner payload IS an IP packet and is
//     decoded directly. Either way the encapsulated flow's
//     addresses / protocol / ports surface; a payload that does
//     not parse as IP is reported with an error and left as hex.
//     Other Protocol Types (MPLS, NSH, …) are left as raw hex.
//
//   - **Conformance check** — Version != 0 surfaces a Note;
//     non-zero reserved bits surface a Note; critical option
//     (C bit) detected surfaces a Note flagging that the
//     transit nodes MUST process and not drop it.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP / IP framing — feed the UDP payload bytes after
//     the outer IP+UDP headers (standard outer UDP dest port
//     6081).
//
//   - Non-IP inner payloads (802.1Q VLAN tags inside a TEB
//     frame, MPLS, NSH, …) — left for `vlan_decode` / their own
//     decoders; only IPv4 / IPv6 inner payloads are decoded here.
//
//   - Vendor-specific option data dissection — only the
//     class + type + length are surfaced; the option data
//     body is hex.
//
//   - VXLAN (RFC 7348) — handled by `vxlan_decode`; the two
//     are similar overlays but Geneve is the more flexible /
//     modern alternative.
package geneve

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ipdecode"
)

// Result is the top-level decoded view.
type Result struct {
	Version           int      `json:"version"`
	OptionLengthW     int      `json:"option_length_words"`
	OptionLengthBytes int      `json:"option_length_bytes"`
	OAM               bool     `json:"oam_packet"`
	Critical          bool     `json:"critical_options_present"`
	FlagsByte1Hex     string   `json:"flags_byte1_hex"`
	Reserved1Zero     bool     `json:"reserved_flags_zero"`
	ProtocolType      int      `json:"protocol_type"`
	ProtocolTypeHex   string   `json:"protocol_type_hex"`
	ProtocolName      string   `json:"protocol_name"`
	VNI               uint32   `json:"vni"`
	Reserved2         int      `json:"reserved_byte"`
	Reserved2Zero     bool     `json:"reserved_byte_zero"`
	Options           []Option `json:"options,omitempty"`
	OptionCount       int      `json:"option_count"`

	InnerEthernet    *InnerEthernet   `json:"inner_ethernet,omitempty"`
	InnerPacket      *ipdecode.Packet `json:"inner_packet,omitempty"`
	InnerDecodeError string           `json:"inner_decode_error,omitempty"`
	PayloadHex       string           `json:"payload_hex,omitempty"`
	PayloadLength    int              `json:"payload_length"`

	HeaderBytes int      `json:"header_bytes"`
	TotalBytes  int      `json:"total_bytes"`
	Notes       []string `json:"notes,omitempty"`
}

// Option is one TLV option.
type Option struct {
	Class       int    `json:"class"`
	ClassHex    string `json:"class_hex"`
	ClassName   string `json:"class_name"`
	Type        int    `json:"type"`
	CFlag       bool   `json:"critical"`
	TypeInClass int    `json:"type_in_class"`
	LengthW     int    `json:"length_words"`
	LengthBytes int    `json:"length_bytes"`
	DataHex     string `json:"data_hex,omitempty"`
}

// InnerEthernet is the dst MAC + src MAC + EtherType peek for
// the canonical Geneve-over-TEB case.
type InnerEthernet struct {
	DstMAC           string           `json:"dst_mac"`
	SrcMAC           string           `json:"src_mac"`
	EtherType        int              `json:"ether_type"`
	EtherTypeHex     string           `json:"ether_type_hex"`
	EtherTypeName    string           `json:"ether_type_name"`
	RemainingBytes   int              `json:"remaining_bytes"`
	InnerPacket      *ipdecode.Packet `json:"inner_packet,omitempty"`
	InnerDecodeError string           `json:"inner_decode_error,omitempty"`
}

// Decode parses a Geneve packet from hex.
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
		return nil, fmt.Errorf("header truncated (%d bytes; need ≥8 for Geneve fixed header)",
			len(b))
	}

	r := &Result{
		TotalBytes:        len(b),
		Version:           int(b[0] >> 6),
		OptionLengthW:     int(b[0] & 0x3F),
		OptionLengthBytes: int(b[0]&0x3F) * 4,
		OAM:               b[1]&0x80 != 0,
		Critical:          b[1]&0x40 != 0,
		FlagsByte1Hex:     fmt.Sprintf("0x%02X", b[1]),
		Reserved1Zero:     b[1]&0x3F == 0,
		ProtocolType:      int(binary.BigEndian.Uint16(b[2:4])),
		VNI:               uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6]),
		Reserved2:         int(b[7]),
		Reserved2Zero:     b[7] == 0,
	}
	r.ProtocolTypeHex = fmt.Sprintf("0x%04X", r.ProtocolType)
	r.ProtocolName = protocolName(r.ProtocolType)

	if r.Version != 0 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Geneve Version is %d; RFC 8926 §3.4 currently defines only Version 0. "+
				"Discard or quarantine — Version-mismatched packets must be dropped per §5.",
			r.Version))
	}
	if !r.Reserved1Zero {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"reserved bits in flags byte non-zero (0x%02X) — RFC 8926 §3.4 requires "+
				"these 6 bits to be 0 and ignored on receive",
			b[1]&0x3F))
	}
	if !r.Reserved2Zero {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"reserved byte 7 non-zero (0x%02X) — RFC 8926 §3.4 requires it to be 0",
			r.Reserved2))
	}
	if r.Critical {
		r.Notes = append(r.Notes,
			"C (Critical options present) flag is set — transit nodes MUST process "+
				"the critical options or drop the packet per RFC 8926 §3.4")
	}

	off := 8
	if 8+r.OptionLengthBytes > len(b) {
		return nil, fmt.Errorf("declared options length %d bytes exceeds buffer (%d available)",
			r.OptionLengthBytes, len(b)-8)
	}
	optEnd := 8 + r.OptionLengthBytes
	for off < optEnd {
		if off+4 > len(b) {
			return nil, fmt.Errorf("option header truncated at offset %d", off)
		}
		opt := Option{
			Class:   int(binary.BigEndian.Uint16(b[off : off+2])),
			Type:    int(b[off+2]),
			LengthW: int(b[off+3] & 0x1F),
		}
		opt.ClassHex = fmt.Sprintf("0x%04X", opt.Class)
		opt.ClassName = optionClassName(opt.Class)
		opt.CFlag = opt.Type&0x80 != 0
		opt.TypeInClass = opt.Type & 0x7F
		opt.LengthBytes = opt.LengthW * 4
		dataEnd := off + 4 + opt.LengthBytes
		if dataEnd > optEnd {
			return nil, fmt.Errorf("option at offset %d (class 0x%04X) data length %d exceeds options block",
				off, opt.Class, opt.LengthBytes)
		}
		if opt.LengthBytes > 0 {
			opt.DataHex = strings.ToUpper(hex.EncodeToString(b[off+4 : dataEnd]))
		}
		r.Options = append(r.Options, opt)
		off = dataEnd
	}
	r.OptionCount = len(r.Options)
	r.HeaderBytes = off

	// Inner payload peek.
	payload := b[off:]
	r.PayloadLength = len(payload)
	switch {
	case r.ProtocolType == 0x6558 && len(payload) >= 14:
		// Transparent Ethernet Bridging — inner Ethernet frame.
		r.InnerEthernet = decodeInnerEthernet(payload)
	case (r.ProtocolType == 0x0800 || r.ProtocolType == 0x86DD) && len(payload) > 0:
		// Inner payload is an IP packet directly — decode it in place.
		setPayloadHex(r, payload)
		if pkt, err := ipdecode.DecodeBytes(payload); err == nil {
			r.InnerPacket = pkt
		} else {
			r.InnerDecodeError = err.Error()
		}
	case len(payload) > 0:
		setPayloadHex(r, payload)
	}

	return r, nil
}

func setPayloadHex(r *Result, payload []byte) {
	if len(payload) > 256 {
		r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload[:256])) + "..."
	} else {
		r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
	}
}

func decodeInnerEthernet(b []byte) *InnerEthernet {
	if len(b) < 14 {
		return nil
	}
	ie := &InnerEthernet{
		DstMAC:         formatMAC(b[0:6]),
		SrcMAC:         formatMAC(b[6:12]),
		EtherType:      int(binary.BigEndian.Uint16(b[12:14])),
		RemainingBytes: len(b) - 14,
	}
	ie.EtherTypeHex = fmt.Sprintf("0x%04X", ie.EtherType)
	ie.EtherTypeName = etherTypeName(ie.EtherType)
	// When the inner frame carries IP, decode the L3 packet in place.
	if (ie.EtherType == 0x0800 || ie.EtherType == 0x86DD) && len(b) > 14 {
		if pkt, err := ipdecode.DecodeBytes(b[14:]); err == nil {
			ie.InnerPacket = pkt
		} else {
			ie.InnerDecodeError = err.Error()
		}
	}
	return ie
}

func protocolName(t int) string {
	switch t {
	case 0x6558:
		return "Transparent Ethernet Bridging"
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0x8847:
		return "MPLS unicast"
	case 0x8848:
		return "MPLS multicast"
	case 0x894F:
		return "NSH (Network Service Header)"
	case 0x0806:
		return "ARP"
	}
	return fmt.Sprintf("EtherType 0x%04X (uncatalogued)", t)
}

func optionClassName(c int) string {
	switch c {
	case 0x0000:
		return "Reserved (IETF)"
	case 0x0001:
		return "IETF standardised (class 0x0001)"
	case 0x0100:
		return "Linux / Open vSwitch / OVN"
	case 0x0101:
		return "VMware (NSX-T)"
	case 0x0102:
		return "Mellanox / NVIDIA"
	case 0x0103:
		return "Cisco Systems"
	case 0x0104:
		return "Oracle"
	}
	if c >= 0x0001 && c <= 0x00FF {
		return fmt.Sprintf("IETF standardised (class 0x%04X)", c)
	}
	if c >= 0x0100 && c <= 0xFEFF {
		return fmt.Sprintf("vendor (class 0x%04X — PEN-associated)", c)
	}
	if c >= 0xFF00 {
		return fmt.Sprintf("experimental / unassigned (class 0x%04X)", c)
	}
	return fmt.Sprintf("class 0x%04X", c)
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
