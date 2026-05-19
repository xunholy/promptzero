// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ipdecode parses raw IP packets (IPv4 + IPv6) plus
// the most-deployed next-layer headers (TCP, UDP, ICMP,
// ICMPv6). This is the foundational network-decode primitive
// every other application-layer Spec sits on top of —
// operators routinely paste raw pcap bytes that include the
// IP + transport headers, and pulling those out manually is
// tedious.
//
// # Wrap-vs-native judgement
//
// Native. IPv4 (RFC 791), IPv6 (RFC 8200), TCP (RFC 9293),
// UDP (RFC 768), ICMP (RFC 792), and ICMPv6 (RFC 4443) are
// all fully published with fixed-format headers. TCP options
// (RFC 9293 §3.2.5 + RFC 2018 / 7323) are a TLV list with a
// small dispatch table. Pasting a hex blob from Wireshark /
// tshark / tcpdump-raw / a network forensics dump is enough
// — no live capture, no kernel, no networking.
//
// # What this package covers
//
//   - **IPv4/IPv6 auto-detection** by the first nibble (4 or
//     6). Anything else is rejected.
//   - **IPv4 header** (RFC 791): version, IHL (header length
//     in 32-bit words), DSCP (Differentiated Services Code
//     Point) + ECN (Explicit Congestion Notification) broken
//     out of the ToS byte, total length, identification,
//     flags (DF / MF), fragment offset, TTL, protocol
//     (named per IANA registry: 1 ICMP / 2 IGMP / 6 TCP /
//     17 UDP / 41 IPv6 / 47 GRE / 50 ESP / 51 AH / 89 OSPF /
//     132 SCTP / 137 MPLS-in-IP), header checksum, source
//     and destination IPv4 addresses. Options field
//     surfaced as raw hex when IHL > 5.
//   - **IPv6 header** (RFC 8200): version, traffic class
//     (DSCP + ECN broken out), flow label, payload length,
//     next header (named the same as IPv4 protocol field),
//     hop limit, source + destination IPv6 addresses. Walks
//     extension headers (Hop-by-Hop 0, Routing 43,
//     Fragment 44, ESP 50, AH 51, Destination 60) and
//     surfaces them as a count + list with raw hex; the
//     final inner-next-header is what dispatches to the
//     transport-layer decoder.
//   - **TCP header** (RFC 9293): source port, destination
//     port, sequence number, acknowledgment number, data
//     offset, full 9-bit flag field broken out as named
//     bools (NS / CWR / ECE / URG / ACK / PSH / RST / SYN /
//     FIN), window size, checksum, urgent pointer, and
//     options walked as a TLV list with named decode for:
//   - 0 End of Option List (EOL)
//   - 1 No-Operation (NOP)
//   - 2 Maximum Segment Size (MSS)
//   - 3 Window Scale
//   - 4 SACK Permitted
//   - 5 SACK (block list)
//   - 8 Timestamps
//   - 34 TCP Fast Open Cookie
//   - **UDP header** (RFC 768): source port, destination
//     port, length, checksum.
//   - **ICMP** (RFC 792): type + code with name lookup for
//     0 Echo Reply, 3 Destination Unreachable (with 16 sub-
//     codes including Network/Host/Protocol/Port Unreachable
//     / Fragmentation Needed / Network/Host Unreachable for
//     ToS), 4 Source Quench, 5 Redirect, 8 Echo Request,
//     9 Router Advertisement, 10 Router Solicitation,
//     11 Time Exceeded (with sub-codes), 12 Parameter
//     Problem, 13 Timestamp Request, 14 Timestamp Reply.
//     For Echo Request/Reply (type 0/8): identifier +
//     sequence number broken out + payload hex.
//   - **ICMPv6** (RFC 4443): type + code with name lookup
//     for the error types (1 Destination Unreachable with
//     sub-codes / 2 Packet Too Big / 3 Time Exceeded /
//     4 Parameter Problem), the informational types (128
//     Echo Request / 129 Echo Reply with identifier +
//     sequence), and the NDP types (133 Router Solicitation
//     / 134 Router Advertisement / 135 Neighbor Solicitation
//     / 136 Neighbor Advertisement / 137 Redirect).
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Checksum validation — operators routinely paste hex
//     blobs from broken-checksum environments (offload, NAT,
//     mid-stream re-injection), and a "checksum invalid"
//     warning is more noise than signal. The captured
//     checksum is surfaced for operators who want to verify
//     independently.
//   - IPv4 fragment reassembly — the offset / MF flag /
//     identification are surfaced so callers can do their
//     own reassembly across packets.
//   - Ethernet / VLAN / MPLS framing — operators feed the
//     IP packet (the first byte must be a version nibble);
//     stripping L2 is the caller's job.
//   - GRE / IPSec ESP / AH inner-payload decode — the
//     protocol-name is surfaced but the encrypted /
//     encapsulated body is left as raw hex.
//   - Deep IPv6 extension header decode — Hop-by-Hop,
//     Routing, Destination Options have their own TLV
//     option lists (RFC 8200 §4.3 / 4.4 / 4.6) that warrant
//     a separate iteration; for now the next-header chain
//     is walked but the option lists are surfaced as raw hex.
package ipdecode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Packet is the decoded view of one IP packet.
type Packet struct {
	HexInput string `json:"hex_input"`
	Version  int    `json:"version"`
	IPv4     *IPv4  `json:"ipv4,omitempty"`
	IPv6     *IPv6  `json:"ipv6,omitempty"`

	// Transport / next-layer dispatch.
	ProtocolNumber int     `json:"protocol_number"`
	ProtocolName   string  `json:"protocol_name"`
	TCP            *TCP    `json:"tcp,omitempty"`
	UDP            *UDP    `json:"udp,omitempty"`
	ICMP           *ICMP   `json:"icmp,omitempty"`
	ICMPv6         *ICMPv6 `json:"icmpv6,omitempty"`
	PayloadHex     string  `json:"payload_hex,omitempty"`
}

// IPv4 is the decoded IPv4 header.
type IPv4 struct {
	IHL               int    `json:"ihl_words"`
	HeaderLengthB     int    `json:"header_length_bytes"`
	DSCP              int    `json:"dscp"`
	ECN               int    `json:"ecn"`
	ECNName           string `json:"ecn_name"`
	TotalLength       int    `json:"total_length"`
	Identification    int    `json:"identification"`
	FlagDontFragment  bool   `json:"flag_dont_fragment"`
	FlagMoreFragments bool   `json:"flag_more_fragments"`
	FragmentOffset    int    `json:"fragment_offset"`
	TTL               int    `json:"ttl"`
	HeaderChecksum    string `json:"header_checksum"`
	SourceIP          string `json:"source_ip"`
	DestinationIP     string `json:"destination_ip"`
	OptionsHex        string `json:"options_hex,omitempty"`
}

// IPv6 is the decoded IPv6 header.
type IPv6 struct {
	TrafficClass   int              `json:"traffic_class"`
	DSCP           int              `json:"dscp"`
	ECN            int              `json:"ecn"`
	ECNName        string           `json:"ecn_name"`
	FlowLabel      int              `json:"flow_label"`
	PayloadLength  int              `json:"payload_length"`
	NextHeader     int              `json:"next_header"`
	NextHeaderName string           `json:"next_header_name"`
	HopLimit       int              `json:"hop_limit"`
	SourceIP       string           `json:"source_ip"`
	DestinationIP  string           `json:"destination_ip"`
	Extensions     []*IPv6Extension `json:"extensions,omitempty"`
}

// IPv6Extension is one parsed IPv6 extension header.
type IPv6Extension struct {
	Number     int    `json:"number"`
	Name       string `json:"name"`
	LengthB    int    `json:"length_bytes"`
	NextHeader int    `json:"next_header"`
	DataHex    string `json:"data_hex,omitempty"`
}

// TCP is the decoded TCP header.
type TCP struct {
	SourcePort      int          `json:"source_port"`
	DestinationPort int          `json:"destination_port"`
	SequenceNumber  uint32       `json:"sequence_number"`
	AckNumber       uint32       `json:"ack_number"`
	DataOffset      int          `json:"data_offset_words"`
	HeaderLengthB   int          `json:"header_length_bytes"`
	FlagNS          bool         `json:"flag_ns"`
	FlagCWR         bool         `json:"flag_cwr"`
	FlagECE         bool         `json:"flag_ece"`
	FlagURG         bool         `json:"flag_urg"`
	FlagACK         bool         `json:"flag_ack"`
	FlagPSH         bool         `json:"flag_psh"`
	FlagRST         bool         `json:"flag_rst"`
	FlagSYN         bool         `json:"flag_syn"`
	FlagFIN         bool         `json:"flag_fin"`
	FlagsString     string       `json:"flags_string"`
	WindowSize      int          `json:"window_size"`
	Checksum        string       `json:"checksum"`
	UrgentPointer   int          `json:"urgent_pointer"`
	Options         []*TCPOption `json:"options,omitempty"`
	PayloadHex      string       `json:"payload_hex,omitempty"`
}

// TCPOption is one TCP option in the options list.
type TCPOption struct {
	Kind        int            `json:"kind"`
	Name        string         `json:"name"`
	Length      int            `json:"length"`
	DataHex     string         `json:"data_hex,omitempty"`
	MSS         int            `json:"mss,omitempty"`
	WindowScale int            `json:"window_scale,omitempty"`
	Timestamps  *TCPTimestamps `json:"timestamps,omitempty"`
	SACKBlocks  [][2]uint32    `json:"sack_blocks,omitempty"`
}

// TCPTimestamps is the option-8 TSval+TSecr pair.
type TCPTimestamps struct {
	TSval uint32 `json:"tsval"`
	TSecr uint32 `json:"tsecr"`
}

// UDP is the decoded UDP header.
type UDP struct {
	SourcePort      int    `json:"source_port"`
	DestinationPort int    `json:"destination_port"`
	Length          int    `json:"length"`
	Checksum        string `json:"checksum"`
	PayloadHex      string `json:"payload_hex,omitempty"`
}

// ICMP is the decoded ICMP header (RFC 792).
type ICMP struct {
	Type       int    `json:"type"`
	TypeName   string `json:"type_name"`
	Code       int    `json:"code"`
	CodeName   string `json:"code_name,omitempty"`
	Checksum   string `json:"checksum"`
	Identifier int    `json:"identifier,omitempty"`
	Sequence   int    `json:"sequence,omitempty"`
	BodyHex    string `json:"body_hex,omitempty"`
}

// ICMPv6 is the decoded ICMPv6 header (RFC 4443).
type ICMPv6 struct {
	Type       int    `json:"type"`
	TypeName   string `json:"type_name"`
	Code       int    `json:"code"`
	CodeName   string `json:"code_name,omitempty"`
	Checksum   string `json:"checksum"`
	Identifier int    `json:"identifier,omitempty"`
	Sequence   int    `json:"sequence,omitempty"`
	BodyHex    string `json:"body_hex,omitempty"`
}

// Decode parses a hex-encoded IP packet.
func Decode(hexBlob string) (*Packet, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw IP packet.
func DecodeBytes(b []byte) (*Packet, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("ipdecode: empty input")
	}
	version := int(b[0] >> 4)
	p := &Packet{
		HexInput: strings.ToUpper(hex.EncodeToString(b)),
		Version:  version,
	}
	switch version {
	case 4:
		return decodeIPv4(p, b)
	case 6:
		return decodeIPv6(p, b)
	}
	return nil, fmt.Errorf("ipdecode: first nibble = %d; expected 4 (IPv4) or 6 (IPv6)", version)
}

func decodeIPv4(p *Packet, b []byte) (*Packet, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("ipdecode: IPv4 header truncated (need 20 bytes, got %d)", len(b))
	}
	ihl := int(b[0] & 0x0F)
	headerLen := ihl * 4
	if headerLen < 20 || headerLen > len(b) {
		return nil, fmt.Errorf("ipdecode: IPv4 IHL=%d gives header length %d; out of range", ihl, headerLen)
	}
	tos := b[1]
	flagsFrag := binary.BigEndian.Uint16(b[6:8])
	v4 := &IPv4{
		IHL:               ihl,
		HeaderLengthB:     headerLen,
		DSCP:              int(tos >> 2),
		ECN:               int(tos & 0x03),
		ECNName:           ecnName(int(tos & 0x03)),
		TotalLength:       int(binary.BigEndian.Uint16(b[2:4])),
		Identification:    int(binary.BigEndian.Uint16(b[4:6])),
		FlagDontFragment:  flagsFrag&0x4000 != 0,
		FlagMoreFragments: flagsFrag&0x2000 != 0,
		FragmentOffset:    int(flagsFrag & 0x1FFF),
		TTL:               int(b[8]),
		HeaderChecksum:    fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[10:12])),
		SourceIP:          net.IP(b[12:16]).String(),
		DestinationIP:     net.IP(b[16:20]).String(),
	}
	if headerLen > 20 {
		v4.OptionsHex = strings.ToUpper(hex.EncodeToString(b[20:headerLen]))
	}
	p.IPv4 = v4
	p.ProtocolNumber = int(b[9])
	p.ProtocolName = protocolName(p.ProtocolNumber)
	payload := b[headerLen:]
	dispatchTransport(p, payload, p.ProtocolNumber)
	return p, nil
}

func decodeIPv6(p *Packet, b []byte) (*Packet, error) {
	if len(b) < 40 {
		return nil, fmt.Errorf("ipdecode: IPv6 header truncated (need 40 bytes, got %d)", len(b))
	}
	first4 := binary.BigEndian.Uint32(b[0:4])
	tc := int((first4 >> 20) & 0xFF)
	flow := int(first4 & 0x000FFFFF)
	v6 := &IPv6{
		TrafficClass:   tc,
		DSCP:           tc >> 2,
		ECN:            tc & 0x03,
		ECNName:        ecnName(tc & 0x03),
		FlowLabel:      flow,
		PayloadLength:  int(binary.BigEndian.Uint16(b[4:6])),
		NextHeader:     int(b[6]),
		NextHeaderName: protocolName(int(b[6])),
		HopLimit:       int(b[7]),
		SourceIP:       net.IP(b[8:24]).String(),
		DestinationIP:  net.IP(b[24:40]).String(),
	}
	p.IPv6 = v6

	// Walk extension headers.
	off := 40
	nextHdr := int(b[6])
	for isIPv6ExtensionHeader(nextHdr) && off+2 <= len(b) {
		extLen := (int(b[off+1]) + 1) * 8 // length is in 8-byte units, +1 because the first 8 bytes don't count
		// Fragment header (44) is a fixed 8 bytes.
		if nextHdr == 44 {
			extLen = 8
		}
		if off+extLen > len(b) {
			break
		}
		ext := &IPv6Extension{
			Number:     nextHdr,
			Name:       ipv6ExtensionName(nextHdr),
			LengthB:    extLen,
			NextHeader: int(b[off]),
			DataHex:    strings.ToUpper(hex.EncodeToString(b[off : off+extLen])),
		}
		v6.Extensions = append(v6.Extensions, ext)
		nextHdr = int(b[off])
		off += extLen
	}
	p.ProtocolNumber = nextHdr
	p.ProtocolName = protocolName(nextHdr)
	if off < len(b) {
		dispatchTransport(p, b[off:], nextHdr)
	}
	return p, nil
}

// dispatchTransport calls the right next-layer decoder based
// on the protocol / next-header number.
func dispatchTransport(p *Packet, body []byte, proto int) {
	switch proto {
	case 6:
		p.TCP = decodeTCP(body)
	case 17:
		p.UDP = decodeUDP(body)
	case 1:
		p.ICMP = decodeICMP(body)
	case 58:
		p.ICMPv6 = decodeICMPv6(body)
	default:
		if len(body) > 0 {
			p.PayloadHex = strings.ToUpper(hex.EncodeToString(body))
		}
	}
}

func decodeTCP(b []byte) *TCP {
	if len(b) < 20 {
		return nil
	}
	dataOffset := int(b[12] >> 4)
	headerLen := dataOffset * 4
	flags := binary.BigEndian.Uint16(b[12:14]) & 0x01FF
	t := &TCP{
		SourcePort:      int(binary.BigEndian.Uint16(b[0:2])),
		DestinationPort: int(binary.BigEndian.Uint16(b[2:4])),
		SequenceNumber:  binary.BigEndian.Uint32(b[4:8]),
		AckNumber:       binary.BigEndian.Uint32(b[8:12]),
		DataOffset:      dataOffset,
		HeaderLengthB:   headerLen,
		FlagNS:          flags&0x100 != 0,
		FlagCWR:         flags&0x080 != 0,
		FlagECE:         flags&0x040 != 0,
		FlagURG:         flags&0x020 != 0,
		FlagACK:         flags&0x010 != 0,
		FlagPSH:         flags&0x008 != 0,
		FlagRST:         flags&0x004 != 0,
		FlagSYN:         flags&0x002 != 0,
		FlagFIN:         flags&0x001 != 0,
		WindowSize:      int(binary.BigEndian.Uint16(b[14:16])),
		Checksum:        fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[16:18])),
		UrgentPointer:   int(binary.BigEndian.Uint16(b[18:20])),
	}
	t.FlagsString = tcpFlagsString(t)
	if headerLen > 20 && headerLen <= len(b) {
		t.Options = decodeTCPOptions(b[20:headerLen])
	}
	if headerLen < len(b) {
		t.PayloadHex = strings.ToUpper(hex.EncodeToString(b[headerLen:]))
	}
	return t
}

// tcpFlagsString renders the conventional Wireshark-style
// flag string (e.g. "SYN, ACK" or "SYN" or "FIN, ACK").
func tcpFlagsString(t *TCP) string {
	var flags []string
	if t.FlagSYN {
		flags = append(flags, "SYN")
	}
	if t.FlagACK {
		flags = append(flags, "ACK")
	}
	if t.FlagPSH {
		flags = append(flags, "PSH")
	}
	if t.FlagRST {
		flags = append(flags, "RST")
	}
	if t.FlagFIN {
		flags = append(flags, "FIN")
	}
	if t.FlagURG {
		flags = append(flags, "URG")
	}
	if t.FlagECE {
		flags = append(flags, "ECE")
	}
	if t.FlagCWR {
		flags = append(flags, "CWR")
	}
	if t.FlagNS {
		flags = append(flags, "NS")
	}
	return strings.Join(flags, ", ")
}

func decodeTCPOptions(opt []byte) []*TCPOption {
	var out []*TCPOption
	off := 0
	for off < len(opt) {
		kind := int(opt[off])
		switch kind {
		case 0: // EOL
			out = append(out, &TCPOption{Kind: kind, Name: "End of Option List (EOL)", Length: 1})
			return out
		case 1: // NOP
			out = append(out, &TCPOption{Kind: kind, Name: "No-Operation (NOP)", Length: 1})
			off++
			continue
		}
		if off+1 >= len(opt) {
			break
		}
		length := int(opt[off+1])
		if length < 2 || off+length > len(opt) {
			break
		}
		o := &TCPOption{Kind: kind, Name: tcpOptionName(kind), Length: length}
		body := opt[off+2 : off+length]
		o.DataHex = strings.ToUpper(hex.EncodeToString(body))
		switch kind {
		case 2: // MSS
			if len(body) == 2 {
				o.MSS = int(binary.BigEndian.Uint16(body))
			}
		case 3: // Window Scale
			if len(body) == 1 {
				o.WindowScale = int(body[0])
			}
		case 5: // SACK blocks: pairs of (left, right) uint32
			for i := 0; i+8 <= len(body); i += 8 {
				left := binary.BigEndian.Uint32(body[i : i+4])
				right := binary.BigEndian.Uint32(body[i+4 : i+8])
				o.SACKBlocks = append(o.SACKBlocks, [2]uint32{left, right})
			}
		case 8: // Timestamps: TSval + TSecr
			if len(body) == 8 {
				o.Timestamps = &TCPTimestamps{
					TSval: binary.BigEndian.Uint32(body[0:4]),
					TSecr: binary.BigEndian.Uint32(body[4:8]),
				}
			}
		}
		out = append(out, o)
		off += length
	}
	return out
}

func decodeUDP(b []byte) *UDP {
	if len(b) < 8 {
		return nil
	}
	u := &UDP{
		SourcePort:      int(binary.BigEndian.Uint16(b[0:2])),
		DestinationPort: int(binary.BigEndian.Uint16(b[2:4])),
		Length:          int(binary.BigEndian.Uint16(b[4:6])),
		Checksum:        fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[6:8])),
	}
	if len(b) > 8 {
		u.PayloadHex = strings.ToUpper(hex.EncodeToString(b[8:]))
	}
	return u
}

func decodeICMP(b []byte) *ICMP {
	if len(b) < 4 {
		return nil
	}
	typ := int(b[0])
	code := int(b[1])
	c := &ICMP{
		Type:     typ,
		TypeName: icmpTypeName(typ),
		Code:     code,
		CodeName: icmpCodeName(typ, code),
		Checksum: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[2:4])),
	}
	if typ == 0 || typ == 8 {
		// Echo Reply / Echo Request: identifier + sequence
		if len(b) >= 8 {
			c.Identifier = int(binary.BigEndian.Uint16(b[4:6]))
			c.Sequence = int(binary.BigEndian.Uint16(b[6:8]))
			if len(b) > 8 {
				c.BodyHex = strings.ToUpper(hex.EncodeToString(b[8:]))
			}
		}
	} else if len(b) > 4 {
		c.BodyHex = strings.ToUpper(hex.EncodeToString(b[4:]))
	}
	return c
}

func decodeICMPv6(b []byte) *ICMPv6 {
	if len(b) < 4 {
		return nil
	}
	typ := int(b[0])
	code := int(b[1])
	c := &ICMPv6{
		Type:     typ,
		TypeName: icmpv6TypeName(typ),
		Code:     code,
		CodeName: icmpv6CodeName(typ, code),
		Checksum: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[2:4])),
	}
	if typ == 128 || typ == 129 {
		// Echo Request / Reply
		if len(b) >= 8 {
			c.Identifier = int(binary.BigEndian.Uint16(b[4:6]))
			c.Sequence = int(binary.BigEndian.Uint16(b[6:8]))
			if len(b) > 8 {
				c.BodyHex = strings.ToUpper(hex.EncodeToString(b[8:]))
			}
		}
	} else if len(b) > 4 {
		c.BodyHex = strings.ToUpper(hex.EncodeToString(b[4:]))
	}
	return c
}

func ecnName(ecn int) string {
	switch ecn {
	case 0:
		return "Not-ECT (no ECN)"
	case 1:
		return "ECT(1)"
	case 2:
		return "ECT(0)"
	case 3:
		return "CE (Congestion Experienced)"
	}
	return ""
}

func protocolName(p int) string {
	switch p {
	case 0:
		return "HOPOPT (IPv6 Hop-by-Hop)"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IPv4-in-IPv4"
	case 6:
		return "TCP"
	case 8:
		return "EGP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6-in-IPv4"
	case 43:
		return "IPv6 Routing"
	case 44:
		return "IPv6 Fragment"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 59:
		return "IPv6 No Next Header"
	case 60:
		return "IPv6 Destination Options"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	case 137:
		return "MPLS-in-IP"
	}
	return fmt.Sprintf("Unassigned (%d)", p)
}

func isIPv6ExtensionHeader(nh int) bool {
	switch nh {
	case 0, 43, 44, 50, 51, 60:
		return true
	}
	return false
}

func ipv6ExtensionName(nh int) string {
	switch nh {
	case 0:
		return "Hop-by-Hop Options"
	case 43:
		return "Routing"
	case 44:
		return "Fragment"
	case 50:
		return "Encapsulating Security Payload (ESP)"
	case 51:
		return "Authentication Header (AH)"
	case 60:
		return "Destination Options"
	}
	return ""
}

func tcpOptionName(kind int) string {
	switch kind {
	case 0:
		return "End of Option List (EOL)"
	case 1:
		return "No-Operation (NOP)"
	case 2:
		return "Maximum Segment Size (MSS)"
	case 3:
		return "Window Scale"
	case 4:
		return "SACK Permitted"
	case 5:
		return "SACK"
	case 8:
		return "Timestamps"
	case 28:
		return "User Timeout"
	case 29:
		return "TCP-AO (Authentication)"
	case 34:
		return "TCP Fast Open Cookie"
	}
	return fmt.Sprintf("Unknown TCP option %d", kind)
}

func icmpTypeName(t int) string {
	switch t {
	case 0:
		return "Echo Reply"
	case 3:
		return "Destination Unreachable"
	case 4:
		return "Source Quench (deprecated)"
	case 5:
		return "Redirect"
	case 8:
		return "Echo Request"
	case 9:
		return "Router Advertisement"
	case 10:
		return "Router Solicitation"
	case 11:
		return "Time Exceeded"
	case 12:
		return "Parameter Problem"
	case 13:
		return "Timestamp Request"
	case 14:
		return "Timestamp Reply"
	case 17:
		return "Address Mask Request"
	case 18:
		return "Address Mask Reply"
	}
	return fmt.Sprintf("Unassigned (%d)", t)
}

func icmpCodeName(typ, code int) string {
	switch typ {
	case 3:
		switch code {
		case 0:
			return "Network Unreachable"
		case 1:
			return "Host Unreachable"
		case 2:
			return "Protocol Unreachable"
		case 3:
			return "Port Unreachable"
		case 4:
			return "Fragmentation Needed and Don't Fragment was Set"
		case 5:
			return "Source Route Failed"
		case 6:
			return "Destination Network Unknown"
		case 7:
			return "Destination Host Unknown"
		case 9:
			return "Network Administratively Prohibited"
		case 10:
			return "Host Administratively Prohibited"
		case 11:
			return "Network Unreachable for ToS"
		case 12:
			return "Host Unreachable for ToS"
		case 13:
			return "Communication Administratively Prohibited"
		}
	case 5:
		switch code {
		case 0:
			return "Redirect for Network"
		case 1:
			return "Redirect for Host"
		case 2:
			return "Redirect for ToS and Network"
		case 3:
			return "Redirect for ToS and Host"
		}
	case 11:
		switch code {
		case 0:
			return "TTL Exceeded in Transit"
		case 1:
			return "Fragment Reassembly Time Exceeded"
		}
	}
	return ""
}

func icmpv6TypeName(t int) string {
	switch t {
	case 1:
		return "Destination Unreachable"
	case 2:
		return "Packet Too Big"
	case 3:
		return "Time Exceeded"
	case 4:
		return "Parameter Problem"
	case 128:
		return "Echo Request"
	case 129:
		return "Echo Reply"
	case 130:
		return "Multicast Listener Query"
	case 131:
		return "Multicast Listener Report"
	case 132:
		return "Multicast Listener Done"
	case 133:
		return "Router Solicitation"
	case 134:
		return "Router Advertisement"
	case 135:
		return "Neighbor Solicitation"
	case 136:
		return "Neighbor Advertisement"
	case 137:
		return "Redirect"
	case 143:
		return "Multicast Listener Discovery v2 Report"
	}
	return fmt.Sprintf("Unassigned (%d)", t)
}

func icmpv6CodeName(typ, code int) string {
	switch typ {
	case 1:
		switch code {
		case 0:
			return "No route to destination"
		case 1:
			return "Communication with destination administratively prohibited"
		case 2:
			return "Beyond scope of source address"
		case 3:
			return "Address unreachable"
		case 4:
			return "Port unreachable"
		case 5:
			return "Source address failed ingress/egress policy"
		case 6:
			return "Reject route to destination"
		}
	case 3:
		switch code {
		case 0:
			return "Hop limit exceeded in transit"
		case 1:
			return "Fragment reassembly time exceeded"
		}
	case 4:
		switch code {
		case 0:
			return "Erroneous header field encountered"
		case 1:
			return "Unrecognized Next Header type encountered"
		case 2:
			return "Unrecognized IPv6 option encountered"
		}
	}
	return ""
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("ipdecode: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ipdecode: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
