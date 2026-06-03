// Package icmp decodes ICMP (RFC 792) and ICMPv6 (RFC 4443 +
// 4861 for Neighbor Discovery) packets.
//
// Wrap-vs-native judgement
//
//	Native. Both ICMP and ICMPv6 wire formats are fully
//	public IETF specs with tight fixed-layout headers
//	(type / code / checksum / rest-of-header) and a small,
//	well-documented per-type body catalogue. Neighbor
//	Discovery (RFC 4861) layers a simple option TLV walker
//	on top of NDP message bodies. Operators paste the bytes
//	starting at the ICMP type field (after the IPv4/IPv6
//	header strip) from a Wireshark Follow-IP-Stream, a
//	`tcpdump -X icmp` line, or any packet capture and get
//	the documented type/code names plus per-type body
//	dissection. Pure offline parser, no state, no crypto.
//
// What this package covers
//
//   - Auto-detect ICMPv4 vs ICMPv6: when the caller specifies
//     `version` ("v4" or "v6") we honour it. Otherwise we
//     heuristic: types ≥ 128 are ICMPv6 (echo + NDP +
//     MLD live there); types 1-30 default to ICMPv4 (where
//     they collide on Destination Unreachable / Time
//     Exceeded the v4 interpretation is chosen as the more
//     common one).
//
//   - Common header (4 bytes): Type + Code + Checksum (BE).
//     The checksum is surfaced as hex; verification requires
//     the pseudo-header for ICMPv6 (out of scope at this
//     layer).
//
//   - ICMPv4 types decoded with names + codes:
//     0 Echo Reply, 3 Destination Unreachable (codes 0-15),
//     4 Source Quench (deprecated), 5 Redirect (codes 0-3),
//     8 Echo Request, 9 Router Advertisement, 10 Router
//     Solicitation, 11 Time Exceeded (codes 0-1), 12
//     Parameter Problem (codes 0-2), 13 Timestamp, 14
//     Timestamp Reply, 15 Information Request (deprecated),
//     16 Information Reply (deprecated), 17 Address Mask
//     Request, 18 Address Mask Reply, 30 Traceroute (deprecated).
//
//   - ICMPv6 types decoded with names + codes (RFC 4443):
//     1 Destination Unreachable (codes 0-7), 2 Packet Too
//     Big, 3 Time Exceeded (codes 0-1), 4 Parameter Problem
//     (codes 0-3), 128 Echo Request, 129 Echo Reply, 130-132
//     MLD (Multicast Listener), 133 Router Solicitation,
//     134 Router Advertisement, 135 Neighbor Solicitation,
//     136 Neighbor Advertisement, 137 Redirect, 143 MLDv2.
//
//   - Per-type body decoding (headline fields):
//
//   - Echo Request/Reply (v4 type 8/0; v6 type 128/129):
//     Identifier (uint16 BE) + Sequence (uint16 BE) +
//     Data (raw bytes). Identifier+Sequence are how `ping`
//     correlates request/reply pairs.
//
//   - Destination Unreachable / Time Exceeded / Parameter
//     Problem (v4 type 3/11/12; plus v6 Destination Unreachable
//     type 1 and Time Exceeded type 3): "unused" field surfaced
//     as hex; the embedded original IP packet (the IP header + at
//     least the first 8 bytes of its payload that the error
//     quotes) is decoded in place via internal/ipdecode — so the
//     offending flow's addresses, protocol and (for UDP, or a
//     long-enough TCP quote) ports are surfaced directly. A quote
//     that does not parse as IP is reported with an error and the
//     raw hex is preserved.
//
//   - Redirect (v4 type 5): Gateway IPv4 address + embedded
//     original packet.
//
//   - Neighbor Solicitation / Advertisement (v6 type 135 /
//     136): Reserved field + Target Address (16 bytes
//     formatted as IPv6) + Options (TLV walker per RFC
//     4861 §4 — type/length(in-units-of-8)/value, with
//     5-entry name table: 1 Source Link-Layer Address,
//     2 Target Link-Layer Address, 3 Prefix Information,
//     4 Redirected Header, 5 MTU).
//
//   - Router Advertisement (v6 type 134): Cur Hop Limit +
//     M/O/H flags + Router Lifetime (uint16) + Reachable
//     Time (uint32) + Retrans Timer (uint32) + Options.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IPv4 / IPv6 header parsing — feed the ICMP bytes after
//     stripping the IP header (already handled by
//     `ip_packet_decode`).
//
//   - Checksum verification — would require the IPv6 pseudo-
//     header for v6; v4 ICMP checksum is computable but the
//     operator can sanity-check by comparing the captured
//     value against the documented value.
//
//   - MLD / MLDv2 group-record dissection — only the message
//     type name is surfaced.
//
//   - Per-NDP-option deep parsing beyond the name (option-
//     specific body fields, e.g. Prefix Information's
//     full layout, are surfaced as raw hex).
package icmp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/xunholy/promptzero/internal/ipdecode"
)

// Result is the top-level decoded view.
type Result struct {
	Version     string `json:"version"` // "v4" or "v6"
	Type        int    `json:"type"`
	TypeName    string `json:"type_name"`
	Code        int    `json:"code"`
	CodeName    string `json:"code_name,omitempty"`
	ChecksumHex string `json:"checksum_hex"`
	TotalBytes  int    `json:"total_bytes"`

	Echo              *Echo           `json:"echo,omitempty"`
	DestUnreachable   *EmbeddedPacket `json:"destination_unreachable,omitempty"`
	TimeExceeded      *EmbeddedPacket `json:"time_exceeded,omitempty"`
	ParameterProblem  *EmbeddedPacket `json:"parameter_problem,omitempty"`
	Redirect          *RedirectV4     `json:"redirect,omitempty"`
	PacketTooBig      *PacketTooBig   `json:"packet_too_big,omitempty"`
	NeighborSolicit   *NDPNeighbor    `json:"neighbor_solicitation,omitempty"`
	NeighborAdvertise *NDPNeighbor    `json:"neighbor_advertisement,omitempty"`
	RouterSolicit     *NDPRouterSol   `json:"router_solicitation,omitempty"`
	RouterAdvertise   *NDPRouterAdv   `json:"router_advertisement,omitempty"`
	RawHex            string          `json:"raw_body_hex,omitempty"`
}

// Echo is the body of Echo Request/Reply (v4 type 8/0, v6
// type 128/129).
type Echo struct {
	Identifier uint16 `json:"identifier"`
	Sequence   uint16 `json:"sequence"`
	DataHex    string `json:"data_hex,omitempty"`
	DataLen    int    `json:"data_length"`
}

// EmbeddedPacket is what v4 error messages carry — the unused
// 32-bit field plus the embedded original IP header + 8 bytes
// of payload (per RFC 792 §3).
type EmbeddedPacket struct {
	UnusedHex           string           `json:"unused_hex"`
	EmbeddedOriginalHex string           `json:"embedded_original_ip_packet_hex"`
	EmbeddedDecoded     *ipdecode.Packet `json:"embedded_decoded,omitempty"`
	EmbeddedDecodeError string           `json:"embedded_decode_error,omitempty"`
}

// RedirectV4 is ICMPv4 Redirect (type 5).
type RedirectV4 struct {
	GatewayIP           string           `json:"gateway_ip"`
	EmbeddedOriginalHex string           `json:"embedded_original_ip_packet_hex"`
	EmbeddedDecoded     *ipdecode.Packet `json:"embedded_decoded,omitempty"`
	EmbeddedDecodeError string           `json:"embedded_decode_error,omitempty"`
}

// PacketTooBig is ICMPv6 type 2.
type PacketTooBig struct {
	MTU                 uint32           `json:"mtu"`
	EmbeddedOriginalHex string           `json:"embedded_original_ip_packet_hex,omitempty"`
	EmbeddedDecoded     *ipdecode.Packet `json:"embedded_decoded,omitempty"`
	EmbeddedDecodeError string           `json:"embedded_decode_error,omitempty"`
}

// NDPNeighbor is Neighbor Solicit / Advertise (v6 type 135 / 136).
type NDPNeighbor struct {
	Flags         string      `json:"flags,omitempty"` // for NA: R/S/O
	TargetAddress string      `json:"target_address"`
	Options       []NDPOption `json:"options,omitempty"`
}

// NDPRouterSol is Router Solicitation (v6 type 133).
type NDPRouterSol struct {
	Options []NDPOption `json:"options,omitempty"`
}

// NDPRouterAdv is Router Advertisement (v6 type 134).
type NDPRouterAdv struct {
	CurHopLimit    int         `json:"cur_hop_limit"`
	Flags          string      `json:"flags"`
	RouterLifetime uint16      `json:"router_lifetime"`
	ReachableTime  uint32      `json:"reachable_time_ms"`
	RetransTimer   uint32      `json:"retrans_timer_ms"`
	Options        []NDPOption `json:"options,omitempty"`
}

// NDPOption is one TLV option from RFC 4861 §4.6.
type NDPOption struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	LengthW8 int    `json:"length_units_of_8"`
	BodyHex  string `json:"body_hex,omitempty"`
}

// Decode parses an ICMP or ICMPv6 packet from hex. If version
// is "" (empty), the version is auto-detected by the type-byte
// heuristic. Otherwise pass "v4" or "v6" explicitly.
func Decode(hexStr, version string) (*Result, error) {
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
		return nil, fmt.Errorf("ICMP header truncated (%d bytes; need ≥4)", len(b))
	}

	r := &Result{
		Type:        int(b[0]),
		Code:        int(b[1]),
		ChecksumHex: fmt.Sprintf("%04X", binary.BigEndian.Uint16(b[2:4])),
		TotalBytes:  len(b),
	}
	r.Version = pickVersion(version, r.Type)

	if r.Version == "v6" {
		r.TypeName = v6TypeName(r.Type)
		r.CodeName = v6CodeName(r.Type, r.Code)
	} else {
		r.TypeName = v4TypeName(r.Type)
		r.CodeName = v4CodeName(r.Type, r.Code)
	}

	body := b[4:]
	switch {
	case r.Version == "v4" && (r.Type == 0 || r.Type == 8): // Echo Reply/Request
		r.Echo = decodeEcho(body)
	case r.Version == "v6" && (r.Type == 128 || r.Type == 129):
		r.Echo = decodeEcho(body)
	case r.Version == "v4" && r.Type == 3: // Dest Unreachable
		r.DestUnreachable = decodeEmbedded(body)
	case r.Version == "v4" && r.Type == 11:
		r.TimeExceeded = decodeEmbedded(body)
	case r.Version == "v4" && r.Type == 12:
		r.ParameterProblem = decodeEmbedded(body)
	case r.Version == "v6" && r.Type == 1: // Dest Unreachable (v6)
		r.DestUnreachable = decodeEmbedded(body)
	case r.Version == "v6" && r.Type == 3: // Time Exceeded (v6)
		r.TimeExceeded = decodeEmbedded(body)
	case r.Version == "v4" && r.Type == 5: // Redirect
		if len(body) >= 4 {
			rd := &RedirectV4{
				GatewayIP:           ipv4String(body[0:4]),
				EmbeddedOriginalHex: strings.ToUpper(hex.EncodeToString(body[4:])),
			}
			rd.EmbeddedDecoded, rd.EmbeddedDecodeError = decodeInnerPacket(body[4:])
			r.Redirect = rd
		}
	case r.Version == "v6" && r.Type == 2: // Packet Too Big
		if len(body) >= 4 {
			p := &PacketTooBig{
				MTU: binary.BigEndian.Uint32(body[0:4]),
			}
			if len(body) > 4 {
				p.EmbeddedOriginalHex = strings.ToUpper(hex.EncodeToString(body[4:]))
				p.EmbeddedDecoded, p.EmbeddedDecodeError = decodeInnerPacket(body[4:])
			}
			r.PacketTooBig = p
		}
	case r.Version == "v6" && r.Type == 133: // Router Sol
		// 4 bytes reserved + options.
		if len(body) >= 4 {
			r.RouterSolicit = &NDPRouterSol{Options: parseNDPOptions(body[4:])}
		}
	case r.Version == "v6" && r.Type == 134: // Router Adv
		r.RouterAdvertise = decodeRouterAdv(body)
	case r.Version == "v6" && r.Type == 135: // Neighbor Sol
		if len(body) >= 20 { // 4 reserved + 16 target.
			r.NeighborSolicit = &NDPNeighbor{
				TargetAddress: ipv6String(body[4:20]),
				Options:       parseNDPOptions(body[20:]),
			}
		}
	case r.Version == "v6" && r.Type == 136: // Neighbor Adv
		if len(body) >= 20 {
			r.NeighborAdvertise = &NDPNeighbor{
				Flags:         naFlagsName(body[0]),
				TargetAddress: ipv6String(body[4:20]),
				Options:       parseNDPOptions(body[20:]),
			}
		}
	default:
		if len(body) > 0 {
			r.RawHex = strings.ToUpper(hex.EncodeToString(body))
		}
	}

	return r, nil
}

func decodeEcho(b []byte) *Echo {
	if len(b) < 4 {
		return nil
	}
	e := &Echo{
		Identifier: binary.BigEndian.Uint16(b[0:2]),
		Sequence:   binary.BigEndian.Uint16(b[2:4]),
		DataLen:    len(b) - 4,
	}
	if len(b) > 4 {
		e.DataHex = strings.ToUpper(hex.EncodeToString(b[4:]))
	}
	return e
}

func decodeEmbedded(b []byte) *EmbeddedPacket {
	if len(b) < 4 {
		return nil
	}
	ep := &EmbeddedPacket{
		UnusedHex:           strings.ToUpper(hex.EncodeToString(b[0:4])),
		EmbeddedOriginalHex: strings.ToUpper(hex.EncodeToString(b[4:])),
	}
	ep.EmbeddedDecoded, ep.EmbeddedDecodeError = decodeInnerPacket(b[4:])
	return ep
}

// decodeInnerPacket decodes the IP packet quoted inside an ICMP error message
// via internal/ipdecode. The quote is truncated (the original IP header + at
// least the first 8 bytes of its payload), so the IP layer and a UDP header
// decode fully while a TCP header degrades gracefully; a decode failure is
// returned as a message rather than asserted — no confidently-wrong output.
func decodeInnerPacket(b []byte) (*ipdecode.Packet, string) {
	if len(b) == 0 {
		return nil, ""
	}
	pkt, err := ipdecode.DecodeBytes(b)
	if err != nil {
		return nil, err.Error()
	}
	return pkt, ""
}

func decodeRouterAdv(b []byte) *NDPRouterAdv {
	if len(b) < 12 {
		return nil
	}
	r := &NDPRouterAdv{
		CurHopLimit:    int(b[0]),
		Flags:          raFlagsName(b[1]),
		RouterLifetime: binary.BigEndian.Uint16(b[2:4]),
		ReachableTime:  binary.BigEndian.Uint32(b[4:8]),
		RetransTimer:   binary.BigEndian.Uint32(b[8:12]),
	}
	if len(b) > 12 {
		r.Options = parseNDPOptions(b[12:])
	}
	return r
}

func parseNDPOptions(b []byte) []NDPOption {
	var opts []NDPOption
	off := 0
	for off+2 <= len(b) {
		typ := int(b[off])
		lenW8 := int(b[off+1])
		if lenW8 == 0 {
			break // malformed; bail
		}
		totalBytes := lenW8 * 8
		if off+totalBytes > len(b) {
			break
		}
		opt := NDPOption{
			Type:     typ,
			TypeName: ndpOptionName(typ),
			LengthW8: lenW8,
		}
		if totalBytes > 2 {
			opt.BodyHex = strings.ToUpper(hex.EncodeToString(b[off+2 : off+totalBytes]))
		}
		opts = append(opts, opt)
		off += totalBytes
	}
	return opts
}

func pickVersion(hint string, typ int) string {
	switch hint {
	case "v4":
		return "v4"
	case "v6":
		return "v6"
	}
	if typ >= 128 {
		return "v6"
	}
	return "v4"
}

func v4TypeName(t int) string {
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
	case 15:
		return "Information Request (deprecated)"
	case 16:
		return "Information Reply (deprecated)"
	case 17:
		return "Address Mask Request"
	case 18:
		return "Address Mask Reply"
	case 30:
		return "Traceroute (deprecated)"
	}
	return fmt.Sprintf("ICMPv4 type %d (uncatalogued)", t)
}

func v4CodeName(typ, code int) string {
	switch typ {
	case 3: // Destination Unreachable
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
			return "Fragmentation Needed and DF set"
		case 5:
			return "Source Route Failed"
		case 6:
			return "Destination Network Unknown"
		case 7:
			return "Destination Host Unknown"
		case 8:
			return "Source Host Isolated"
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
		case 14:
			return "Host Precedence Violation"
		case 15:
			return "Precedence Cutoff in effect"
		}
	case 5: // Redirect
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
	case 11: // Time Exceeded
		switch code {
		case 0:
			return "TTL Expired in Transit"
		case 1:
			return "Fragment Reassembly Time Exceeded"
		}
	case 12: // Parameter Problem
		switch code {
		case 0:
			return "Pointer indicates the error"
		case 1:
			return "Missing a Required Option"
		case 2:
			return "Bad Length"
		}
	}
	return ""
}

func v6TypeName(t int) string {
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
		return "Multicast Listener Query (MLD)"
	case 131:
		return "Multicast Listener Report (MLD)"
	case 132:
		return "Multicast Listener Done (MLD)"
	case 133:
		return "Router Solicitation (NDP)"
	case 134:
		return "Router Advertisement (NDP)"
	case 135:
		return "Neighbor Solicitation (NDP)"
	case 136:
		return "Neighbor Advertisement (NDP)"
	case 137:
		return "Redirect (NDP)"
	case 138:
		return "Router Renumbering"
	case 141:
		return "Inverse Neighbor Discovery Solicitation"
	case 142:
		return "Inverse Neighbor Discovery Advertisement"
	case 143:
		return "Multicast Listener Report v2 (MLDv2)"
	}
	return fmt.Sprintf("ICMPv6 type %d (uncatalogued)", t)
}

func v6CodeName(typ, code int) string {
	switch typ {
	case 1: // Destination Unreachable
		switch code {
		case 0:
			return "No Route to Destination"
		case 1:
			return "Communication Administratively Prohibited"
		case 2:
			return "Beyond Scope of Source Address"
		case 3:
			return "Address Unreachable"
		case 4:
			return "Port Unreachable"
		case 5:
			return "Source Address Failed Ingress/Egress Policy"
		case 6:
			return "Reject Route to Destination"
		case 7:
			return "Error in Source Routing Header"
		}
	case 3: // Time Exceeded
		switch code {
		case 0:
			return "Hop Limit Exceeded in Transit"
		case 1:
			return "Fragment Reassembly Time Exceeded"
		}
	case 4: // Parameter Problem
		switch code {
		case 0:
			return "Erroneous Header Field"
		case 1:
			return "Unrecognized Next Header"
		case 2:
			return "Unrecognized IPv6 Option"
		case 3:
			return "IPv6 First Fragment has incomplete IPv6 Header Chain"
		}
	}
	return ""
}

func ndpOptionName(t int) string {
	switch t {
	case 1:
		return "Source Link-Layer Address"
	case 2:
		return "Target Link-Layer Address"
	case 3:
		return "Prefix Information"
	case 4:
		return "Redirected Header"
	case 5:
		return "MTU"
	case 14:
		return "Nonce (SEND)"
	case 24:
		return "Route Information"
	case 25:
		return "Recursive DNS Server (RDNSS)"
	case 31:
		return "DNS Search List (DNSSL)"
	}
	return fmt.Sprintf("NDP option %d", t)
}

func raFlagsName(b byte) string {
	parts := []string{}
	if b&0x80 != 0 {
		parts = append(parts, "M (Managed Address Config)")
	}
	if b&0x40 != 0 {
		parts = append(parts, "O (Other Config)")
	}
	if b&0x20 != 0 {
		parts = append(parts, "H (Mobile IPv6 Home Agent)")
	}
	if len(parts) == 0 {
		return "(no flags set)"
	}
	return strings.Join(parts, " | ")
}

func naFlagsName(b byte) string {
	parts := []string{}
	if b&0x80 != 0 {
		parts = append(parts, "R (Router)")
	}
	if b&0x40 != 0 {
		parts = append(parts, "S (Solicited)")
	}
	if b&0x20 != 0 {
		parts = append(parts, "O (Override)")
	}
	if len(parts) == 0 {
		return "(no flags set)"
	}
	return strings.Join(parts, " | ")
}

func ipv4String(b []byte) string {
	if len(b) != 4 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func ipv6String(b []byte) string {
	if len(b) != 16 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	ip := net.IP(b)
	return ip.String()
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
