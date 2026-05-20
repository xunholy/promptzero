// Package ndp decodes ICMPv6 NDP (Neighbor Discovery Protocol)
// messages per RFC 4861 (base NDP) + RFC 4191 (Default Router
// Preferences + Route Information) + RFC 8106 (RDNSS / DNSSL
// for SLAAC-only IPv6 hosts). NDP is the **foundational
// signalling layer** of IPv6 — every IPv6 host speaks NDP for
// neighbor resolution (the IPv6 equivalent of ARP), router
// discovery, parameter discovery, redirect handling, and
// duplicate-address detection.
//
// Operationally, NDP is interesting because it carries every
// step of how a fresh IPv6 host learns its environment:
//
//   - **Router Solicitation (RS)** — "any routers out there?"
//     A newly-joined host (cold boot, link up, interface
//     re-attach) sends one to FF02::2 (all-routers multicast)
//     to short-circuit the periodic Router Advertisement
//     interval.
//   - **Router Advertisement (RA)** — "I'm a router; here are
//     my prefixes + DNS servers + MTU + default-router
//     lifetime." This is the canonical IPv6-pentest target:
//     mitm6 / suddensix / parasite6 / fake_router6 inject
//     malicious RAs to redirect the victim's default route
//     via the attacker's host.
//   - **Neighbor Solicitation (NS)** — "who has this IPv6
//     address?" The IPv6 equivalent of ARP — sent to the
//     solicited-node multicast group derived from the target
//     IPv6 address.
//   - **Neighbor Advertisement (NA)** — "I have it; here's my
//     MAC." Carries R (Router) / S (Solicited) / O (Override)
//     flags; unsolicited NAs with O=1 are the IPv6
//     equivalent of gratuitous ARP and can be abused for
//     ND-cache poisoning.
//   - **Redirect** — "you sent traffic for X to me but I'm
//     not the best next-hop; use Y instead." Historically
//     abusable for IPv6 redirect attacks; modern stacks rate-
//     limit + cryptographically validate.
//
// The **NDP Options** TLV stream attached to every NDP message
// carries the actual interesting data: Source/Target Link-Layer
// Addresses (the IPv6 → MAC binding), Prefix Information (the
// SLAAC prefix + on-link bit + autoconfig bit + lifetime),
// MTU (link MTU override), RDNSS (the DNS servers the host
// should use for name resolution — leak target for mitm6 +
// rogue RA attacks), DNSSL (the search-domain list).
//
// Wrap-vs-native judgement
//
//	Native. RFC 4861 + 4191 + 8106 are publicly available; NDP
//	uses a tight 4-byte ICMPv6 header + per-type fixed fields
//	+ a TLV Options stream where every option is (Type +
//	Length-in-8-byte-units + Value). No crypto at the parse
//	layer (the optional SeND extension — RFC 3971 — adds CGA
//	+ RSA Signature options that this decoder surfaces as raw
//	hex; key validation is higher-level work).
//
// What this package covers
//
//   - **ICMPv6 header** (RFC 4443 §2, 4 bytes; multi-byte fields
//     are big-endian): byte 0 Type + byte 1 Code (always 0 for
//     NDP) + bytes 2-3 Checksum.
//
//   - **5-entry NDP type name table** (RFC 4861 §4): 133
//     `Router_Solicitation` / 134 `Router_Advertisement` / 135
//     `Neighbor_Solicitation` / 136 `Neighbor_Advertisement` /
//     137 `Redirect`.
//
//   - **Router Advertisement body** (RFC 4861 §4.2, 12 bytes
//     after the ICMPv6 header): byte 4 Cur Hop Limit + byte 5
//     Flags (bit 7 `M` Managed Address Configuration / bit 6
//     `O` Other Configuration / bit 5 `H` Home Agent / bits 4-3
//     `Prf` Default Router Preference per RFC 4191 — 00 Medium,
//     01 High, 10 Reserved, 11 Low / bit 2 `P` Proxy) + bytes
//     6-7 Router Lifetime (uint16 BE seconds; 0 = NOT a default
//     router) + bytes 8-11 Reachable Time (uint32 BE
//     milliseconds) + bytes 12-15 Retrans Timer (uint32 BE
//     milliseconds).
//
//   - **Neighbor Solicitation body** (RFC 4861 §4.3, 20 bytes):
//     bytes 4-7 Reserved + bytes 8-23 Target Address (IPv6).
//
//   - **Neighbor Advertisement body** (RFC 4861 §4.4, 20 bytes):
//     byte 4 Flags (bit 7 `R` Router / bit 6 `S` Solicited /
//     bit 5 `O` Override) + bytes 5-7 Reserved + bytes 8-23
//     Target Address (IPv6).
//
//   - **Router Solicitation body** (RFC 4861 §4.1, 4 bytes):
//     bytes 4-7 Reserved.
//
//   - **Redirect body** (RFC 4861 §4.5, 36 bytes): bytes 4-7
//     Reserved + bytes 8-23 Target Address (the better next-
//     hop) + bytes 24-39 Destination Address (the original
//     destination).
//
//   - **NDP Options TLV walker** (RFC 4861 §4.6): every option
//     is byte 0 Type + byte 1 Length-in-8-byte-units (so total
//     option bytes = Length × 8) + (Length×8 - 2) bytes of
//     payload. Walker stops at the end of the input or on a
//     Length=0 (illegal — would loop).
//
//   - **9-entry NDP Option type name table**: 1
//     `Source_Link_Layer_Address` (SLLA) / 2
//     `Target_Link_Layer_Address` (TLLA) / 3
//     `Prefix_Information` / 4 `Redirected_Header` / 5 `MTU` /
//     13 `Nonce` (RFC 3971 SeND) / 24 `Route_Information` (RFC
//     4191) / 25 `RDNSS` (RFC 8106 Recursive DNS Server) / 31
//     `DNSSL` (RFC 8106 DNS Search List).
//
//   - **Per-option decoders**:
//
//   - **SLLA / TLLA** (Types 1, 2): 6-byte MAC address
//     (assuming Ethernet — the common case).
//
//   - **Prefix Information** (Type 3, 32 bytes total):
//     byte 2 Prefix Length (bits 0-128) + byte 3 Flags
//     (bit 7 `L` On-Link / bit 6 `A` Autonomous Address
//     Configuration / bit 5 `R` Router Address per RFC
//     6275 Mobile IPv6) + bytes 4-7 Valid Lifetime
//     (uint32 BE seconds; 0xFFFFFFFF = infinity) + bytes
//     8-11 Preferred Lifetime + bytes 12-15 Reserved +
//     bytes 16-31 Prefix (IPv6).
//
//   - **MTU** (Type 5, 8 bytes total): bytes 4-7 MTU
//     (uint32 BE; overrides the link-layer MTU for IPv6
//     transmission).
//
//   - **RDNSS** (Type 25, variable): byte 2-3 Reserved +
//     bytes 4-7 Lifetime (uint32 BE seconds — how long
//     to trust these DNS servers) + bytes 8+ one or more
//     16-byte IPv6 DNS server addresses.
//
//   - **DNSSL** (Type 31, variable): bytes 4-7 Lifetime
//
//   - bytes 8+ DNS search domains (each a sequence of
//     length-prefixed labels followed by a 0x00 root
//     terminator — RFC 1035 §3.1 encoding).
//
//   - **Route Information** (Type 24, variable per RFC
//     4191): byte 2 Prefix Length + byte 3 Flags (bits
//     4-3 Prf Preference) + bytes 4-7 Route Lifetime +
//     bytes 8+ Prefix (truncated to fit per Prefix
//     Length).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **IPv6 framing** — feed NDP bytes after the IPv6 header
//     strip (NDP messages travel inside ICMPv6 packets with
//     Next Header = 58). Standard L3 destination is FF02::1
//     (all-nodes), FF02::2 (all-routers), or the solicited-
//     node multicast group FF02::1:FF**xx:xxxx** derived from
//     the target IPv6 address.
//   - **ICMPv6 echo + error decoders** — the existing
//     `icmp_packet_decode` Spec covers ICMPv4 echo + DUR + TE.
//     NDP-specific Types 133-137 are the focus here; other
//     ICMPv6 message types (1 Destination Unreachable, 2
//     Packet Too Big, 3 Time Exceeded, 4 Parameter Problem,
//     128 Echo Request, 129 Echo Reply, 130 MLD Query, 131
//     MLD Report, 132 MLD Done, 143 MLDv2 Report) are out of
//     scope.
//   - **Checksum verification** — the ICMPv6 checksum is
//     computed over an IPv6 pseudo-header + the ICMPv6 message;
//     this decoder surfaces the on-wire checksum as hex but
//     does not re-compute (out of scope unless we have the L3
//     pseudo-header).
//   - **SeND (Secure Neighbor Discovery)** — RFC 3971 adds CGA
//   - RSA Signature + Nonce + Timestamp options to prevent
//     ND spoofing; the Nonce option (Type 13) name surfaces
//     but the CGA + RSA Signature options are not decoded.
//   - **DAD (Duplicate Address Detection)** state-machine —
//     the per-address tentative / preferred / deprecated /
//     invalid state machine is a higher-level concern.
package ndp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the structured decode of an ICMPv6 NDP message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// ICMPv6 header
	Type        int    `json:"type"`
	TypeName    string `json:"type_name"`
	Code        int    `json:"code"`
	ChecksumHex string `json:"checksum_hex"`

	// Per-type fixed fields (only the relevant subset is
	// populated; the others stay zero / omitted).
	CurHopLimit        int    `json:"cur_hop_limit,omitempty"`
	RAFlagsHex         string `json:"ra_flags_hex,omitempty"`
	RAManaged          bool   `json:"ra_managed,omitempty"`
	RAOther            bool   `json:"ra_other,omitempty"`
	RAHomeAgent        bool   `json:"ra_home_agent,omitempty"`
	RAPreference       string `json:"ra_preference,omitempty"`
	RAProxy            bool   `json:"ra_proxy,omitempty"`
	RouterLifetimeS    uint16 `json:"router_lifetime_seconds,omitempty"`
	ReachableTimeMs    uint32 `json:"reachable_time_ms,omitempty"`
	RetransTimerMs     uint32 `json:"retrans_timer_ms,omitempty"`
	NAFlagsHex         string `json:"na_flags_hex,omitempty"`
	NARouter           bool   `json:"na_router,omitempty"`
	NASolicited        bool   `json:"na_solicited,omitempty"`
	NAOverride         bool   `json:"na_override,omitempty"`
	TargetAddress      string `json:"target_address,omitempty"`
	DestinationAddress string `json:"destination_address,omitempty"`

	Options []Option `json:"options,omitempty"`
}

// Option is one entry in the NDP Options TLV stream.
type Option struct {
	Type         int    `json:"type"`
	TypeName     string `json:"type_name"`
	LengthOctets int    `json:"length_octets"`
	PayloadHex   string `json:"payload_hex,omitempty"`

	// SLLA / TLLA
	LinkLayerAddress string `json:"link_layer_address,omitempty"`

	// Prefix Information
	PrefixLength       int    `json:"prefix_length,omitempty"`
	PrefixFlagsHex     string `json:"prefix_flags_hex,omitempty"`
	PrefixOnLink       bool   `json:"prefix_on_link,omitempty"`
	PrefixAutoconfig   bool   `json:"prefix_autoconfig,omitempty"`
	PrefixRouter       bool   `json:"prefix_router,omitempty"`
	ValidLifetimeS     uint32 `json:"valid_lifetime_seconds,omitempty"`
	PreferredLifetimeS uint32 `json:"preferred_lifetime_seconds,omitempty"`
	Prefix             string `json:"prefix,omitempty"`

	// MTU
	MTU uint32 `json:"mtu,omitempty"`

	// RDNSS / Route Information
	LifetimeS     uint32   `json:"lifetime_seconds,omitempty"`
	DNSServers    []string `json:"dns_servers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`

	// Route Information
	RoutePreference string `json:"route_preference,omitempty"`
}

// Decode parses an ICMPv6 NDP message from a hex string starting
// at the ICMPv6 Type byte. Separators (':' '-' '_' whitespace)
// tolerated; '0x' prefix tolerated.
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
	if len(b) < 4 {
		return nil, fmt.Errorf("ICMPv6 message truncated (%d bytes; need ≥4 for header)",
			len(b))
	}

	r := &Result{
		TotalBytes:  len(b),
		Type:        int(b[0]),
		Code:        int(b[1]),
		ChecksumHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[2:4])),
	}
	r.TypeName = typeName(r.Type)

	body := b[4:]
	optStart := 0
	switch r.Type {
	case 133: // Router Solicitation
		if len(body) >= 4 {
			optStart = 4
		}
	case 134: // Router Advertisement
		if len(body) >= 12 {
			r.CurHopLimit = int(body[0])
			r.RAFlagsHex = fmt.Sprintf("0x%02X", body[1])
			r.RAManaged = body[1]&0x80 != 0
			r.RAOther = body[1]&0x40 != 0
			r.RAHomeAgent = body[1]&0x20 != 0
			r.RAPreference = raPreferenceName(int((body[1] >> 3) & 0x03))
			r.RAProxy = body[1]&0x04 != 0
			r.RouterLifetimeS = binary.BigEndian.Uint16(body[2:4])
			r.ReachableTimeMs = binary.BigEndian.Uint32(body[4:8])
			r.RetransTimerMs = binary.BigEndian.Uint32(body[8:12])
			optStart = 12
		}
	case 135: // Neighbor Solicitation
		if len(body) >= 20 {
			r.TargetAddress = net.IP(body[4:20]).String()
			optStart = 20
		}
	case 136: // Neighbor Advertisement
		if len(body) >= 20 {
			r.NAFlagsHex = fmt.Sprintf("0x%02X", body[0])
			r.NARouter = body[0]&0x80 != 0
			r.NASolicited = body[0]&0x40 != 0
			r.NAOverride = body[0]&0x20 != 0
			r.TargetAddress = net.IP(body[4:20]).String()
			optStart = 20
		}
	case 137: // Redirect
		if len(body) >= 36 {
			r.TargetAddress = net.IP(body[4:20]).String()
			r.DestinationAddress = net.IP(body[20:36]).String()
			optStart = 36
		}
	}

	if optStart > 0 && optStart < len(body) {
		r.Options = walkOptions(body[optStart:])
	}
	return r, nil
}

func walkOptions(b []byte) []Option {
	var opts []Option
	off := 0
	for off+2 <= len(b) {
		oType := int(b[off])
		oLenOctets := int(b[off+1])
		if oLenOctets == 0 {
			break
		}
		totalBytes := oLenOctets * 8
		if off+totalBytes > len(b) {
			break
		}
		raw := b[off : off+totalBytes]
		opt := Option{
			Type:         oType,
			TypeName:     optionTypeName(oType),
			LengthOctets: oLenOctets,
		}
		decodeOption(&opt, raw)
		opts = append(opts, opt)
		off += totalBytes
	}
	return opts
}

func decodeOption(o *Option, raw []byte) {
	// raw[0] = type, raw[1] = length in 8-byte units; remainder
	// is per-option payload.
	if len(raw) < 2 {
		return
	}
	body := raw[2:]
	switch o.Type {
	case 1, 2: // Source / Target Link-Layer Address
		if len(body) >= 6 {
			o.LinkLayerAddress = fmt.Sprintf(
				"%02X:%02X:%02X:%02X:%02X:%02X",
				body[0], body[1], body[2], body[3], body[4], body[5])
		}
	case 3: // Prefix Information
		if len(body) >= 30 {
			o.PrefixLength = int(body[0])
			o.PrefixFlagsHex = fmt.Sprintf("0x%02X", body[1])
			o.PrefixOnLink = body[1]&0x80 != 0
			o.PrefixAutoconfig = body[1]&0x40 != 0
			o.PrefixRouter = body[1]&0x20 != 0
			o.ValidLifetimeS = binary.BigEndian.Uint32(body[2:6])
			o.PreferredLifetimeS = binary.BigEndian.Uint32(body[6:10])
			o.Prefix = net.IP(body[14:30]).String()
		}
	case 5: // MTU
		if len(body) >= 6 {
			// body[0:2] reserved; body[2:6] MTU.
			o.MTU = binary.BigEndian.Uint32(body[2:6])
		}
	case 24: // Route Information (RFC 4191)
		if len(body) >= 6 {
			o.PrefixLength = int(body[0])
			o.RoutePreference = raPreferenceName(int((body[1] >> 3) & 0x03))
			o.LifetimeS = binary.BigEndian.Uint32(body[2:6])
			// Prefix occupies the remaining bytes (0/8/16
			// depending on Length octets — 1/2/3 = up to /0,
			// /64, /128).
			if len(body) >= 22 {
				o.Prefix = net.IP(body[6:22]).String()
			}
		}
	case 25: // RDNSS (RFC 8106)
		if len(body) >= 6 {
			// body[0:2] reserved; body[2:6] lifetime;
			// body[6:] = one or more 16-byte IPv6 addresses.
			o.LifetimeS = binary.BigEndian.Uint32(body[2:6])
			for p := 6; p+16 <= len(body); p += 16 {
				o.DNSServers = append(o.DNSServers, net.IP(body[p:p+16]).String())
			}
		}
	case 31: // DNSSL (RFC 8106)
		if len(body) >= 6 {
			o.LifetimeS = binary.BigEndian.Uint32(body[2:6])
			o.SearchDomains = parseDNSSearchList(body[6:])
		}
	default:
		// Unknown: surface raw payload bytes (after the 2-byte
		// option header).
		if len(body) > 0 {
			o.PayloadHex = strings.ToUpper(hex.EncodeToString(body))
		}
	}
}

// parseDNSSearchList walks a sequence of length-prefixed labels
// per RFC 1035 §3.1, terminated by a 0x00 root label.
func parseDNSSearchList(b []byte) []string {
	var out []string
	var cur strings.Builder
	off := 0
	for off < len(b) {
		l := int(b[off])
		off++
		if l == 0 {
			// End of name.
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		if off+l > len(b) {
			return out
		}
		if cur.Len() > 0 {
			cur.WriteByte('.')
		}
		cur.Write(b[off : off+l])
		off += l
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func typeName(t int) string {
	switch t {
	case 133:
		return "Router_Solicitation"
	case 134:
		return "Router_Advertisement"
	case 135:
		return "Neighbor_Solicitation"
	case 136:
		return "Neighbor_Advertisement"
	case 137:
		return "Redirect"
	}
	return fmt.Sprintf("non-NDP ICMPv6 type %d", t)
}

func raPreferenceName(p int) string {
	switch p {
	case 0:
		return "Medium"
	case 1:
		return "High"
	case 2:
		return "Reserved"
	case 3:
		return "Low"
	}
	return ""
}

func optionTypeName(t int) string {
	switch t {
	case 1:
		return "Source_Link_Layer_Address"
	case 2:
		return "Target_Link_Layer_Address"
	case 3:
		return "Prefix_Information"
	case 4:
		return "Redirected_Header"
	case 5:
		return "MTU"
	case 13:
		return "Nonce"
	case 24:
		return "Route_Information"
	case 25:
		return "RDNSS"
	case 31:
		return "DNSSL"
	}
	return fmt.Sprintf("uncatalogued option type %d", t)
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
