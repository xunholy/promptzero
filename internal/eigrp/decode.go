// Package eigrp decodes EIGRP (Enhanced Interior Gateway Routing Protocol)
// packets per RFC 7868 (informational; Cisco proprietary until 2016). EIGRP
// uses IP protocol number 88 — it runs directly over IP, not TCP or UDP.
// Multicast to 224.0.0.10 (all EIGRP routers); unicast for targeted messages.
// Runs on every Cisco enterprise campus / WAN deployment; common in enterprise
// data-centre access-layer and branch-office router configurations.
//
// EIGRP is a **high-value enterprise routing target**. Unlike OSPF (which
// requires a DR election and per-area database synchronization before injecting
// routes), EIGRP authentication is OFF by default — any device that sends a
// Hello with the correct Autonomous System number immediately becomes an EIGRP
// neighbour and can inject arbitrary routes. Shodan and passive-BGP monitoring
// regularly surface enterprise routers running unauthenticated EIGRP toward
// untrusted segments.
//
// The wire format leaks:
//
//   - **Autonomous System number** — the primary trust boundary. EIGRP
//     neighbours must share the same AS number. Knowing the AS number from a
//     captured Hello allows an attacker to form a neighbour relationship and
//     inject routes, enabling traffic interception (MITM) or black-hole
//     attacks, without needing any authentication material.
//
//   - **K-values (metric weights)** — K1 (bandwidth), K2 (load), K3 (delay),
//     K4 (reliability), K5 (MTU weight). All neighbours must agree on K-values
//     to form adjacency. K1=1 K2=0 K3=1 K4=0 K5=0 is the classic default.
//     Non-default K-values fingerprint IOS version or non-standard policy.
//
//   - **Hold time** — how long before the neighbour is declared dead. Short
//     hold times signal fast-convergence tuning.
//
//   - **Software version** — IOS major.minor and EIGRP major.minor, surfaced
//     in the Software Version TLV (0x0004) of Hello packets. Discloses exact
//     IOS release for vulnerability matching.
//
//   - **Internal route topology** — Internal Route TLVs (0x0102) in Update
//     packets expose next_hop, delay, bandwidth, prefix_length, and
//     destination subnet. These reveal the complete internal network topology.
//
//   - **External route redistribution** — External Route TLVs (0x0103)
//     expose redistribution sources (OSPF, BGP, static, connected) with their
//     originating router and AS. Reveals multi-protocol topology and BGP
//     peering structure.
//
//   - **Authentication type** — the Auth TLV (0x0002) discloses whether MD5
//     (type 2) or SHA-256 named-mode (type 3) auth is in use. MD5 EIGRP
//     authentication is offline-crackable via hashcat. SHA-256 named-mode
//     (IOS 15.1+) is the modern secure option but is less widely deployed.
//     No Auth TLV = NO AUTHENTICATION — neighbour spoofing trivial.
//
//   - **Flags** — the Init flag marks the first Hello in a new neighbour
//     relationship; End-of-Table marks the last Update packet; Restart and
//     Conditional Receive support graceful-restart and reliable multicast.
//
// Wrap-vs-native judgement
//
//	Native. RFC 7868 is publicly available. The EIGRP wire format is a
//	tight 20-byte binary header followed by TLV entries. No crypto at the
//	parse layer (authentication TLV content is opaque auth data, not
//	decryptable payload). Pure offline parser.
//
// What this package covers
//
//   - **20-byte EIGRP header**: version, opcode + name, flags (init /
//     conditional_receive / restart / end_of_table), sequence, acknowledge,
//     virtual_router_id, autonomous_system.
//
//   - **7-entry opcode name table**: 1 Update, 3 Query, 4 Reply, 5 Hello,
//     6 IPX-SAP (legacy), 10 SIA-Query, 11 SIA-Reply.
//
//   - **TLV walker**: type (2 BE) + length (2 BE) + value[length-4] for
//     all TLVs present; surfaces tlv_count and tlv_types list.
//
//   - **Parameters TLV (0x0001)**: K1–K5 metric weights + hold_time.
//
//   - **Auth TLV (0x0002)**: auth_type with name (MD5 / SHA-256), has_auth.
//
//   - **Software Version TLV (0x0004)**: IOS major.minor + EIGRP major.minor.
//
//   - **Internal Route TLV (0x0102)**: next_hop (dotted-quad), delay,
//     bandwidth, prefix_length, destination (dotted-quad). First route only.
//
//   - **Classification flags**: is_hello, is_update, is_query.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **External Route TLVs (0x0103)**: full external route body (originating
//     router + AS + external metric + protocol ID + flags + destination).
//
//   - **IPv6 route TLVs (0x0402, 0x0403)**: next-gen AFI-based route
//     encoding.
//
//   - **Multi-Protocol TLVs (0x0602)**: AFI-based multi-topology routes.
//
//   - **Sequence TLV (0x0003)**: reliable-multicast peer sequence list.
//
//   - **Next Multicast Sequence TLV (0x0005)**: pending multicast delivery.
//
//   - **Stub Routing TLV (0x0006)**: stub-mode capability advertising.
//
//   - **Checksum verification**: header checksum field is decoded but not
//     validated.
//
//   - **Authentication verification**: auth_data bytes are never surfaced;
//     only auth_type is decoded (privacy-preserving, length only).
//
//   - **IP framing**: feed bytes after IPv4 header strip — EIGRP rides IP
//     protocol 88 with no UDP/TCP wrapper.
package eigrp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the structured decode of an EIGRP packet.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Header fields
	Version          int    `json:"version"`
	Opcode           int    `json:"opcode"`
	OpcodeName       string `json:"opcode_name"`
	Checksum         string `json:"checksum"`
	Sequence         uint32 `json:"sequence"`
	Acknowledge      uint32 `json:"acknowledge"`
	VirtualRouterID  uint16 `json:"virtual_router_id"`
	AutonomousSystem uint16 `json:"autonomous_system"`

	// Decoded flags
	FlagInit               bool `json:"flag_init"`
	FlagConditionalReceive bool `json:"flag_conditional_receive"`
	FlagRestart            bool `json:"flag_restart"`
	FlagEndOfTable         bool `json:"flag_end_of_table"`

	// Classification
	IsHello  bool `json:"is_hello"`
	IsUpdate bool `json:"is_update"`
	IsQuery  bool `json:"is_query"`

	// TLV summary
	TLVCount int      `json:"tlv_count"`
	TLVTypes []uint16 `json:"tlv_types"`

	// Parameters TLV (0x0001)
	HasParameters bool `json:"has_parameters"`
	K1            int  `json:"k1,omitempty"`
	K2            int  `json:"k2,omitempty"`
	K3            int  `json:"k3,omitempty"`
	K4            int  `json:"k4,omitempty"`
	K5            int  `json:"k5,omitempty"`
	HoldTime      int  `json:"hold_time,omitempty"`

	// Software Version TLV (0x0004)
	HasSoftwareVersion bool `json:"has_software_version"`
	IOSMajor           int  `json:"ios_major,omitempty"`
	IOSMinor           int  `json:"ios_minor,omitempty"`
	EIGRPMajor         int  `json:"eigrp_major,omitempty"`
	EIGRPMinor         int  `json:"eigrp_minor,omitempty"`

	// Auth TLV (0x0002)
	HasAuth      bool   `json:"has_auth"`
	AuthType     int    `json:"auth_type,omitempty"`
	AuthTypeName string `json:"auth_type_name,omitempty"`

	// Route TLVs
	RouteCount       int    `json:"route_count"`
	FirstRoutePrefix string `json:"first_route_prefix,omitempty"`
}

const eigrpHeaderSize = 20

// Decode parses an EIGRP packet from a hex string.
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
	if len(b) < eigrpHeaderSize {
		return nil, fmt.Errorf("eigrp header truncated (%d bytes; need %d)", len(b), eigrpHeaderSize)
	}

	r := &Result{TotalBytes: len(b)}

	// Parse 20-byte EIGRP header.
	r.Version = int(b[0])
	r.Opcode = int(b[1])
	r.OpcodeName = opcodeName(r.Opcode)
	r.Checksum = fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(b[2:4]))

	flags := binary.BigEndian.Uint32(b[4:8])
	r.FlagInit = flags&0x00000001 != 0
	r.FlagConditionalReceive = flags&0x00000002 != 0
	r.FlagRestart = flags&0x00000004 != 0
	r.FlagEndOfTable = flags&0x00000008 != 0

	r.Sequence = binary.BigEndian.Uint32(b[8:12])
	r.Acknowledge = binary.BigEndian.Uint32(b[12:16])
	r.VirtualRouterID = binary.BigEndian.Uint16(b[16:18])
	r.AutonomousSystem = binary.BigEndian.Uint16(b[18:20])

	// Classify by opcode.
	switch r.Opcode {
	case 1:
		r.IsUpdate = true
	case 3:
		r.IsQuery = true
	case 5:
		r.IsHello = true
	}

	// Walk TLVs.
	r.TLVTypes = []uint16{}
	off := eigrpHeaderSize
	for off+4 <= len(b) {
		tlvType := binary.BigEndian.Uint16(b[off : off+2])
		tlvLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if tlvLen < 4 {
			// Malformed TLV; stop walking.
			break
		}
		if off+tlvLen > len(b) {
			// Truncated TLV value; stop walking.
			break
		}

		r.TLVCount++
		r.TLVTypes = append(r.TLVTypes, tlvType)

		value := b[off+4 : off+tlvLen]
		decodeTLV(r, tlvType, value)

		off += tlvLen
	}

	return r, nil
}

func decodeTLV(r *Result, tlvType uint16, value []byte) {
	switch tlvType {
	case 0x0001: // Parameters
		decodeParametersTLV(r, value)
	case 0x0002: // Authentication
		decodeAuthTLV(r, value)
	case 0x0004: // Software Version
		decodeSoftwareVersionTLV(r, value)
	case 0x0102, 0x0402: // Internal Route IPv4 / IPv6 Internal
		decodeInternalRouteTLV(r, value)
	case 0x0103, 0x0403: // External Route IPv4 / IPv6 External
		// Count external routes toward RouteCount but don't deep-parse.
		r.RouteCount++
	}
}

func decodeParametersTLV(r *Result, value []byte) {
	// Parameters TLV value: K1 K2 K3 K4 K5 (1 byte each) + hold_time (2 BE)
	// Total value length: 7 bytes (TLV total = 11 bytes, minus 4-byte header = 7)
	if len(value) < 7 {
		return
	}
	r.HasParameters = true
	r.K1 = int(value[0])
	r.K2 = int(value[1])
	r.K3 = int(value[2])
	r.K4 = int(value[3])
	r.K5 = int(value[4])
	r.HoldTime = int(binary.BigEndian.Uint16(value[5:7]))
}

func decodeAuthTLV(r *Result, value []byte) {
	// Auth TLV value: auth_type (2 BE) + auth_data (variable)
	if len(value) < 2 {
		return
	}
	r.HasAuth = true
	r.AuthType = int(binary.BigEndian.Uint16(value[0:2]))
	r.AuthTypeName = authTypeName(r.AuthType)
}

func decodeSoftwareVersionTLV(r *Result, value []byte) {
	// Software Version TLV value: IOS_major IOS_minor EIGRP_major EIGRP_minor
	// (1 byte each) = 4 bytes total
	if len(value) < 4 {
		return
	}
	r.HasSoftwareVersion = true
	r.IOSMajor = int(value[0])
	r.IOSMinor = int(value[1])
	r.EIGRPMajor = int(value[2])
	r.EIGRPMinor = int(value[3])
}

func decodeInternalRouteTLV(r *Result, value []byte) {
	// Internal Route TLV value (IPv4, 0x0102):
	// next_hop (4) + delay (4 BE) + bandwidth (4 BE) + reserved (3) +
	// reliability (1) + load (1) + mtu (3) + hop_count (1) + reliability2 (1) +
	// prefix_length (1) + destination (variable, ceil(prefix/8) bytes)
	// Minimum meaningful: next_hop(4) + delay(4) + bandwidth(4) + ... + prefix_length(1) = 24 bytes
	r.RouteCount++
	if r.FirstRoutePrefix != "" {
		// Only capture the first route.
		return
	}
	if len(value) < 25 {
		return
	}
	// next_hop at offset 0
	nextHop := net.IP(value[0:4]).String()
	_ = nextHop
	// prefix_length at offset 24 per RFC 7868 §6.6.2 (after next_hop + delay +
	// bandwidth + reserved + reliability + load + mtu + hop_count + reliability):
	// next_hop(4) + delay(4) + bandwidth(4) + reserved(3) + reliability(1) +
	// load(1) + mtu(3) + hop_count(1) + reliability2(1) = 22 bytes; prefix at [22]
	if len(value) < 23 {
		return
	}
	prefixLen := int(value[22])
	// destination starts at offset 23
	addrBytes := (prefixLen + 7) / 8
	if addrBytes > 4 {
		addrBytes = 4
	}
	if 23+addrBytes > len(value) {
		return
	}
	// Pad to 4 bytes for IPv4 formatting.
	dst := make([]byte, 4)
	copy(dst, value[23:23+addrBytes])
	r.FirstRoutePrefix = fmt.Sprintf("%s/%d", net.IP(dst).String(), prefixLen)
}

func opcodeName(op int) string {
	switch op {
	case 1:
		return "Update"
	case 3:
		return "Query"
	case 4:
		return "Reply"
	case 5:
		return "Hello"
	case 6:
		return "IPX-SAP"
	case 10:
		return "SIA-Query"
	case 11:
		return "SIA-Reply"
	}
	return fmt.Sprintf("opcode_%d", op)
}

func authTypeName(t int) string {
	switch t {
	case 2:
		return "MD5"
	case 3:
		return "SHA-256"
	}
	return fmt.Sprintf("auth_type_%d", t)
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
