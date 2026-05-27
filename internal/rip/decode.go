// Package rip decodes RIP (Routing Information Protocol) v1 and v2
// wire-protocol messages per RFC 1058 (RIPv1) and RFC 2453 (RIPv2).
// RIP runs over UDP/520 (RIPv1/RIPv2); RIPng (IPv6) runs over UDP/521
// and is out of scope for this package.
//
// Operationally, RIP is one of the oldest distance-vector routing
// protocols still in widespread deployment — legacy enterprise
// networks, campus LANs, ISP last-mile, and embedded routers all
// run it. Its simplicity is also its critical weakness.
//
// Security relevance
//
//   - **RIPv1 has NO authentication** — any host on the subnet can
//     send a forged RIPv2 Response and inject arbitrary routes.
//     Captured packets immediately expose full internal topology.
//
//   - **RIPv2 simple-password auth (type 2) transmits the password
//     in CLEARTEXT** inside the first route entry slot (address_family
//     = 0xFFFF). A passive network capture yields the password
//     immediately.
//
//   - **RIPv2 MD5 auth (type 3)** is offline-crackable; the key ID
//     and sequence number are available in the cleartext auth header.
//
//   - **Route injection attacks** redirect traffic through an
//     attacker-controlled router. Any unauthenticated RIP speaker
//     can announce 0.0.0.0/0 with metric 1 and become the default
//     gateway for the entire subnet.
//
//   - **Metric-16 (infinity) manipulation** causes route withdrawal:
//     an attacker sends metric=16 for a victim's prefix, triggering
//     the split-horizon / holddown mechanism and creating a black
//     hole for that prefix.
//
//   - **Topology disclosure** — every RIP Response packet enumerates
//     internal prefixes, subnet masks (v2), and next-hop addresses.
//     This is free network recon.
//
// RIP header (4 bytes)
//
//   - command (1 byte): 1 = Request, 2 = Response
//   - version (1 byte): 1 = RIPv1, 2 = RIPv2
//   - zero/routing-domain (2 bytes): reserved in RIPv1; historically
//     used as "routing domain" in some RIPv2 implementations but
//     defined as zero in RFC 2453.
//
// RIP route entry (20 bytes each, following the header)
//
// RIPv1:
//   - address_family (2 BE): 2 = AF_INET
//   - zero (2 bytes)
//   - ip_address (4 bytes)
//   - zero (4 bytes) — subnet mask field, always zero in RIPv1
//   - zero (4 bytes) — next-hop field, always zero in RIPv1
//   - metric (4 BE): 1–15 valid hops, 16 = infinity / unreachable
//
// RIPv2:
//   - address_family (2 BE): 2 = AF_INET, 0xFFFF = authentication entry
//   - route_tag (2 BE): used for inter-AS route tagging
//   - ip_address (4 bytes)
//   - subnet_mask (4 bytes)
//   - next_hop (4 bytes)
//   - metric (4 BE): 1–15 valid hops, 16 = infinity / unreachable
//
// RIPv2 authentication entry (when address_family = 0xFFFF)
//
//   - 0xFFFF (2 BE) — authentication marker
//   - auth_type (2 BE): 2 = simple password (cleartext!), 3 = MD5
//   - If auth_type = 2: 16 bytes cleartext password (zero-padded)
//   - If auth_type = 3: MD5 key ID + auth data length + sequence number
//
// Wrap-vs-native judgement
//
//	Native. RFC 1058 and RFC 2453 are fully public. The wire format
//	is a tight 4-byte header followed by 20-byte fixed-size route
//	entries. No compression, no crypto at the parse layer. Operators
//	paste RIP UDP payload bytes from tcpdump (port 520) or a Wireshark
//	RIP dissector and get a full per-packet breakdown including route
//	enumeration, auth-type detection, and cleartext-password flagging.
package rip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const (
	ripHeaderSize   = 4
	routeEntrySize  = 20
	maxRoutesOutput = 10

	afINET = 0x0002
	afAuth = 0xFFFF

	authTypePassword = 2
	authTypeMD5      = 3

	metricInfinity = 16

	cmdRequest  = 1
	cmdResponse = 2
)

// RouteEntry is a decoded RIP route entry (20 bytes).
type RouteEntry struct {
	AddressFamily uint16 `json:"address_family"`
	RouteTag      uint16 `json:"route_tag,omitempty"`
	IPAddress     string `json:"ip_address"`
	SubnetMask    string `json:"subnet_mask,omitempty"`
	NextHop       string `json:"next_hop,omitempty"`
	Metric        uint32 `json:"metric"`
}

// Result is the structured decode of a RIP v1/v2 packet.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Header fields
	Command     uint8  `json:"command"`
	CommandName string `json:"command_name"`
	Version     uint8  `json:"version"`

	// Route summary
	RouteCount int          `json:"route_count"`
	Routes     []RouteEntry `json:"routes,omitempty"`

	// Authentication
	HasAuth         bool   `json:"has_auth"`
	AuthType        uint16 `json:"auth_type,omitempty"`
	AuthTypeName    string `json:"auth_type_name,omitempty"`
	IsCleartextAuth bool   `json:"is_cleartext_auth"`
	CleartextFlag   string `json:"cleartext_auth_flag,omitempty"`

	// Security flags
	HasInfinityMetric bool `json:"has_infinity_metric"`

	// Classification
	IsRequest  bool `json:"is_request"`
	IsResponse bool `json:"is_response"`
}

// Decode parses a RIP v1/v2 UDP payload from a hex string.
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
	if len(b) < ripHeaderSize {
		return nil, fmt.Errorf("rip header truncated (%d bytes; need %d)", len(b), ripHeaderSize)
	}

	r := &Result{TotalBytes: len(b)}

	r.Command = b[0]
	r.Version = b[1]
	// bytes 2-3: zero / routing domain — not decoded
	r.CommandName = commandName(r.Command)
	r.IsRequest = r.Command == cmdRequest
	r.IsResponse = r.Command == cmdResponse

	body := b[ripHeaderSize:]
	parseRoutes(r, body)

	return r, nil
}

func parseRoutes(r *Result, body []byte) {
	off := 0
	var routes []RouteEntry

	for off+routeEntrySize <= len(body) {
		entry := body[off : off+routeEntrySize]
		off += routeEntrySize

		af := binary.BigEndian.Uint16(entry[0:2])

		if af == afAuth {
			// Authentication entry
			authType := binary.BigEndian.Uint16(entry[2:4])
			r.HasAuth = true
			r.AuthType = authType
			r.AuthTypeName = authTypeName(authType)
			if authType == authTypePassword {
				r.IsCleartextAuth = true
				r.CleartextFlag = "RIPv2 simple-password auth (type 2) — 16-byte password " +
					"transmitted in cleartext inside the authentication entry; passive " +
					"network capture immediately yields the shared secret"
			}
			// Auth entry does not count as a route
			continue
		}

		route := RouteEntry{
			AddressFamily: af,
			RouteTag:      binary.BigEndian.Uint16(entry[2:4]),
			IPAddress:     fmtIP(entry[4:8]),
			SubnetMask:    fmtIP(entry[8:12]),
			NextHop:       fmtIP(entry[12:16]),
			Metric:        binary.BigEndian.Uint32(entry[16:20]),
		}

		if route.Metric == metricInfinity {
			r.HasInfinityMetric = true
		}

		r.RouteCount++
		if len(routes) < maxRoutesOutput {
			routes = append(routes, route)
		}
	}

	if len(routes) > 0 {
		r.Routes = routes
	}
}

func fmtIP(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return net.IP(b[:4]).String()
}

func commandName(cmd uint8) string {
	switch cmd {
	case cmdRequest:
		return "Request"
	case cmdResponse:
		return "Response"
	}
	return fmt.Sprintf("command_%d", cmd)
}

func authTypeName(t uint16) string {
	switch t {
	case authTypePassword:
		return "Simple Password (cleartext)"
	case authTypeMD5:
		return "MD5"
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
