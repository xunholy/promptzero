// Package natpmp decodes NAT-PMP (NAT Port Mapping Protocol)
// messages per RFC 6886. NAT-PMP is the predecessor to PCP
// (RFC 6887, covered by `pcp_decode`) — Apple's 2008 design
// that PCP superseded in 2013 but which remains widely
// deployed in older residential broadband CPE (every Apple
// Airport / Time Capsule / early Asus / Belkin / Linksys
// router shipped before ~2014 speaks NAT-PMP rather than PCP).
// Modern peer-to-peer applications (BitTorrent clients,
// Tailscale, libnatpmp) try NAT-PMP first and fall back to
// UPnP IGD when neither NAT-PMP nor PCP works.
//
// Wrap-vs-native judgement
//
//	Native. RFC 6886 is fully public. NAT-PMP has tight
//	fixed-position messages (2 bytes for the Public
//	Address Request; 12 bytes for Map Requests and
//	Public Address Responses; 16 bytes for Map Responses).
//	No crypto at the parse layer, no variable-length
//	fields. Operators paste NAT-PMP bytes (UDP destination
//	port 5351) from a `tcpdump -X udp port 5351` line or a
//	Wireshark Follow-UDP-Stream view and get the documented
//	per-opcode breakdown.
//
// What this package covers
//
//   - **Common header**: byte 0 = Version (must be 0 for
//     NAT-PMP; 2 indicates PCP — use `pcp_decode` instead);
//     byte 1 = **Opcode** with the high bit signalling
//     direction (Request when clear, Response when set).
//     **6-entry opcode name table** (low 7 bits): 0 Public
//     Address Request / 128 (0x80) Public Address Response /
//     1 Map UDP Request / 129 (0x81) Map UDP Response / 2
//     Map TCP Request / 130 (0x82) Map TCP Response.
//
//   - **Public Address Request** (Opcode 0, 2 bytes total):
//     Version + Opcode only. Client asks the gateway for
//     its WAN-facing IP.
//
//   - **Public Address Response** (Opcode 128, 12 bytes):
//     Version + Opcode + 2-byte **Result Code** + 4-byte
//     Seconds Since Epoch (server-anchor counter for
//     mapping-validity comparisons) + 4-byte **Public IP**
//     (IPv4). NAT-PMP is IPv4-only — IPv6 hosts use PCP.
//
//   - **Map Request** (Opcode 1 for UDP / 2 for TCP, 12
//     bytes): Version + Opcode + 2-byte Reserved + 2-byte
//     Internal Port + 2-byte **Suggested External Port**
//     (client hint; server may pick differently) + 4-byte
//     **Requested Lifetime** (seconds; 0 = delete mapping).
//
//   - **Map Response** (Opcode 129 for UDP / 130 for TCP,
//     16 bytes): Version + Opcode + 2-byte Result Code +
//     4-byte Seconds Since Epoch + 2-byte Internal Port +
//     2-byte **Mapped External Port** (granted; may differ
//     from suggestion) + 4-byte **Granted Lifetime**.
//
//   - **6-entry Result Code name table** (RFC 6886 §3.5):
//     0 SUCCESS / 1 UNSUPP_VERSION / 2 NOT_AUTHORIZED
//     (gateway refused; common when the gateway
//     administratively disables NAT-PMP) / 3 NETWORK_FAILURE
//     (no upstream connectivity) / 4 OUT_OF_RESOURCES (port
//     range exhausted; client should retry later) / 5
//     UNSUPPORTED_OPCODE.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP framing — feed NAT-PMP bytes after the UDP header
//     strip. NAT-PMP runs on UDP destination port 5351;
//     clients listen on UDP 5350 for unsolicited Public
//     Address change announcements.
//
//   - PCP (RFC 6887) — the successor protocol that adds
//     IPv6, peer-mapping, and TLV options. Use `pcp_decode`
//     for PCP messages (Version=2 in the first byte).
//
//   - UPnP IGD — different protocol family (HTTP/XML over
//     SSDP discovery). Not related to NAT-PMP.
//
//   - NAT-PMP unsolicited announcements (Version=0 Opcode=128
//     sent to clients on UDP 5350 when the gateway WAN IP
//     changes) — decoded with the standard Public Address
//     Response layout; the operator's framing context tells
//     them whether it's a unicast reply or a multicast
//     announcement.
package natpmp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view of a NAT-PMP message.
type Result struct {
	Version    int    `json:"version"`
	Opcode     int    `json:"opcode"`
	OpcodeName string `json:"opcode_name"`
	IsResponse bool   `json:"is_response"`
	TotalBytes int    `json:"total_bytes"`

	PublicAddressRequest  *PublicAddressRequestBody  `json:"public_address_request,omitempty"`
	PublicAddressResponse *PublicAddressResponseBody `json:"public_address_response,omitempty"`
	MapRequest            *MapRequestBody            `json:"map_request,omitempty"`
	MapResponse           *MapResponseBody           `json:"map_response,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// PublicAddressRequestBody is the decoded body of Opcode 0.
// No fields beyond the common header — surfaced as a tag for
// JSON differentiation.
type PublicAddressRequestBody struct{}

// PublicAddressResponseBody is the decoded body of Opcode 128.
type PublicAddressResponseBody struct {
	ResultCode        int    `json:"result_code"`
	ResultCodeName    string `json:"result_code_name"`
	SecondsSinceEpoch uint32 `json:"seconds_since_epoch"`
	PublicIPAddress   string `json:"public_ip_address"`
}

// MapRequestBody is the decoded body of Opcode 1 (UDP) or 2 (TCP).
type MapRequestBody struct {
	Protocol              string `json:"protocol"`
	InternalPort          int    `json:"internal_port"`
	SuggestedExternalPort int    `json:"suggested_external_port"`
	RequestedLifetimeSec  uint32 `json:"requested_lifetime_seconds"`
}

// MapResponseBody is the decoded body of Opcode 129 (UDP) or 130 (TCP).
type MapResponseBody struct {
	Protocol           string `json:"protocol"`
	ResultCode         int    `json:"result_code"`
	ResultCodeName     string `json:"result_code_name"`
	SecondsSinceEpoch  uint32 `json:"seconds_since_epoch"`
	InternalPort       int    `json:"internal_port"`
	MappedExternalPort int    `json:"mapped_external_port"`
	LifetimeSec        uint32 `json:"lifetime_seconds"`
}

// Decode parses a single NAT-PMP message from hex.
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
	if len(b) < 2 {
		return nil, fmt.Errorf("NAT-PMP message truncated (%d bytes; need ≥2 for version + opcode)",
			len(b))
	}
	r := &Result{
		TotalBytes: len(b),
		Version:    int(b[0]),
		Opcode:     int(b[1]),
		IsResponse: b[1]&0x80 != 0,
	}
	r.OpcodeName = opcodeName(r.Opcode)
	if r.Version != 0 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"version is %d (NAT-PMP requires version 0; version 2 indicates PCP — use pcp_decode)",
			r.Version))
	}
	switch r.Opcode {
	case 0:
		r.PublicAddressRequest = &PublicAddressRequestBody{}
		if len(b) > 2 {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"Public Address Request has %d trailing bytes after the 2-byte header", len(b)-2))
		}
	case 128:
		if len(b) < 12 {
			return r, fmt.Errorf("public address response truncated (%d; need 12)", len(b))
		}
		body := &PublicAddressResponseBody{
			ResultCode:        int(binary.BigEndian.Uint16(b[2:4])),
			SecondsSinceEpoch: binary.BigEndian.Uint32(b[4:8]),
			PublicIPAddress:   ipv4String(b[8:12]),
		}
		body.ResultCodeName = resultCodeName(body.ResultCode)
		r.PublicAddressResponse = body
	case 1, 2:
		if len(b) < 12 {
			return r, fmt.Errorf("map request truncated (%d; need 12)", len(b))
		}
		proto := "UDP"
		if r.Opcode == 2 {
			proto = "TCP"
		}
		r.MapRequest = &MapRequestBody{
			Protocol:              proto,
			InternalPort:          int(binary.BigEndian.Uint16(b[4:6])),
			SuggestedExternalPort: int(binary.BigEndian.Uint16(b[6:8])),
			RequestedLifetimeSec:  binary.BigEndian.Uint32(b[8:12]),
		}
	case 129, 130:
		if len(b) < 16 {
			return r, fmt.Errorf("map response truncated (%d; need 16)", len(b))
		}
		proto := "UDP"
		if r.Opcode == 130 {
			proto = "TCP"
		}
		body := &MapResponseBody{
			Protocol:           proto,
			ResultCode:         int(binary.BigEndian.Uint16(b[2:4])),
			SecondsSinceEpoch:  binary.BigEndian.Uint32(b[4:8]),
			InternalPort:       int(binary.BigEndian.Uint16(b[8:10])),
			MappedExternalPort: int(binary.BigEndian.Uint16(b[10:12])),
			LifetimeSec:        binary.BigEndian.Uint32(b[12:16]),
		}
		body.ResultCodeName = resultCodeName(body.ResultCode)
		r.MapResponse = body
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"uncatalogued NAT-PMP opcode %d (RFC 6886 defines 0/1/2 + responses 128/129/130)",
			r.Opcode))
	}
	return r, nil
}

func opcodeName(op int) string {
	switch op {
	case 0:
		return "Public Address Request"
	case 1:
		return "Map UDP Request"
	case 2:
		return "Map TCP Request"
	case 128:
		return "Public Address Response"
	case 129:
		return "Map UDP Response"
	case 130:
		return "Map TCP Response"
	}
	return fmt.Sprintf("uncatalogued opcode %d", op)
}

func resultCodeName(c int) string {
	switch c {
	case 0:
		return "SUCCESS"
	case 1:
		return "UNSUPP_VERSION"
	case 2:
		return "NOT_AUTHORIZED"
	case 3:
		return "NETWORK_FAILURE"
	case 4:
		return "OUT_OF_RESOURCES"
	case 5:
		return "UNSUPPORTED_OPCODE"
	}
	return fmt.Sprintf("uncatalogued result code %d", c)
}

func ipv4String(b []byte) string {
	if len(b) != 4 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
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
