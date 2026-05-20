// Package pcp decodes PCP (Port Control Protocol) messages
// per RFC 6887. PCP is the modern NAT/firewall configuration
// protocol that supersedes NAT-PMP (RFC 6886) and adds IPv6
// support, peer-mapping (for hole-punching), and a more
// flexible TLV-options envelope. Universal in residential
// broadband CPE (every ASUS / Netgear / Fritz!Box router /
// CGNAT enforcement at carriers since ~2014); used directly
// by uTorrent / qBittorrent / Tailscale's `libpcp` /
// libnatpmp / miniupnpd to request external port mappings on
// behalf of inbound-listening applications.
//
// Wrap-vs-native judgement
//
//	Native. RFC 6887 is fully public. PCP has a tight
//	24-byte common header (Version + R-bit + Opcode +
//	per-direction fields) followed by an opcode-specific
//	body and an optional TLV options walker. No crypto at
//	the parse layer.
//
// What this package covers
//
//   - **24-byte common header** (RFC 6887 §7.1):
//
//   - byte 0: Version (must be 2 for PCP).
//
//   - byte 1: R-bit (high bit; 0 = Request from client,
//     1 = Response from server) + low 7 bits = **Opcode**
//     with **3-entry name table**: 0 ANNOUNCE / 1 MAP /
//     2 PEER.
//
//   - For **Requests** (R=0):
//
//   - 2-byte Reserved.
//
//   - 4-byte Requested Lifetime (seconds; 0 = delete
//     mapping).
//
//   - 16-byte PCP Client IP Address (IPv4-mapped or
//     IPv6).
//
//   - For **Responses** (R=1):
//
//   - 1-byte Reserved.
//
//   - 1-byte **Result Code** with **14-entry name
//     table** (RFC 6887 §7.4): 0 SUCCESS / 1
//     UNSUPP_VERSION / 2 NOT_AUTHORIZED / 3
//     MALFORMED_REQUEST / 4 UNSUPP_OPCODE / 5
//     UNSUPP_OPTION / 6 MALFORMED_OPTION / 7
//     NETWORK_FAILURE / 8 NO_RESOURCES / 9
//     UNSUPP_PROTOCOL / 10 USER_EX_QUOTA / 11
//     CANNOT_PROVIDE_EXTERNAL / 12 ADDRESS_MISMATCH /
//     13 EXCESSIVE_REMOTE_PEERS.
//
//   - 4-byte Lifetime (granted; or error retry-after
//     on negative Result Code).
//
//   - 4-byte Epoch Time (server's monotonic
//     re-anchor counter).
//
//   - 12-byte Reserved.
//
//   - **MAP opcode body** (Opcode 1; RFC 6887 §11):
//
//   - 12-byte Mapping Nonce (client-generated cookie
//     for request/response correlation).
//
//   - 1-byte Protocol (IP proto number; 0 = "all
//     protocols").
//
//   - 3-byte Reserved.
//
//   - 2-byte Internal Port (the port the client wants
//     to receive on).
//
//   - 2-byte Suggested External Port (client hint;
//     server may pick differently).
//
//   - 16-byte Suggested External IP Address (client
//     hint; server may pick differently).
//
//   - **PEER opcode body** (Opcode 2; RFC 6887 §12) —
//     same as MAP plus a remote-peer tuple appended:
//
//   - 2-byte Remote Peer Port.
//
//   - 2-byte Reserved.
//
//   - 16-byte Remote Peer IP Address.
//
//   - **ANNOUNCE opcode** (Opcode 0) — no opcode-specific
//     body; the common header alone signals server epoch
//     reset (clients must refresh all mappings when
//     received).
//
//   - **Options walker** (RFC 6887 §7.3) — optional TLV
//     records appended after the opcode body. Each option:
//
//   - 1-byte Option Code (high bit = mandatory).
//
//   - 1-byte Reserved.
//
//   - 2-byte Option Length (uint16 BE; excludes header).
//
//   - Padded to 4-byte boundary.
//     **6-entry option code name table** (RFC 6887 + 7488
//
//   - 6970 + 7843): 1 THIRD_PARTY (request mapping on
//     behalf of another IP) / 2 PREFER_FAILURE (don't
//     downgrade to a different port if requested
//     unavailable) / 3 FILTER (restrict the mapping to a
//     specific peer) / 4 NAT64_PREFIX (DS-Lite / NAT64
//     prefix discovery) / 5 PORT_SET (request multiple
//     consecutive ports as one mapping).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP framing — feed PCP bytes after the UDP header
//     strip. PCP runs on UDP destination port 5351 (server
//     side); clients listen on UDP 5350 for ANNOUNCE
//     multicasts.
//
//   - NAT-PMP (RFC 6886) — the predecessor protocol that
//     PCP supersedes (8-byte messages, IPv4-only,
//     simpler). Could share most decoder logic but has a
//     different envelope; deferred.
//
//   - PCP Authentication (RFC 7652) — optional auth
//     extension via 2 additional option types (5
//     ASMAP_CAPA, 6 NONCE) — surfaced as raw hex via the
//     generic option walker.
package pcp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view of a PCP message.
type Result struct {
	Version    int    `json:"version"`
	IsResponse bool   `json:"is_response"`
	Opcode     int    `json:"opcode"`
	OpcodeName string `json:"opcode_name"`
	TotalBytes int    `json:"total_bytes"`

	// Per-direction header fields.
	RequestHeader  *RequestHeader  `json:"request_header,omitempty"`
	ResponseHeader *ResponseHeader `json:"response_header,omitempty"`

	// Per-opcode bodies.
	MapBody  *MapBody  `json:"map_body,omitempty"`
	PeerBody *PeerBody `json:"peer_body,omitempty"`

	Options []Option `json:"options,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// RequestHeader is the request-specific portion of the common
// header (R-bit = 0).
type RequestHeader struct {
	RequestedLifetimeSec uint32 `json:"requested_lifetime_seconds"`
	ClientIPAddress      string `json:"pcp_client_ip_address"`
}

// ResponseHeader is the response-specific portion of the
// common header (R-bit = 1).
type ResponseHeader struct {
	ResultCode     int    `json:"result_code"`
	ResultCodeName string `json:"result_code_name"`
	LifetimeSec    uint32 `json:"lifetime_seconds"`
	EpochTime      uint32 `json:"epoch_time"`
}

// MapBody is the decoded body of a MAP-opcode message.
type MapBody struct {
	MappingNonceHex          string `json:"mapping_nonce_hex"`
	Protocol                 int    `json:"protocol"`
	ProtocolName             string `json:"protocol_name"`
	InternalPort             int    `json:"internal_port"`
	SuggestedExternalPort    int    `json:"suggested_external_port"`
	SuggestedExternalAddress string `json:"suggested_external_address"`
}

// PeerBody is the decoded body of a PEER-opcode message.
type PeerBody struct {
	MapBody
	RemotePeerPort    int    `json:"remote_peer_port"`
	RemotePeerAddress string `json:"remote_peer_address"`
}

// Option is one TLV record from the options walker.
type Option struct {
	Code      int    `json:"code"`
	CodeName  string `json:"code_name"`
	Mandatory bool   `json:"mandatory"`
	Length    int    `json:"length"`
	ValueHex  string `json:"value_hex,omitempty"`
}

// Decode parses a single PCP message from hex.
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
	if len(b) < 24 {
		return nil, fmt.Errorf("PCP message truncated (%d bytes; need ≥24 for common header)",
			len(b))
	}
	r := &Result{
		TotalBytes: len(b),
		Version:    int(b[0]),
		IsResponse: b[1]&0x80 != 0,
		Opcode:     int(b[1] & 0x7F),
	}
	r.OpcodeName = opcodeName(r.Opcode)
	if r.Version != 2 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"version is %d (this Spec covers PCP / RFC 6887 version 2 only)", r.Version))
	}
	if r.IsResponse {
		r.ResponseHeader = &ResponseHeader{
			ResultCode:  int(b[3]),
			LifetimeSec: binary.BigEndian.Uint32(b[4:8]),
			EpochTime:   binary.BigEndian.Uint32(b[8:12]),
		}
		r.ResponseHeader.ResultCodeName = resultCodeName(r.ResponseHeader.ResultCode)
	} else {
		r.RequestHeader = &RequestHeader{
			RequestedLifetimeSec: binary.BigEndian.Uint32(b[4:8]),
			ClientIPAddress:      formatIPv6(b[8:24]),
		}
	}
	body := b[24:]
	switch r.Opcode {
	case 0:
		// ANNOUNCE has no opcode-specific body.
	case 1:
		if mb, n, err := decodeMap(body); err == nil {
			r.MapBody = mb
			r.Options = decodeOptions(body[n:])
		} else {
			r.Notes = append(r.Notes, err.Error())
		}
	case 2:
		if pb, n, err := decodePeer(body); err == nil {
			r.PeerBody = pb
			r.Options = decodeOptions(body[n:])
		} else {
			r.Notes = append(r.Notes, err.Error())
		}
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"uncatalogued PCP opcode %d (RFC 6887 defines 0/1/2)", r.Opcode))
	}
	return r, nil
}

func decodeMap(b []byte) (*MapBody, int, error) {
	const need = 36 // 12 nonce + 1 proto + 3 reserved + 2 int port + 2 ext port + 16 ext addr
	if len(b) < need {
		return nil, 0, fmt.Errorf("MAP body truncated (%d; need %d)", len(b), need)
	}
	mb := &MapBody{
		MappingNonceHex:          strings.ToUpper(hex.EncodeToString(b[0:12])),
		Protocol:                 int(b[12]),
		InternalPort:             int(binary.BigEndian.Uint16(b[16:18])),
		SuggestedExternalPort:    int(binary.BigEndian.Uint16(b[18:20])),
		SuggestedExternalAddress: formatIPv6(b[20:36]),
	}
	mb.ProtocolName = protocolName(mb.Protocol)
	return mb, need, nil
}

func decodePeer(b []byte) (*PeerBody, int, error) {
	const need = 56 // MAP 36 + 2 remote port + 2 reserved + 16 remote addr
	if len(b) < need {
		return nil, 0, fmt.Errorf("PEER body truncated (%d; need %d)", len(b), need)
	}
	mb, _, err := decodeMap(b)
	if err != nil {
		return nil, 0, err
	}
	pb := &PeerBody{MapBody: *mb}
	pb.RemotePeerPort = int(binary.BigEndian.Uint16(b[36:38]))
	pb.RemotePeerAddress = formatIPv6(b[40:56])
	return pb, need, nil
}

func decodeOptions(b []byte) []Option {
	var out []Option
	off := 0
	for off+4 <= len(b) {
		code := int(b[off] & 0x7F)
		mandatory := b[off]&0x80 != 0
		ln := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if off+4+ln > len(b) {
			break
		}
		v := b[off+4 : off+4+ln]
		out = append(out, Option{
			Code:      code,
			CodeName:  optionCodeName(code),
			Mandatory: mandatory,
			Length:    ln,
			ValueHex:  strings.ToUpper(hex.EncodeToString(v)),
		})
		padded := off + 4 + ln + ((4 - (ln % 4)) % 4)
		off = padded
	}
	return out
}

func opcodeName(op int) string {
	switch op {
	case 0:
		return "ANNOUNCE"
	case 1:
		return "MAP"
	case 2:
		return "PEER"
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
		return "MALFORMED_REQUEST"
	case 4:
		return "UNSUPP_OPCODE"
	case 5:
		return "UNSUPP_OPTION"
	case 6:
		return "MALFORMED_OPTION"
	case 7:
		return "NETWORK_FAILURE"
	case 8:
		return "NO_RESOURCES"
	case 9:
		return "UNSUPP_PROTOCOL"
	case 10:
		return "USER_EX_QUOTA"
	case 11:
		return "CANNOT_PROVIDE_EXTERNAL"
	case 12:
		return "ADDRESS_MISMATCH"
	case 13:
		return "EXCESSIVE_REMOTE_PEERS"
	}
	return fmt.Sprintf("uncatalogued result code %d", c)
}

func optionCodeName(c int) string {
	switch c {
	case 1:
		return "THIRD_PARTY"
	case 2:
		return "PREFER_FAILURE"
	case 3:
		return "FILTER"
	case 4:
		return "NAT64_PREFIX"
	case 5:
		return "PORT_SET"
	}
	return fmt.Sprintf("uncatalogued option %d", c)
}

func protocolName(p int) string {
	switch p {
	case 0:
		return "ALL protocols"
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 33:
		return "DCCP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 132:
		return "SCTP"
	}
	return fmt.Sprintf("uncatalogued IP protocol %d", p)
}

// formatIPv6 renders a 16-byte address as IPv4 when it's an
// IPv4-mapped IPv6 (RFC 4291 §2.5.5.2: ::FFFF:0:0/96), otherwise
// as canonical IPv6.
func formatIPv6(b []byte) string {
	if len(b) != 16 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	ip := net.IP(b)
	if v4 := ip.To4(); v4 != nil {
		// Only treat as v4 when it's actually the IPv4-mapped pattern.
		if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
			b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
			b[8] == 0 && b[9] == 0 && b[10] == 0xFF && b[11] == 0xFF {
			return v4.String()
		}
	}
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
