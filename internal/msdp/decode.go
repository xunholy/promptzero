// Package msdp decodes MSDP (Multicast Source Discovery
// Protocol) packets per RFC 3618. MSDP is the inter-domain
// multicast protocol that completes the multicast trio
// alongside IGMP (host↔router, covered by `igmp_decode`) and
// PIM (router↔router intra-domain, covered by `pim_decode`).
// Each PIM-SM domain has its own Rendezvous Points (RPs); MSDP
// connects RPs across domains so that a receiver in one domain
// can join a multicast group whose source is in another.
//
// Operationally, every major Internet exchange + carrier core
// that carries multicast traffic (financial-market data feeds,
// IPTV peering, content distribution) runs MSDP between RPs
// over TCP port 639.
//
// Wrap-vs-native judgement
//
//	Native. RFC 3618 is fully public; MSDP messages are
//	plain TLVs: 1-byte Type + 2-byte Length (including the
//	3-byte header) + per-type body. No crypto, no
//	compression. Operators paste MSDP bytes (TCP port 639)
//	from a `tcpdump -X tcp port 639` line or a Wireshark
//	Follow-TCP-Stream view and get the documented type +
//	body breakdown.
//
// What this package covers
//
//   - **3-byte TLV header** (RFC 3618 §3):
//
//   - byte 0: **Type** with **6-entry name table**:
//     1 IPv4 Source-Active, 2 IPv4 SA Request, 3 IPv4
//     SA Response, 4 Keepalive, 6 Notification, 7
//     Traceroute in Progress (deprecated), 8 Traceroute
//     Reply (deprecated).
//
//   - bytes 1-2: Length (uint16 BE; total including
//     this 3-byte header).
//
//   - **IPv4 Source-Active body** (Type 1; RFC 3618 §4.1):
//
//   - byte 0: Entry Count (uint8; number of (S, G) entries).
//
//   - bytes 1-4: RP Address (IPv4 — the originating
//     Rendezvous Point).
//
//   - **Entry × Entry Count** (each 12 bytes):
//
//   - 3-byte Reserved.
//
//   - 1-byte Sprefix Len (typically 32; the source
//     prefix length).
//
//   - 4-byte Group Address (IPv4 multicast).
//
//   - 4-byte Source Address (IPv4 unicast).
//
//   - Optional encapsulated multicast datagram (raw hex
//     — typically the first packet from a new source,
//     sent to bootstrap MSDP peers that haven't yet
//     built (S, G) state).
//
//   - **IPv4 SA Request body** (Type 2; RFC 3618 §4.2):
//
//   - byte 0: Reserved.
//
//   - bytes 1-4: Group Address (IPv4 multicast).
//
//   - **IPv4 SA Response body** (Type 3; RFC 3618 §4.3) —
//     same layout as Source-Active.
//
//   - **Keepalive body** (Type 4) — empty (header only;
//     length = 3).
//
//   - **Notification body** (Type 6; RFC 3618 §6.1):
//
//   - byte 0: **O (Open) bit** (high bit) + 7-bit **Error
//     Code** with **7-entry name table** (RFC 3618
//     §6.1): 1 Message Header Error, 2 SA-Request Error,
//     3 SA-Message/SA-Response Error, 4 Hold Timer
//     Expired, 5 Finite State Machine Error, 6
//     Notification, 7 Cease.
//
//   - byte 1: Error Subcode.
//
//   - bytes 2+: Data (variable; surfaced as hex).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - TCP framing — feed MSDP bytes after the TCP payload
//     extraction. MSDP runs on TCP port 639.
//
//   - MSDP state-machine reasoning (peer setup, SA cache,
//     hold-timer expiry, mesh-group RPF check) — higher-
//     level analysis.
//
//   - Encapsulated multicast datagram dissection — when
//     SA carries a bootstrap data packet, it's surfaced
//     as opaque hex; operators can feed it into
//     `ip_packet_decode` to walk the inner IP frame.
package msdp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view of an MSDP packet.
// A single TCP segment may contain multiple TLVs, so the
// decoder returns a slice of Messages.
type Result struct {
	Messages   []Message `json:"messages"`
	TotalBytes int       `json:"total_bytes"`
	Notes      []string  `json:"notes,omitempty"`
}

// Message is one MSDP TLV record.
type Message struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	BodyHex  string `json:"body_hex,omitempty"`

	// Decoded forms populated for known types.
	SourceActive *SourceActiveBody `json:"source_active,omitempty"`
	SARequest    *SARequestBody    `json:"sa_request,omitempty"`
	SAResponse   *SourceActiveBody `json:"sa_response,omitempty"`
	Notification *NotificationBody `json:"notification,omitempty"`
}

// SourceActiveBody is the decoded body of a Type 1 (or Type 3)
// Source-Active / SA Response message.
type SourceActiveBody struct {
	EntryCount        int                 `json:"entry_count"`
	RPAddress         string              `json:"rp_address"`
	Entries           []SourceActiveEntry `json:"entries"`
	EncapsulatedHex   string              `json:"encapsulated_datagram_hex,omitempty"`
	EncapsulatedBytes int                 `json:"encapsulated_datagram_bytes,omitempty"`
}

// SourceActiveEntry is one (S, G) record from an SA / SA
// Response body.
type SourceActiveEntry struct {
	Index         int    `json:"index"`
	SprefixLength int    `json:"sprefix_length"`
	GroupAddress  string `json:"group_address"`
	SourceAddress string `json:"source_address"`
}

// SARequestBody is the decoded body of a Type 2 SA Request.
type SARequestBody struct {
	GroupAddress string `json:"group_address"`
}

// NotificationBody is the decoded body of a Type 6 Notification.
type NotificationBody struct {
	OpenBit       bool   `json:"open_bit"`
	ErrorCode     int    `json:"error_code"`
	ErrorCodeName string `json:"error_code_name"`
	ErrorSubcode  int    `json:"error_subcode"`
	DataHex       string `json:"data_hex,omitempty"`
}

// Decode parses one or more MSDP TLVs from hex.
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
	if len(b) < 3 {
		return nil, fmt.Errorf("MSDP packet truncated (%d bytes; need ≥3 for TLV header)",
			len(b))
	}
	r := &Result{TotalBytes: len(b)}
	off := 0
	for off+3 <= len(b) {
		typ := int(b[off])
		ln := int(binary.BigEndian.Uint16(b[off+1 : off+3]))
		if ln < 3 {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"TLV at offset %d declares length %d (< 3 header bytes)", off, ln))
			return r, nil
		}
		if off+ln > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"TLV type %d at offset %d declares length %d but only %d remain",
				typ, off, ln, len(b)-off))
			return r, nil
		}
		body := b[off+3 : off+ln]
		m := Message{
			Type:     typ,
			TypeName: typeName(typ),
			Length:   ln,
			BodyHex:  strings.ToUpper(hex.EncodeToString(body)),
		}
		switch typ {
		case 1:
			m.SourceActive = decodeSourceActive(body)
		case 2:
			m.SARequest = decodeSARequest(body)
		case 3:
			m.SAResponse = decodeSourceActive(body)
		case 4:
			// Keepalive — empty body, no extra decode.
		case 6:
			m.Notification = decodeNotification(body)
		default:
			if typ != 7 && typ != 8 {
				r.Notes = append(r.Notes, fmt.Sprintf(
					"uncatalogued MSDP type %d (RFC 3618 defines 1-4, 6; 7-8 deprecated)", typ))
			}
		}
		r.Messages = append(r.Messages, m)
		off += ln
	}
	return r, nil
}

func decodeSourceActive(b []byte) *SourceActiveBody {
	if len(b) < 5 {
		return nil
	}
	body := &SourceActiveBody{
		EntryCount: int(b[0]),
		RPAddress:  ipv4String(b[1:5]),
	}
	off := 5
	for i := 0; i < body.EntryCount; i++ {
		if off+12 > len(b) {
			break
		}
		body.Entries = append(body.Entries, SourceActiveEntry{
			Index:         i,
			SprefixLength: int(b[off+3]),
			GroupAddress:  ipv4String(b[off+4 : off+8]),
			SourceAddress: ipv4String(b[off+8 : off+12]),
		})
		off += 12
	}
	if off < len(b) {
		enc := b[off:]
		body.EncapsulatedBytes = len(enc)
		body.EncapsulatedHex = strings.ToUpper(hex.EncodeToString(enc))
	}
	return body
}

func decodeSARequest(b []byte) *SARequestBody {
	if len(b) < 5 {
		return nil
	}
	return &SARequestBody{
		GroupAddress: ipv4String(b[1:5]),
	}
}

func decodeNotification(b []byte) *NotificationBody {
	if len(b) < 2 {
		return nil
	}
	n := &NotificationBody{
		OpenBit:      b[0]&0x80 != 0,
		ErrorCode:    int(b[0] & 0x7F),
		ErrorSubcode: int(b[1]),
	}
	n.ErrorCodeName = errorCodeName(n.ErrorCode)
	if len(b) > 2 {
		n.DataHex = strings.ToUpper(hex.EncodeToString(b[2:]))
	}
	return n
}

func typeName(t int) string {
	switch t {
	case 1:
		return "IPv4 Source-Active"
	case 2:
		return "IPv4 SA Request"
	case 3:
		return "IPv4 SA Response"
	case 4:
		return "Keepalive"
	case 6:
		return "Notification"
	case 7:
		return "Traceroute in Progress (deprecated)"
	case 8:
		return "Traceroute Reply (deprecated)"
	}
	return fmt.Sprintf("uncatalogued type %d", t)
}

func errorCodeName(c int) string {
	switch c {
	case 0:
		return "Reserved"
	case 1:
		return "Message Header Error"
	case 2:
		return "SA-Request Error"
	case 3:
		return "SA-Message/SA-Response Error"
	case 4:
		return "Hold Timer Expired"
	case 5:
		return "Finite State Machine Error"
	case 6:
		return "Notification"
	case 7:
		return "Cease"
	}
	return fmt.Sprintf("uncatalogued error code %d", c)
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
