// Package pppoe decodes Point-to-Point Protocol over Ethernet
// packets per RFC 2516 — both the Discovery phase (PADI /
// PADO / PADR / PADS / PADT) and the Session phase (PPP-in-
// PPPoE payload).
//
// Wrap-vs-native judgement
//
//	Native. RFC 2516 is fully public; PPPoE is a tight
//	6-byte header (Version+Type byte + Code + Session ID +
//	Length) followed by either a TLV stream (Discovery
//	stage) or a PPP frame (Session stage). No crypto, no
//	compression, no varints. Operators paste post-Ethernet
//	bytes (EtherType 0x8863 for Discovery or 0x8864 for
//	Session) from a `tcpdump -X ether proto 0x8863` line, a
//	Wireshark Follow-Frame view, or any PPPoE-emitting tool
//	and get the documented header + per-phase body.
//
// What this package covers
//
//   - **6-byte header**:
//
//   - byte 0: Version (4 bits) + Type (4 bits). Both MUST
//     be 1 per RFC 2516 (so byte 0 must be 0x11). Other
//     values surface a conformance Note.
//
//   - byte 1: **Code** with **6-entry name table**:
//
//   - 0x00 Session (PPPoE Session; carries a PPP frame)
//
//   - 0x09 PADI (PPPoE Active Discovery Initiation —
//     client broadcasts to find an Access Concentrator)
//
//   - 0x07 PADO (PPPoE Active Discovery Offer — AC
//     responds with its services)
//
//   - 0x19 PADR (PPPoE Active Discovery Request —
//     client picks an AC)
//
//   - 0x65 PADS (PPPoE Active Discovery Session-
//     confirmation — AC assigns a Session ID)
//
//   - 0xA7 PADT (PPPoE Active Discovery Terminate —
//     either side tearing down the session)
//
//   - bytes 2-3: Session ID (uint16 BE; 0x0000 during
//     Discovery, then assigned by the AC in PADS).
//
//   - bytes 4-5: Length (uint16 BE; length of the payload
//     after the 6-byte header).
//
//   - **Discovery TLV walker** (Codes 0x09 / 0x07 / 0x19 /
//     0x65 / 0xA7): each TLV is Tag Type (2 bytes BE) + Tag
//     Length (2 bytes BE) + Tag Value (Length bytes). The
//     walker iterates until end-of-list (Tag Type 0x0000) or
//     buffer exhaustion. **9-entry Tag Type name table** (RFC
//     2516 §4):
//
//   - 0x0000 End-Of-List
//
//   - 0x0101 Service-Name (UTF-8)
//
//   - 0x0102 AC-Name (Access Concentrator Name, UTF-8)
//
//   - 0x0103 Host-Uniq (opaque cookie chosen by client to
//     match PADO replies to its PADI)
//
//   - 0x0104 AC-Cookie (opaque cookie chosen by AC; client
//     echoes back in PADR for DoS mitigation)
//
//   - 0x0105 Vendor-Specific (4-byte vendor ID + opaque
//     body)
//
//   - 0x0110 Relay-Session-ID (binary; used by intermediate
//     relays)
//
//   - 0x0201 Service-Name-Error (UTF-8 error message when
//     Service-Name can't be honoured)
//
//   - 0x0202 AC-System-Error (UTF-8 error)
//
//   - 0x0203 Generic-Error (UTF-8 error)
//
//   - **Session-stage payload** (Code 0x00): the first 2 bytes
//     of the PPPoE payload are the PPP Protocol Identifier
//     (uint16 BE per RFC 1661). **9-entry PPP Protocol name
//     table**:
//
//   - 0x0021 IPv4
//
//   - 0x0057 IPv6
//
//   - 0x8021 IPCP (IP Control Protocol)
//
//   - 0x8057 IPv6CP
//
//   - 0xC021 LCP (Link Control Protocol)
//
//   - 0xC023 PAP (Password Authentication Protocol)
//
//   - 0xC223 CHAP (Challenge Handshake Authentication
//     Protocol)
//
//   - 0xC227 EAP-over-PPP (deprecated value)
//
//   - 0xC229 EAP (Extensible Authentication Protocol)
//
//   - **Conformance checks**:
//
//   - Version != 1 or Type != 1 surfaces a Note.
//
//   - PADx codes with non-zero Session ID surface a Note
//     (only PADS and Session can have a non-zero ID).
//
//   - Length field mismatch (declared vs buffer remaining)
//     surfaces a Note.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Ethernet framing — feed the PPPoE bytes after the
//     EtherType 0x8863 (Discovery) / 0x8864 (Session) strip.
//
//   - PPP frame deep dissection (LCP CONFIG-REQ option TLVs,
//     PAP / CHAP / EAP protocol exchanges, IPCP option TLVs)
//     — the Session payload's Protocol ID is recognised but
//     the body is surfaced as raw hex. Inner IPv4 / IPv6
//     payloads can be piped to `ip_packet_decode`.
//
//   - PPPoE Tag Value deep dissection beyond UTF-8 / hex
//     surface — Vendor-Specific body, Service-Name semantics,
//     etc., belong in operator analysis or a sibling helper.
package pppoe

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view.
type Result struct {
	Version        int    `json:"version"`
	Type           int    `json:"type"`
	Code           int    `json:"code"`
	CodeHex        string `json:"code_hex"`
	CodeName       string `json:"code_name"`
	SessionID      uint16 `json:"session_id"`
	SessionIDHex   string `json:"session_id_hex"`
	LengthDeclared int    `json:"length_declared"`
	IsDiscovery    bool   `json:"is_discovery"`
	IsSession      bool   `json:"is_session"`

	Tags []Tag `json:"tags,omitempty"`

	PPPProtocol     *uint16 `json:"ppp_protocol,omitempty"`
	PPPProtocolHex  string  `json:"ppp_protocol_hex,omitempty"`
	PPPProtocolName string  `json:"ppp_protocol_name,omitempty"`
	PPPPayloadHex   string  `json:"ppp_payload_hex,omitempty"`
	PPPPayloadLen   int     `json:"ppp_payload_length,omitempty"`

	HeaderBytes int      `json:"header_bytes"`
	TotalBytes  int      `json:"total_bytes"`
	Notes       []string `json:"notes,omitempty"`
}

// Tag is one decoded PPPoE Discovery TLV.
type Tag struct {
	Type      int    `json:"type"`
	TypeHex   string `json:"type_hex"`
	TypeName  string `json:"type_name"`
	Length    int    `json:"length"`
	ValueHex  string `json:"value_hex,omitempty"`
	ValueText string `json:"value_text,omitempty"`
}

// Decode parses a PPPoE packet from hex.
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
	if len(b) < 6 {
		return nil, fmt.Errorf("PPPoE header truncated (%d bytes; need ≥6)", len(b))
	}

	r := &Result{
		TotalBytes:     len(b),
		Version:        int(b[0] >> 4),
		Type:           int(b[0] & 0x0F),
		Code:           int(b[1]),
		CodeHex:        fmt.Sprintf("0x%02X", b[1]),
		SessionID:      binary.BigEndian.Uint16(b[2:4]),
		LengthDeclared: int(binary.BigEndian.Uint16(b[4:6])),
		HeaderBytes:    6,
	}
	r.CodeName = codeName(r.Code)
	r.SessionIDHex = fmt.Sprintf("0x%04X", r.SessionID)
	r.IsDiscovery = r.Code != 0x00
	r.IsSession = r.Code == 0x00

	if r.Version != 1 || r.Type != 1 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Version=%d Type=%d — RFC 2516 §4 requires both to be 1 (byte 0 must be 0x11)",
			r.Version, r.Type))
	}

	// Length conformance check.
	if r.LengthDeclared > len(b)-6 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"declared Length %d exceeds buffer remaining %d bytes",
			r.LengthDeclared, len(b)-6))
	}
	if r.LengthDeclared < len(b)-6 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"declared Length %d is less than buffer remaining %d bytes (trailing %d "+
				"bytes will be ignored)",
			r.LengthDeclared, len(b)-6, len(b)-6-r.LengthDeclared))
	}

	// PADx codes (Discovery stage) should have Session ID = 0
	// except for PADS (which assigns the Session ID) and PADT
	// (which tears down a known session).
	if r.IsDiscovery && r.Code != 0x65 && r.Code != 0xA7 && r.SessionID != 0 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Discovery code 0x%02X (%s) has non-zero Session ID 0x%04X — RFC 2516 "+
				"requires Session ID to be 0 during PADI/PADO/PADR",
			r.Code, r.CodeName, r.SessionID))
	}

	// Cap the payload we look at to the declared Length (or
	// buffer remaining if smaller).
	payloadEnd := 6 + r.LengthDeclared
	if payloadEnd > len(b) {
		payloadEnd = len(b)
	}
	payload := b[6:payloadEnd]

	switch {
	case r.IsDiscovery:
		r.Tags = parseTags(payload)
	case r.IsSession:
		if len(payload) >= 2 {
			proto := binary.BigEndian.Uint16(payload[0:2])
			r.PPPProtocol = &proto
			r.PPPProtocolHex = fmt.Sprintf("0x%04X", proto)
			r.PPPProtocolName = pppProtocolName(int(proto))
			body := payload[2:]
			r.PPPPayloadLen = len(body)
			if len(body) > 0 {
				if len(body) > 256 {
					r.PPPPayloadHex =
						strings.ToUpper(hex.EncodeToString(body[:256])) + "..."
				} else {
					r.PPPPayloadHex = strings.ToUpper(hex.EncodeToString(body))
				}
			}
		}
	}

	return r, nil
}

func parseTags(b []byte) []Tag {
	var tags []Tag
	off := 0
	for off+4 <= len(b) {
		typ := int(binary.BigEndian.Uint16(b[off : off+2]))
		ln := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if off+4+ln > len(b) {
			break // truncated
		}
		val := b[off+4 : off+4+ln]
		t := Tag{
			Type:     typ,
			TypeHex:  fmt.Sprintf("0x%04X", typ),
			TypeName: tagTypeName(typ),
			Length:   ln,
		}
		if ln > 0 {
			t.ValueHex = strings.ToUpper(hex.EncodeToString(val))
			if tagIsText(typ) && utf8.Valid(val) {
				t.ValueText = string(val)
			}
		}
		tags = append(tags, t)
		off += 4 + ln
		if typ == 0x0000 {
			break // End-Of-List
		}
	}
	return tags
}

func codeName(c int) string {
	switch c {
	case 0x00:
		return "Session (carries PPP frame)"
	case 0x09:
		return "PADI (PPPoE Active Discovery Initiation)"
	case 0x07:
		return "PADO (PPPoE Active Discovery Offer)"
	case 0x19:
		return "PADR (PPPoE Active Discovery Request)"
	case 0x65:
		return "PADS (PPPoE Active Discovery Session-confirmation)"
	case 0xA7:
		return "PADT (PPPoE Active Discovery Terminate)"
	}
	return fmt.Sprintf("uncatalogued code 0x%02X", c)
}

func tagTypeName(t int) string {
	switch t {
	case 0x0000:
		return "End-Of-List"
	case 0x0101:
		return "Service-Name"
	case 0x0102:
		return "AC-Name (Access Concentrator Name)"
	case 0x0103:
		return "Host-Uniq (client-chosen request cookie)"
	case 0x0104:
		return "AC-Cookie (AC-chosen DoS-mitigation cookie)"
	case 0x0105:
		return "Vendor-Specific"
	case 0x0110:
		return "Relay-Session-ID"
	case 0x0201:
		return "Service-Name-Error"
	case 0x0202:
		return "AC-System-Error"
	case 0x0203:
		return "Generic-Error"
	}
	return fmt.Sprintf("uncatalogued tag 0x%04X", t)
}

func tagIsText(t int) bool {
	switch t {
	case 0x0101, 0x0102, 0x0201, 0x0202, 0x0203:
		return true
	}
	return false
}

func pppProtocolName(p int) string {
	switch p {
	case 0x0021:
		return "IPv4"
	case 0x0057:
		return "IPv6"
	case 0x8021:
		return "IPCP (IP Control Protocol)"
	case 0x8057:
		return "IPv6CP"
	case 0xC021:
		return "LCP (Link Control Protocol)"
	case 0xC023:
		return "PAP (Password Authentication Protocol)"
	case 0xC223:
		return "CHAP (Challenge Handshake Auth Protocol)"
	case 0xC227:
		return "EAP-over-PPP (deprecated)"
	case 0xC229:
		return "EAP (Extensible Authentication Protocol)"
	}
	return fmt.Sprintf("uncatalogued PPP protocol 0x%04X", p)
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
