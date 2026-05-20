// Package llmnr decodes LLMNR (Link-Local Multicast Name
// Resolution) messages per RFC 4795. LLMNR is the modern
// Windows multicast name-resolution protocol that runs over
// UDP/5355 to multicast 224.0.0.252 (IPv4) or FF02::1:3 (IPv6
// link-local).
//
// LLMNR exists in the Windows lookup chain as the **second
// fallback** when DNS fails to resolve a short, unqualified
// name (Windows tries DNS, then LLMNR, then — on older
// configurations — NBNS). Operationally, LLMNR is interesting
// for the same reason NBNS is: it is the **canonical target of
// Responder.py poisoning** alongside NBNS. When a Windows host
// types `\\fileserv1` and the corporate DNS doesn't know the
// name, the host broadcasts an LLMNR QUERY to the local subnet;
// an attacker running Responder.py replies with their own IP
// and captures the inbound NTLMv2 challenge/response for
// offline cracking with hashcat mode 5600.
//
// Wrap-vs-native judgement
//
//	Native. RFC 4795 is publicly available; the wire format is
//	a tight 12-byte DNS-style header followed by question /
//	answer records that re-use the RFC 1035 label encoding —
//	with the critical LLMNR-specific constraint that the
//	protocol explicitly forbids compression pointers
//	(RFC 4795 §2.1.7). The Flags field re-purposes a few DNS
//	bits — bit 10 is `C` (Conflict, set in a response to
//	indicate the name is in use) and bit 8 is `T` (Tentative,
//	set during name-registration before the name is
//	defended). Opcode is always 0 (LLMNR_QUERY). No crypto at
//	the parse layer.
//
// What this package covers
//
//   - **DNS-style header** (RFC 4795 §2.1.1, 12 bytes, big-
//     endian): TransactionID + Flags + QD/AN/NS/AR counts.
//
//   - **Flags field** (16 bits BE) with LLMNR-specific
//     interpretation: bit 15 `QR` (0 = query, 1 = response);
//     bits 11-14 `Opcode` (always 0 = LLMNR_QUERY); bit 10 `C`
//     (Conflict — set in a response to indicate the queried
//     name is in active use by multiple hosts; canonical
//     LLMNR-poisoning detection signal); bit 9 `TC`
//     (Truncated); bit 8 `T` (Tentative — set during name
//     registration before the name has been successfully
//     defended on the link); bits 7-4 Reserved; bits 0-3
//     `RCODE` (per RFC 1035).
//
//   - **DNS label-encoded name walker** (RFC 4795 §2.1.7):
//     standard RFC 1035 length-prefixed labels terminated by
//     a 0x00 root label. **LLMNR explicitly forbids
//     compression pointers**, so the walker rejects any
//     length byte with the high bits 11 (0xC0+) as
//     malformed. Labels are joined with dots; the trailing
//     root produces no extra dot.
//
//   - **Question record**: encoded name + 2-byte Type + 2-byte
//     Class.
//
//   - **Answer record**: encoded name + Type + Class + 4-byte
//     TTL + 2-byte RDLength + RDLength bytes of RDATA.
//
//   - **6-entry resource-record Type name table**: 1 `A`
//     (IPv4 host address) / 5 `CNAME` (Canonical Name) / 12
//     `PTR` (Pointer — reverse lookup) / 15 `MX` (Mail
//     Exchange) / 16 `TXT` (Text) / 28 `AAAA` (IPv6 host
//     address).
//
//   - **Per-RR-type RDATA decoders**:
//
//   - `A` (Type 1) → 4-byte IPv4 address.
//
//   - `AAAA` (Type 28) → 16-byte IPv6 address.
//
//   - `PTR` (Type 12) / `CNAME` (Type 5) → DNS-encoded
//     name (label walker; no compression pointers).
//
//   - Other types → RDATA bytes surfaced as raw hex.
//
//   - **RCODE name table** (RFC 1035 §4.1.1): 0 `No_Error` / 1
//     `Format_Error` / 2 `Server_Failure` / 3 `Name_Error` (the
//     standard "no such name" response) / 4 `Not_Implemented`
//     / 5 `Refused`.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed LLMNR bytes after the UDP-
//     datagram header strip (default UDP port 5355).
//   - **NBNS / mDNS** — the parallel Windows / Bonjour name-
//     resolution protocols on UDP/137 and UDP/5353; the
//     `nbns_decode` Spec handles NBNS and a future
//     `mdns_decode` Spec will handle mDNS.
//   - **Generic DNS** — UDP/53 traffic uses the same RFC 1035
//     wire format but supports compression pointers + the full
//     RR-type registry; the existing `dns_packet_decode` Spec
//     covers it.
//   - **Per-RR-type decoders beyond A / AAAA / PTR / CNAME**
//     — TXT key-value parsing, SRV target+port extraction, MX
//     preference + exchange decoding are out of scope (LLMNR
//     deployments overwhelmingly carry A + AAAA queries).
//   - **Multi-fragment reassembly** — LLMNR over UDP fragments
//     when the response exceeds the UDP MTU; the per-message
//     `TC` flag is surfaced but reassembly is out of scope.
//   - **Name-conflict resolution state-machine** — the
//     defend-name / tentative / conflict / abandoned state
//     transitions per RFC 4795 §4.4 are higher-level analysis.
package llmnr

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the structured decode of an LLMNR message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Header
	TransactionID uint16 `json:"transaction_id"`
	FlagsHex      string `json:"flags_hex"`
	QR            bool   `json:"qr_response"`
	Opcode        int    `json:"opcode"`
	OpcodeName    string `json:"opcode_name"`
	Conflict      bool   `json:"c_conflict,omitempty"`
	TC            bool   `json:"tc_truncated,omitempty"`
	Tentative     bool   `json:"t_tentative,omitempty"`
	RCODE         int    `json:"rcode"`
	RCODEName     string `json:"rcode_name"`

	QDCount int `json:"qd_count"`
	ANCount int `json:"an_count"`
	NSCount int `json:"ns_count"`
	ARCount int `json:"ar_count"`

	Questions []Question `json:"questions,omitempty"`
	Answers   []Answer   `json:"answers,omitempty"`
}

// Question is one entry in the LLMNR question section.
type Question struct {
	Name     string `json:"name"`
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Class    int    `json:"class"`
}

// Answer is one entry in the answer / authority / additional
// section.
type Answer struct {
	Name     string `json:"name"`
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Class    int    `json:"class"`
	TTL      uint32 `json:"ttl"`
	RDLength int    `json:"rd_length"`

	// Per-type decoded RDATA (only one set populated).
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	NameData string `json:"name_data,omitempty"`
	RDataHex string `json:"rdata_hex,omitempty"`
}

// Decode parses an LLMNR message from a hex string. Separators
// (':' '-' '_' whitespace) tolerated; '0x' prefix tolerated.
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
	if len(b) < 12 {
		return nil, fmt.Errorf("LLMNR message truncated (%d bytes; need ≥12 for header)",
			len(b))
	}

	r := &Result{
		TotalBytes:    len(b),
		TransactionID: binary.BigEndian.Uint16(b[0:2]),
		FlagsHex:      fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[2:4])),
		QDCount:       int(binary.BigEndian.Uint16(b[4:6])),
		ANCount:       int(binary.BigEndian.Uint16(b[6:8])),
		NSCount:       int(binary.BigEndian.Uint16(b[8:10])),
		ARCount:       int(binary.BigEndian.Uint16(b[10:12])),
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	r.QR = flags&0x8000 != 0
	r.Opcode = int((flags >> 11) & 0x0F)
	r.OpcodeName = opcodeName(r.Opcode)
	r.Conflict = flags&0x0400 != 0
	r.TC = flags&0x0200 != 0
	r.Tentative = flags&0x0100 != 0
	r.RCODE = int(flags & 0x000F)
	r.RCODEName = rcodeName(r.RCODE)

	off := 12
	for i := 0; i < r.QDCount; i++ {
		q, n, err := decodeQuestion(b, off)
		if err != nil {
			return r, err
		}
		r.Questions = append(r.Questions, q)
		off = n
	}
	for i := 0; i < r.ANCount+r.NSCount+r.ARCount; i++ {
		a, n, err := decodeAnswer(b, off)
		if err != nil {
			return r, err
		}
		r.Answers = append(r.Answers, a)
		off = n
	}
	return r, nil
}

func decodeQuestion(b []byte, off int) (Question, int, error) {
	name, next, err := readName(b, off)
	if err != nil {
		return Question{}, 0, err
	}
	if next+4 > len(b) {
		return Question{}, 0, fmt.Errorf("question Type/Class truncated")
	}
	q := Question{
		Name:  name,
		Type:  int(binary.BigEndian.Uint16(b[next : next+2])),
		Class: int(binary.BigEndian.Uint16(b[next+2 : next+4])),
	}
	q.TypeName = typeName(q.Type)
	return q, next + 4, nil
}

func decodeAnswer(b []byte, off int) (Answer, int, error) {
	name, next, err := readName(b, off)
	if err != nil {
		return Answer{}, 0, err
	}
	if next+10 > len(b) {
		return Answer{}, 0, fmt.Errorf("answer fixed fields truncated")
	}
	a := Answer{
		Name:     name,
		Type:     int(binary.BigEndian.Uint16(b[next : next+2])),
		Class:    int(binary.BigEndian.Uint16(b[next+2 : next+4])),
		TTL:      binary.BigEndian.Uint32(b[next+4 : next+8]),
		RDLength: int(binary.BigEndian.Uint16(b[next+8 : next+10])),
	}
	a.TypeName = typeName(a.Type)
	rdStart := next + 10
	rdEnd := rdStart + a.RDLength
	if rdEnd > len(b) {
		return Answer{}, 0, fmt.Errorf("answer RDATA truncated")
	}
	switch a.Type {
	case 1: // A
		if a.RDLength == 4 {
			a.IPv4 = net.IPv4(b[rdStart], b[rdStart+1], b[rdStart+2], b[rdStart+3]).String()
		} else if a.RDLength > 0 {
			a.RDataHex = strings.ToUpper(hex.EncodeToString(b[rdStart:rdEnd]))
		}
	case 28: // AAAA
		if a.RDLength == 16 {
			a.IPv6 = net.IP(b[rdStart:rdEnd]).String()
		} else if a.RDLength > 0 {
			a.RDataHex = strings.ToUpper(hex.EncodeToString(b[rdStart:rdEnd]))
		}
	case 5, 12: // CNAME / PTR
		nm, _, err := readName(b, rdStart)
		if err == nil {
			a.NameData = nm
		} else {
			a.RDataHex = strings.ToUpper(hex.EncodeToString(b[rdStart:rdEnd]))
		}
	default:
		if a.RDLength > 0 {
			a.RDataHex = strings.ToUpper(hex.EncodeToString(b[rdStart:rdEnd]))
		}
	}
	return a, rdEnd, nil
}

// readName walks a DNS-encoded name per RFC 1035 §3.1. LLMNR
// (RFC 4795 §2.1.7) explicitly forbids compression pointers —
// any length byte with the high bits 11 (0xC0+) is treated as
// a parse error.
func readName(b []byte, off int) (string, int, error) {
	if off >= len(b) {
		return "", 0, fmt.Errorf("name read past end")
	}
	var labels []string
	cur := off
	for {
		if cur >= len(b) {
			return "", 0, fmt.Errorf("name not terminated")
		}
		l := int(b[cur])
		if l == 0 {
			// Root terminator.
			return strings.Join(labels, "."), cur + 1, nil
		}
		if l&0xC0 != 0 {
			return "", 0, fmt.Errorf("LLMNR forbids compression pointers (RFC 4795 §2.1.7) at offset %d",
				cur)
		}
		if cur+1+l > len(b) {
			return "", 0, fmt.Errorf("label truncated")
		}
		labels = append(labels, string(b[cur+1:cur+1+l]))
		cur += 1 + l
	}
}

func opcodeName(o int) string {
	if o == 0 {
		return "LLMNR_QUERY"
	}
	return fmt.Sprintf("uncatalogued opcode %d", o)
}

func rcodeName(c int) string {
	switch c {
	case 0:
		return "No_Error"
	case 1:
		return "Format_Error"
	case 2:
		return "Server_Failure"
	case 3:
		return "Name_Error"
	case 4:
		return "Not_Implemented"
	case 5:
		return "Refused"
	}
	return fmt.Sprintf("uncatalogued rcode %d", c)
}

func typeName(t int) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	}
	return fmt.Sprintf("uncatalogued type %d", t)
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
