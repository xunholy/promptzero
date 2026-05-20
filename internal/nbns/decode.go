// Package nbns decodes NBNS (NetBIOS Name Service) messages per
// RFC 1001 (NetBIOS service concepts) and RFC 1002 (NetBIOS over
// TCP/UDP encoding). NBNS is the legacy Windows name-resolution
// protocol that runs over UDP/137 and predates DNS in the
// Microsoft ecosystem.
//
// Operationally, NBNS is interesting because:
//
//   - **Responder.py poisoning** — NBNS is the canonical target
//     of NBNS-poisoning attacks (alongside LLMNR). When a
//     Windows host looks up an unqualified short name (e.g.
//     someone fat-fingers `\\fileserv1` and types
//     `\\filsserv1`), it tries DNS first, then broadcasts a
//     UDP/137 NBNS QUERY to the local subnet. An attacker
//     running Responder.py replies with their own IP and
//     captures the inbound NTLMv2 challenge/response for
//     offline cracking.
//   - **AD environment fingerprinting** — observing NBNS
//     QUERY traffic on a corporate subnet reveals every short
//     hostname users are typing, every file-server they're
//     trying to reach, and every printer they're searching
//     for. Multiple QUERY-RESPONSE pairs leak the entire
//     NetBIOS namespace.
//   - **Domain enumeration** — NBNS REGISTRATION / REFRESH
//     traffic from domain controllers (suffix 0x1C) leaks the
//     domain name + every DC's NetBIOS name + every workgroup
//     in the broadcast domain.
//
// Wrap-vs-native judgement
//
//	Native. RFC 1002 is publicly available; the wire format is
//	a tight 12-byte DNS-style header followed by question /
//	answer records that use the same RFC 1035 encoding shape
//	BUT with a NetBIOS-specific name encoding (each 1-byte
//	character is split into two nibbles, each offset by 0x41
//	'A' to be DNS-label-legal — making a 16-byte NetBIOS name
//	encode to a 32-byte DNS label). The decoder de-encodes the
//	NetBIOS name back to the original 15-byte name + 1-byte
//	suffix-byte and maps the suffix against the documented
//	name-service suffix table. No crypto at the parse layer.
//
// What this package covers
//
//   - **DNS-style header** (RFC 1002 §4.2, 12 bytes, big-endian):
//     Transaction ID + Flags + QDCount + ANCount + NSCount +
//     ARCount.
//
//   - **Flags field** (16 bits BE): bit 15 `QR` (0 = query, 1 =
//     response); bits 11-14 `Opcode`; bit 10 `AA` (Authoritative
//     Answer); bit 9 `TC` (Truncated); bit 8 `RD` (Recursion
//     Desired); bit 7 `RA` (Recursion Available); bit 6 reserved;
//     bit 5 `B` (Broadcast); bit 4 reserved; bits 0-3 `RCODE`.
//
//   - **5-entry Opcode name table** (RFC 1002 §4.2.1.1): 0
//     `QUERY` / 5 `REGISTRATION` / 6 `RELEASE` / 7 `WACK`
//     (Wait for Acknowledgement — sent by NBNS server when it
//     needs more time to resolve a name) / 8 `REFRESH`.
//
//   - **8-entry RCODE name table** (RFC 1002 §4.2.6): 0
//     `No_Error` / 1 `Format_Error` / 2 `Server_Failure` / 3
//     `Name_Error` (name not found) / 4 `Not_Implemented` / 5
//     `Refused_Error` (administratively refused) / 6
//     `Active_Error` (name already in use; the canonical
//     NetBIOS name-conflict response) / 7 `Conflict_Error`.
//
//   - **NetBIOS name decoder** (RFC 1002 §4.2.1.2): a NetBIOS
//     name is 15 bytes of name (right-padded with spaces) + 1
//     byte of name-service suffix; encoded by splitting each
//     name byte into two nibbles, each offset by 0x41 ('A'), to
//     produce a 32-byte sequence of letters A-P. On-wire the
//     32-byte sequence is preceded by a length byte (always
//     0x20 = 32) and followed by a 0x00 terminator (or a
//     compression-pointer continuation per RFC 1035 §4.1.4 —
//     starts with bits 11 in the first byte). The decoder
//     surfaces the trimmed 15-byte name + suffix byte +
//     suffix-byte name from the canonical table.
//
//   - **20+ entry NetBIOS suffix name table** (Microsoft KB
//     163409 + Samba documentation): 0x00 `Workstation` / 0x01
//     `Master_Browser` / 0x03 `Messenger` / 0x06 `RAS_Server` /
//     0x1B `Domain_Master_Browser` (the PDC emulator FSMO
//     role) / 0x1C `Domain_Controllers` (every DC registers
//     this for the domain name; canonical AD-enumeration
//     fingerprint) / 0x1D `Master_Browser` (browse master per
//     subnet) / 0x1E `Browser_Election` / 0x1F `NetDDE` / 0x20
//     `File_Server` / 0x21 `RAS_Client` / 0x22
//     `MS_Exchange_Interchange` / 0x23
//     `MS_Exchange_Store` / 0x24 `MS_Exchange_Directory` /
//     0x2B `Lotus_Notes` / 0x30 `Modem_Sharing_Server` / 0x31
//     `Modem_Sharing_Client` / 0x43 `SMS_Client_Remote_Control`
//     / 0x44 `SMS_Admin_Remote_Control` / 0x45
//     `SMS_Client_Remote_Chat` / 0x46 `SMS_Client_Remote_Xfer`
//     / 0x87 `MS_Exchange_MTA` / 0x6A
//     `MS_Exchange_IMC` / 0xBE `Network_Monitor_Agent` / 0xBF
//     `Network_Monitor_Application`.
//
//   - **Question record** (per RFC 1002 §4.2.1.3): encoded
//     NetBIOS name + 2-byte Type + 2-byte Class. Type 0x0020
//     (`NB`) is the common case; 0x0021 (`NBSTAT`) requests
//     a NetBIOS adapter status table. Class 0x0001 (`IN`) is
//     near-universal.
//
//   - **NB resource record body** (per RFC 1002 §4.2.13): when
//     the answer is type `NB` (0x0020), the RDATA carries one
//     or more (2-byte Flags + 4-byte IPv4 address) tuples. The
//     decoder surfaces every IP claimed by the responding
//     node.
//
//   - **Compression pointer traversal** — NBNS answers
//     frequently re-use the question's name via the RFC 1035
//     §4.1.4 compression pointer (bits 11 in the first name
//     byte → bottom 14 bits = offset from message start). The
//     decoder follows pointers up to 5 hops deep to surface
//     the resolved name.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed NBNS bytes after the UDP-
//     datagram header strip (default UDP port 137 for NBNS;
//     UDP port 138 for the related NetBIOS Datagram Service —
//     a separate decoder).
//   - **NetBIOS Datagram Service (NBDS, UDP/138)** — used for
//     SMB browser elections + workgroup announcements;
//     different wire format.
//   - **NetBIOS Session Service (NBSS, TCP/139)** — the TCP
//     framing layer underneath classic SMB1 file-share
//     traffic; separate decoder.
//   - **NBSTAT response decoder** — Type 0x0021 NBSTAT answers
//     carry a NetBIOS-name table + per-name flags + a 6-byte
//     unit ID (MAC address); the per-name walker is dataset-
//     specific and surfaced as opaque `rdata_hex` for future
//     per-record decoders.
//   - **WINS replication** — NBNS-over-WINS adds replication
//     PDUs to the base spec; higher-level analysis.
package nbns

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the structured decode of an NBNS message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Header
	TransactionID uint16 `json:"transaction_id"`
	FlagsHex      string `json:"flags_hex"`
	QR            bool   `json:"qr_response"`
	Opcode        int    `json:"opcode"`
	OpcodeName    string `json:"opcode_name"`
	AA            bool   `json:"aa_authoritative,omitempty"`
	TC            bool   `json:"tc_truncated,omitempty"`
	RD            bool   `json:"rd_recursion_desired,omitempty"`
	RA            bool   `json:"ra_recursion_available,omitempty"`
	Broadcast     bool   `json:"b_broadcast,omitempty"`
	RCODE         int    `json:"rcode"`
	RCODEName     string `json:"rcode_name"`

	QDCount int `json:"qd_count"`
	ANCount int `json:"an_count"`
	NSCount int `json:"ns_count"`
	ARCount int `json:"ar_count"`

	Questions []Question `json:"questions,omitempty"`
	Answers   []Answer   `json:"answers,omitempty"`
}

// Question is one entry in the NBNS question section.
type Question struct {
	Name       string `json:"name"`
	Suffix     int    `json:"suffix"`
	SuffixName string `json:"suffix_name"`
	Type       int    `json:"type"`
	TypeName   string `json:"type_name"`
	Class      int    `json:"class"`
}

// Answer is one entry in the answer / authority / additional
// section.
type Answer struct {
	Name        string   `json:"name"`
	Suffix      int      `json:"suffix"`
	SuffixName  string   `json:"suffix_name"`
	Type        int      `json:"type"`
	TypeName    string   `json:"type_name"`
	Class       int      `json:"class"`
	TTL         uint32   `json:"ttl"`
	RDLength    int      `json:"rd_length"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
	RDataHex    string   `json:"rdata_hex,omitempty"`
}

// Decode parses an NBNS message from a hex string. Separators
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
		return nil, fmt.Errorf("NBNS message truncated (%d bytes; need ≥12 for header)",
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
	r.AA = flags&0x0400 != 0
	r.TC = flags&0x0200 != 0
	r.RD = flags&0x0100 != 0
	r.RA = flags&0x0080 != 0
	r.Broadcast = flags&0x0010 != 0
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
	name, suffix, next, err := readNetBIOSName(b, off)
	if err != nil {
		return Question{}, 0, err
	}
	if next+4 > len(b) {
		return Question{}, 0, fmt.Errorf("question Type/Class truncated")
	}
	q := Question{
		Name:       name,
		Suffix:     suffix,
		SuffixName: suffixName(suffix),
		Type:       int(binary.BigEndian.Uint16(b[next : next+2])),
		Class:      int(binary.BigEndian.Uint16(b[next+2 : next+4])),
	}
	q.TypeName = typeName(q.Type)
	return q, next + 4, nil
}

func decodeAnswer(b []byte, off int) (Answer, int, error) {
	name, suffix, next, err := readNetBIOSName(b, off)
	if err != nil {
		return Answer{}, 0, err
	}
	if next+10 > len(b) {
		return Answer{}, 0, fmt.Errorf("answer fixed fields truncated")
	}
	a := Answer{
		Name:       name,
		Suffix:     suffix,
		SuffixName: suffixName(suffix),
		Type:       int(binary.BigEndian.Uint16(b[next : next+2])),
		Class:      int(binary.BigEndian.Uint16(b[next+2 : next+4])),
		TTL:        binary.BigEndian.Uint32(b[next+4 : next+8]),
		RDLength:   int(binary.BigEndian.Uint16(b[next+8 : next+10])),
	}
	a.TypeName = typeName(a.Type)
	rdStart := next + 10
	rdEnd := rdStart + a.RDLength
	if rdEnd > len(b) {
		return Answer{}, 0, fmt.Errorf("answer RDATA truncated")
	}
	if a.Type == 0x0020 {
		// NB type — sequence of (Flags 2 + IPv4 4) tuples.
		for p := rdStart; p+6 <= rdEnd; p += 6 {
			ip := net.IPv4(b[p+2], b[p+3], b[p+4], b[p+5]).String()
			a.IPAddresses = append(a.IPAddresses, ip)
		}
	} else if a.RDLength > 0 {
		a.RDataHex = strings.ToUpper(hex.EncodeToString(b[rdStart:rdEnd]))
	}
	return a, rdEnd, nil
}

// readNetBIOSName decodes an RFC 1002 §4.2.1.2 encoded NetBIOS
// name starting at offset `off`. Returns the trimmed 15-byte
// name, the 1-byte suffix, and the post-name offset. Handles
// RFC 1035 §4.1.4 compression pointers up to 5 hops deep.
func readNetBIOSName(b []byte, off int) (string, int, int, error) {
	const maxHops = 5
	var firstNext int
	hops := 0
	cur := off
	for {
		if cur >= len(b) {
			return "", 0, 0, fmt.Errorf("name read past end")
		}
		ll := int(b[cur])
		if ll&0xC0 == 0xC0 {
			// Compression pointer — bottom 14 bits.
			if cur+2 > len(b) {
				return "", 0, 0, fmt.Errorf("compression pointer truncated")
			}
			if firstNext == 0 {
				firstNext = cur + 2
			}
			cur = int(binary.BigEndian.Uint16(b[cur:cur+2]) & 0x3FFF)
			hops++
			if hops > maxHops {
				return "", 0, 0, fmt.Errorf("compression pointer loop")
			}
			continue
		}
		if ll != 0x20 {
			return "", 0, 0, fmt.Errorf("unexpected NetBIOS name length %d (want 32)", ll)
		}
		if cur+1+32+1 > len(b) {
			return "", 0, 0, fmt.Errorf("encoded NetBIOS name truncated")
		}
		raw := b[cur+1 : cur+1+32]
		decoded := make([]byte, 16)
		for i := 0; i < 16; i++ {
			hi := raw[i*2] - 0x41
			lo := raw[i*2+1] - 0x41
			if hi > 15 || lo > 15 {
				return "", 0, 0, fmt.Errorf("invalid NetBIOS nibble at offset %d", i*2)
			}
			decoded[i] = (hi << 4) | lo
		}
		name := strings.TrimRight(string(decoded[:15]), " \x00")
		suffix := int(decoded[15])
		next := cur + 1 + 32 + 1 // include 0x00 terminator
		if firstNext != 0 {
			next = firstNext
		}
		return name, suffix, next, nil
	}
}

func opcodeName(o int) string {
	switch o {
	case 0:
		return "QUERY"
	case 5:
		return "REGISTRATION"
	case 6:
		return "RELEASE"
	case 7:
		return "WACK"
	case 8:
		return "REFRESH"
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
		return "Refused_Error"
	case 6:
		return "Active_Error"
	case 7:
		return "Conflict_Error"
	}
	return fmt.Sprintf("uncatalogued rcode %d", c)
}

func typeName(t int) string {
	switch t {
	case 0x0001:
		return "A (host address; legacy)"
	case 0x0002:
		return "NS"
	case 0x000A:
		return "NULL"
	case 0x0020:
		return "NB"
	case 0x0021:
		return "NBSTAT"
	}
	return fmt.Sprintf("uncatalogued type 0x%04X", t)
}

func suffixName(s int) string {
	switch s {
	case 0x00:
		return "Workstation"
	case 0x01:
		return "Master_Browser"
	case 0x03:
		return "Messenger"
	case 0x06:
		return "RAS_Server"
	case 0x1B:
		return "Domain_Master_Browser"
	case 0x1C:
		return "Domain_Controllers"
	case 0x1D:
		return "Master_Browser_per_Subnet"
	case 0x1E:
		return "Browser_Election"
	case 0x1F:
		return "NetDDE"
	case 0x20:
		return "File_Server"
	case 0x21:
		return "RAS_Client"
	case 0x22:
		return "MS_Exchange_Interchange"
	case 0x23:
		return "MS_Exchange_Store"
	case 0x24:
		return "MS_Exchange_Directory"
	case 0x2B:
		return "Lotus_Notes"
	case 0x30:
		return "Modem_Sharing_Server"
	case 0x31:
		return "Modem_Sharing_Client"
	case 0x43:
		return "SMS_Client_Remote_Control"
	case 0x44:
		return "SMS_Admin_Remote_Control"
	case 0x45:
		return "SMS_Client_Remote_Chat"
	case 0x46:
		return "SMS_Client_Remote_Xfer"
	case 0x6A:
		return "MS_Exchange_IMC"
	case 0x87:
		return "MS_Exchange_MTA"
	case 0xBE:
		return "Network_Monitor_Agent"
	case 0xBF:
		return "Network_Monitor_Application"
	}
	return fmt.Sprintf("uncatalogued suffix 0x%02X", s)
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
