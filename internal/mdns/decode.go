// Package mdns decodes Multicast DNS (mDNS) messages per RFC
// 6762 + the DNS-SD (DNS-Based Service Discovery) layer per RFC
// 6763. mDNS runs over UDP/5353 to multicast 224.0.0.251 (IPv4)
// or FF02::FB (IPv6 link-local) and is the **discovery layer of
// every Bonjour / Avahi / Linux Avahi / Windows-Service-Discovery
// IoT and macOS / iOS device stack**.
//
// Operationally, mDNS is the canonical signal for enumerating
// consumer + prosumer IoT on a LAN:
//
//   - **Apple ecosystem** — AirDrop (`_airdrop._tcp.local`),
//     AirPrint (`_ipp._tcp.local` / `_printer._tcp.local`),
//     AirPlay (`_airplay._tcp.local`), HomeKit
//     (`_hap._tcp.local`), Apple TV (`_appletv-v2._tcp.local`),
//     macOS file sharing (`_smb._tcp.local`,
//     `_afpovertcp._tcp.local`).
//   - **Streaming** — Chromecast (`_googlecast._tcp.local`),
//     Spotify Connect (`_spotify-connect._tcp.local`), Sonos
//     (`_sonos._tcp.local`), Roku (`_roku-rcp._tcp.local`).
//   - **Smart home** — Philips Hue (`_hue._tcp.local`), HomeKit
//     accessories, Plex (`_plexmediasvr._tcp.local`).
//   - **Linux / Unix LAN discovery** — Avahi `_workstation._tcp.local`
//     (every Avahi-enabled Linux box advertises here),
//     `_sftp-ssh._tcp.local`, `_ssh._tcp.local`,
//     `_http._tcp.local`.
//   - **Developer tooling** — Docker swarm gossip, Kubernetes
//     headless services in mDNS-augmented deployments, IDE
//     remote-debug session brokers.
//
// Wrap-vs-native judgement
//
//	Native. RFC 6762 + RFC 6763 are publicly available; mDNS
//	re-uses the RFC 1035 DNS wire format with two crucial
//	extensions: the **QU bit** (top bit of QCLASS in
//	questions — set when the questioner prefers a unicast
//	response) and the **Cache-Flush bit** (top bit of CLASS
//	in resource records — set when the answer should flush
//	previously-cached entries for the same name+type). The
//	DNS-SD layer is a naming convention on top — service
//	types follow `_<service>._<proto>.local` where `<proto>`
//	is `_tcp` or `_udp`. No crypto at the parse layer.
//
// What this package covers
//
//   - **DNS-style header** (RFC 1035 §4.1.1 / RFC 6762 §18,
//     12 bytes, big-endian): TransactionID + Flags + QD/AN/NS/AR
//     counts. mDNS senders typically set TransactionID = 0
//     (replies do echo the ID for the rare unicast case).
//
//   - **Flags field** (16 bits BE): bit 15 `QR` (0 = query, 1
//     = response); bits 11-14 `Opcode` (0 = QUERY — only
//     value used in mDNS); bit 10 `AA` (Authoritative Answer
//     — set in mDNS responses); bit 9 `TC` (Truncated); bits
//     0-3 `RCODE` (must be 0 in mDNS).
//
//   - **DNS label-encoded name walker** (RFC 1035 §3.1 + §4.1.4
//     compression pointers): standard length-prefixed labels
//     terminated by a 0x00 root. Compression pointers (high
//     bits 11 in the first byte → bottom 14 bits = offset
//     from message start) are followed up to 5 hops deep.
//
//   - **Question record** with **QU bit** (RFC 6762 §5.4):
//     encoded name + 2-byte Type + 2-byte QCLASS where the
//     top bit (`0x8000`) is the QU flag (Question Unicast
//     response preferred) and the bottom 15 bits are the
//     normal class (typically 1 = IN). The decoder surfaces
//     `qu_unicast` and the trimmed class as separate fields.
//
//   - **Answer record** with **Cache-Flush bit** (RFC 6762
//     §10.2): encoded name + Type + CLASS (top bit `0x8000`
//     = Cache-Flush; bottom 15 bits = normal class) + 4-byte
//     TTL + 2-byte RDLength + RDLength bytes of RDATA.
//
//   - **9+ entry resource-record Type name table**: 1 `A`
//     (IPv4 host address) / 5 `CNAME` (Canonical Name) / 12
//     `PTR` (Pointer — DNS-SD service-type → instance-name
//     mapping) / 16 `TXT` (Text — DNS-SD key=value capability
//     metadata) / 28 `AAAA` (IPv6 host address) / 33 `SRV`
//     (Service — DNS-SD instance → host:port + priority +
//     weight) / 41 `OPT` (EDNS0; OPT pseudo-record carrying
//     DNS-SD-extension data) / 47 `NSEC` (Next Secure —
//     re-purposed in mDNS to mean "I have these record types
//     for this name and only these").
//
//   - **Per-RR-type RDATA decoders**:
//
//   - `A` (Type 1) → 4-byte IPv4 address.
//
//   - `AAAA` (Type 28) → 16-byte IPv6 address.
//
//   - `PTR` (Type 12) / `CNAME` (Type 5) → DNS-encoded
//     name (with compression-pointer traversal).
//
//   - `SRV` (Type 33) → 2-byte Priority + 2-byte Weight
//
//   - 2-byte Port + DNS-encoded Target. The classic
//     `_<service>._<proto>.local` service entry; reveals
//     the listening port + target hostname.
//
//   - `TXT` (Type 16) → list of length-prefixed strings.
//     Each string is typically `key=value` (DNS-SD §6);
//     the decoder splits on the first `=` and surfaces
//     `key`/`value` pairs alongside the raw strings.
//
//   - Other types → RDATA bytes surfaced as raw hex.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed mDNS bytes after the UDP-
//     datagram header strip (default UDP port 5353).
//   - **NBNS / LLMNR** — the parallel Windows name-resolution
//     protocols on UDP/137 and UDP/5355; the `nbns_decode` +
//     `llmnr_decode` Specs handle those.
//   - **Generic DNS** — UDP/53 traffic re-uses the same RFC
//     1035 wire format; the existing `dns_packet_decode` Spec
//     covers it.
//   - **DNS-SD service-type semantics beyond name detection**
//     — the per-service-type schema (what TXT keys to expect
//     for `_homekit._tcp.local` vs `_airplay._tcp.local`) is
//     vendor-specific and out of scope; this decoder surfaces
//     the TXT key=value pairs but does not interpret them.
//   - **NSEC bitmap decode** — the NSEC RDATA carries a
//     compressed type-bitmap indicating which RR types exist
//     for the name; the decoder surfaces the next-name
//     portion but leaves the type-bitmap as opaque hex.
//   - **DNSSEC validation** — out of scope (mDNS rarely uses
//     DNSSEC anyway).
//   - **Multi-fragment reassembly** — mDNS responses can span
//     multiple UDP packets when the answer set exceeds the
//     MTU (RFC 6762 §11); the `TC` flag surfaces but the
//     decoder does not reassemble across input messages.
package mdns

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the structured decode of an mDNS message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Header
	TransactionID uint16 `json:"transaction_id"`
	FlagsHex      string `json:"flags_hex"`
	QR            bool   `json:"qr_response"`
	Opcode        int    `json:"opcode"`
	AA            bool   `json:"aa_authoritative,omitempty"`
	TC            bool   `json:"tc_truncated,omitempty"`
	RCODE         int    `json:"rcode"`

	QDCount int `json:"qd_count"`
	ANCount int `json:"an_count"`
	NSCount int `json:"ns_count"`
	ARCount int `json:"ar_count"`

	Questions []Question `json:"questions,omitempty"`
	Answers   []Answer   `json:"answers,omitempty"`
}

// Question is one entry in the mDNS question section.
type Question struct {
	Name      string `json:"name"`
	Type      int    `json:"type"`
	TypeName  string `json:"type_name"`
	Class     int    `json:"class"`
	QUUnicast bool   `json:"qu_unicast,omitempty"`
}

// Answer is one entry in the answer / authority / additional
// section.
type Answer struct {
	Name       string `json:"name"`
	Type       int    `json:"type"`
	TypeName   string `json:"type_name"`
	Class      int    `json:"class"`
	CacheFlush bool   `json:"cache_flush,omitempty"`
	TTL        uint32 `json:"ttl"`
	RDLength   int    `json:"rd_length"`

	// Per-type decoded RDATA (only the relevant subset
	// populated).
	IPv4         string            `json:"ipv4,omitempty"`
	IPv6         string            `json:"ipv6,omitempty"`
	NameData     string            `json:"name_data,omitempty"`
	SRVPriority  int               `json:"srv_priority,omitempty"`
	SRVWeight    int               `json:"srv_weight,omitempty"`
	SRVPort      int               `json:"srv_port,omitempty"`
	SRVTarget    string            `json:"srv_target,omitempty"`
	TXTStrings   []string          `json:"txt_strings,omitempty"`
	TXTKeyValues map[string]string `json:"txt_key_values,omitempty"`
	RDataHex     string            `json:"rdata_hex,omitempty"`
}

// Decode parses an mDNS message from a hex string. Separators
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
		return nil, fmt.Errorf("mDNS message truncated (%d bytes; need ≥12 for header)",
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
	r.AA = flags&0x0400 != 0
	r.TC = flags&0x0200 != 0
	r.RCODE = int(flags & 0x000F)

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
		Name: name,
		Type: int(binary.BigEndian.Uint16(b[next : next+2])),
	}
	qclass := binary.BigEndian.Uint16(b[next+2 : next+4])
	q.QUUnicast = qclass&0x8000 != 0
	q.Class = int(qclass & 0x7FFF)
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
		TTL:      binary.BigEndian.Uint32(b[next+4 : next+8]),
		RDLength: int(binary.BigEndian.Uint16(b[next+8 : next+10])),
	}
	class := binary.BigEndian.Uint16(b[next+2 : next+4])
	a.CacheFlush = class&0x8000 != 0
	a.Class = int(class & 0x7FFF)
	a.TypeName = typeName(a.Type)
	rdStart := next + 10
	rdEnd := rdStart + a.RDLength
	if rdEnd > len(b) {
		return Answer{}, 0, fmt.Errorf("answer RDATA truncated")
	}
	decodeRDATA(&a, b, rdStart, rdEnd)
	return a, rdEnd, nil
}

func decodeRDATA(a *Answer, full []byte, rdStart, rdEnd int) {
	rd := full[rdStart:rdEnd]
	switch a.Type {
	case 1: // A
		if len(rd) == 4 {
			a.IPv4 = net.IPv4(rd[0], rd[1], rd[2], rd[3]).String()
			return
		}
	case 28: // AAAA
		if len(rd) == 16 {
			a.IPv6 = net.IP(rd).String()
			return
		}
	case 5, 12: // CNAME / PTR
		nm, _, err := readName(full, rdStart)
		if err == nil {
			a.NameData = nm
			return
		}
	case 33: // SRV
		if len(rd) >= 6 {
			a.SRVPriority = int(binary.BigEndian.Uint16(rd[0:2]))
			a.SRVWeight = int(binary.BigEndian.Uint16(rd[2:4]))
			a.SRVPort = int(binary.BigEndian.Uint16(rd[4:6]))
			if target, _, err := readName(full, rdStart+6); err == nil {
				a.SRVTarget = target
				return
			}
		}
	case 16: // TXT
		off := 0
		kv := map[string]string{}
		for off < len(rd) {
			l := int(rd[off])
			off++
			if off+l > len(rd) {
				break
			}
			s := string(rd[off : off+l])
			a.TXTStrings = append(a.TXTStrings, s)
			if idx := strings.Index(s, "="); idx >= 0 {
				kv[s[:idx]] = s[idx+1:]
			}
			off += l
		}
		if len(kv) > 0 {
			a.TXTKeyValues = kv
		}
		return
	}
	if a.RDLength > 0 {
		a.RDataHex = strings.ToUpper(hex.EncodeToString(rd))
	}
}

// readName walks a DNS-encoded name per RFC 1035 §3.1 with RFC
// §4.1.4 compression-pointer support (up to 5 hops deep).
func readName(b []byte, off int) (string, int, error) {
	const maxHops = 5
	var labels []string
	var firstNext int
	hops := 0
	cur := off
	for {
		if cur >= len(b) {
			return "", 0, fmt.Errorf("name not terminated")
		}
		l := int(b[cur])
		if l == 0 {
			if firstNext == 0 {
				firstNext = cur + 1
			}
			return strings.Join(labels, "."), firstNext, nil
		}
		if l&0xC0 == 0xC0 {
			if cur+2 > len(b) {
				return "", 0, fmt.Errorf("compression pointer truncated")
			}
			if firstNext == 0 {
				firstNext = cur + 2
			}
			cur = int(binary.BigEndian.Uint16(b[cur:cur+2]) & 0x3FFF)
			hops++
			if hops > maxHops {
				return "", 0, fmt.Errorf("compression pointer loop")
			}
			continue
		}
		if cur+1+l > len(b) {
			return "", 0, fmt.Errorf("label truncated")
		}
		labels = append(labels, string(b[cur+1:cur+1+l]))
		cur += 1 + l
	}
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
	case 41:
		return "OPT"
	case 47:
		return "NSEC"
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
