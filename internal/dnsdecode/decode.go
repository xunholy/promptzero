// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dnsdecode parses DNS messages on the wire — the
// most-traffic-bearing UDP protocol on the internet and a
// staple of every blue-team / red-team / network-debugging
// workflow.
//
// # Wrap-vs-native judgement
//
// Native. DNS is defined by RFC 1035 + a long tail of
// supporting RFCs (1996 NOTIFY, 2136 UPDATE, 2671/6891 EDNS,
// 4034/4035 DNSSEC, 6844 CAA, 6698 TLSA, 9460 SVCB/HTTPS,
// etc.). The wire format is a 12-byte header + four
// length-prefixed section lists, with RR data dispatched on
// a 16-bit type. Name compression uses 14-bit pointers
// (top 2 bits set on the length byte). Pasting a hex blob
// from Wireshark / tshark / a dig +short capture is enough
// — no key material, no cryptography, no live network attach.
//
// # What this package covers
//
//   - DNS header (RFC 1035 §4.1.1): transaction ID, flag
//     fields broken out as QR (query/response), Opcode
//     (QUERY/IQUERY/STATUS/NOTIFY/UPDATE), AA (authoritative
//     answer), TC (truncation), RD (recursion desired), RA
//     (recursion available), AD (authentic data, DNSSEC),
//     CD (checking disabled, DNSSEC), and RCODE (NOERROR /
//     FORMERR / SERVFAIL / NXDOMAIN / NOTIMP / REFUSED /
//     YXDOMAIN / YXRRSET / NXRRSET / NOTAUTH / NOTZONE /
//     plus EDNS extended RCODEs).
//   - Section counts: QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
//   - Question section (RFC 1035 §4.1.2): QNAME with
//     compression pointer resolution, QTYPE, QCLASS.
//   - RR sections with type-specific decode for the common
//     types operators care about:
//   - A (1) — 4-byte IPv4.
//   - NS (2) — owner-domain name.
//   - CNAME (5) — canonical name.
//   - SOA (6) — primary NS, RNAME, serial, refresh,
//     retry, expire, minimum.
//   - PTR (12) — domain name (reverse-DNS).
//   - MX (15) — preference + exchange.
//   - TXT (16) — list of <character-string>s.
//   - AAAA (28) — 16-byte IPv6 in canonical colon form.
//   - SRV (33) — priority + weight + port + target.
//   - OPT (41, EDNS) — UDP-size from class field,
//     extended RCODE + version + DO flag from TTL field,
//     and per-option [code, length, raw data].
//   - DNSKEY (48) — flags + protocol + algorithm + key
//     data hex; key-tag (RFC 4034 Appx B) when computable.
//   - DS (43) — key tag + algorithm + digest type +
//     digest hex.
//   - CAA (257, RFC 6844) — flags + tag + value (plus
//     the well-known tags issue / issuewild / iodef /
//     contactemail / contactphone).
//   - Name decompression with pointer-chain max-depth guard
//     to defeat the classic pointer-loop denial-of-service.
//   - RCODE / Opcode / RR type / RR class lookup tables.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - DNSSEC signature validation (RRSIG / NSEC / NSEC3
//     walk) — RRSIG records are surfaced with type-covered
//     and key-tag fields but the signature blob is exposed
//     as base64; cryptographic validation is a separate
//     iteration that needs a trust-anchor store.
//   - TLSA (52) and SVCB/HTTPS (64/65) — well-defined but
//     usage is still niche; future Spec when real captures
//     surface.
//   - LOC (29), NAPTR (35), URI (256), and the long-tail
//     experimental types — the type code is named but the
//     RDATA is surfaced as raw hex.
//   - DNS-over-HTTPS / DNS-over-TLS / DNS-over-QUIC
//     framing — those wrap the same DNS message on the wire,
//     so callers feed the inner message here.
//   - Multi-message reassembly for TCP (the 2-byte length
//     prefix used by TCP DNS) — operators are expected to
//     strip the prefix before passing the message body.
package dnsdecode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Message is the decoded view of a DNS packet.
type Message struct {
	HexInput      string      `json:"hex_input"`
	TransactionID int         `json:"transaction_id"`
	Flags         *Flags      `json:"flags"`
	QDCount       int         `json:"qdcount"`
	ANCount       int         `json:"ancount"`
	NSCount       int         `json:"nscount"`
	ARCount       int         `json:"arcount"`
	Questions     []*Question `json:"questions,omitempty"`
	Answers       []*Record   `json:"answers,omitempty"`
	Authority     []*Record   `json:"authority,omitempty"`
	Additional    []*Record   `json:"additional,omitempty"`
}

// Flags is the broken-out DNS header flag bits.
type Flags struct {
	QR               int    `json:"qr"`
	QRName           string `json:"qr_name"`
	Opcode           int    `json:"opcode"`
	OpcodeName       string `json:"opcode_name"`
	AuthAnswer       bool   `json:"authoritative_answer"`
	Truncation       bool   `json:"truncation"`
	RecursionDesired bool   `json:"recursion_desired"`
	RecursionAvail   bool   `json:"recursion_available"`
	AuthenticData    bool   `json:"authentic_data"`
	CheckingDisabled bool   `json:"checking_disabled"`
	RCode            int    `json:"rcode"`
	RCodeName        string `json:"rcode_name"`
}

// Question is one entry in the question section.
type Question struct {
	Name      string `json:"name"`
	Type      int    `json:"type"`
	TypeName  string `json:"type_name"`
	Class     int    `json:"class"`
	ClassName string `json:"class_name"`
}

// Record is one resource record. Only the field that matches
// the type is populated; everything else is RDataHex.
type Record struct {
	Name        string `json:"name"`
	Type        int    `json:"type"`
	TypeName    string `json:"type_name"`
	Class       int    `json:"class"`
	ClassName   string `json:"class_name"`
	TTL         uint32 `json:"ttl,omitempty"`
	RDataLength int    `json:"rdata_length"`
	RDataHex    string `json:"rdata_hex,omitempty"`

	// Type-specific decoded fields. Only one of these is
	// populated per record; the others are empty.
	IPv4        string      `json:"ipv4,omitempty"`
	IPv6        string      `json:"ipv6,omitempty"`
	Target      string      `json:"target,omitempty"`
	TextRecords []string    `json:"text_records,omitempty"`
	MX          *MXData     `json:"mx,omitempty"`
	SOA         *SOAData    `json:"soa,omitempty"`
	SRV         *SRVData    `json:"srv,omitempty"`
	OPT         *OPTData    `json:"opt,omitempty"`
	DNSKEY      *DNSKEYData `json:"dnskey,omitempty"`
	DS          *DSData     `json:"ds,omitempty"`
	CAA         *CAAData    `json:"caa,omitempty"`
}

// MXData is the type-15 RDATA: preference + exchange.
type MXData struct {
	Preference int    `json:"preference"`
	Exchange   string `json:"exchange"`
}

// SOAData is the type-6 RDATA: zone authority.
type SOAData struct {
	PrimaryNS       string `json:"primary_ns"`
	ResponsibleName string `json:"responsible_name"`
	Serial          uint32 `json:"serial"`
	RefreshSec      uint32 `json:"refresh_sec"`
	RetrySec        uint32 `json:"retry_sec"`
	ExpireSec       uint32 `json:"expire_sec"`
	MinimumSec      uint32 `json:"minimum_sec"`
}

// SRVData is the type-33 RDATA: service location.
type SRVData struct {
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Port     int    `json:"port"`
	Target   string `json:"target"`
}

// OPTData is the type-41 RDATA: EDNS pseudo-RR. UDP size +
// extended RCODE/version/DO are pulled out of the class +
// TTL fields per RFC 6891.
type OPTData struct {
	UDPSize       int         `json:"udp_size"`
	ExtendedRCode int         `json:"extended_rcode"`
	Version       int         `json:"version"`
	DOFlag        bool        `json:"do_flag"`
	Options       []OPTOption `json:"options,omitempty"`
}

// OPTOption is one EDNS option [code, length, raw hex].
type OPTOption struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Length  int    `json:"length"`
	DataHex string `json:"data_hex,omitempty"`
}

// DNSKEYData is the type-48 RDATA.
type DNSKEYData struct {
	Flags         int    `json:"flags"`
	IsKSK         bool   `json:"is_ksk"`
	IsZSK         bool   `json:"is_zsk"`
	Protocol      int    `json:"protocol"`
	Algorithm     int    `json:"algorithm"`
	AlgorithmName string `json:"algorithm_name"`
	KeyTag        int    `json:"key_tag"`
	PublicKeyHex  string `json:"public_key_hex"`
}

// DSData is the type-43 RDATA.
type DSData struct {
	KeyTag         int    `json:"key_tag"`
	Algorithm      int    `json:"algorithm"`
	AlgorithmName  string `json:"algorithm_name"`
	DigestType     int    `json:"digest_type"`
	DigestTypeName string `json:"digest_type_name"`
	DigestHex      string `json:"digest_hex"`
}

// CAAData is the type-257 RDATA per RFC 6844.
type CAAData struct {
	Flags      int    `json:"flags"`
	IsCritical bool   `json:"is_critical"`
	Tag        string `json:"tag"`
	Value      string `json:"value"`
}

// Decode parses a hex-encoded DNS message.
func Decode(hexBlob string) (*Message, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw DNS message.
func DecodeBytes(b []byte) (*Message, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("dnsdecode: message too short (%d bytes); DNS header is 12 bytes", len(b))
	}
	m := &Message{
		HexInput:      strings.ToUpper(hex.EncodeToString(b)),
		TransactionID: int(binary.BigEndian.Uint16(b[0:2])),
		Flags:         decodeFlags(binary.BigEndian.Uint16(b[2:4])),
		QDCount:       int(binary.BigEndian.Uint16(b[4:6])),
		ANCount:       int(binary.BigEndian.Uint16(b[6:8])),
		NSCount:       int(binary.BigEndian.Uint16(b[8:10])),
		ARCount:       int(binary.BigEndian.Uint16(b[10:12])),
	}
	off := 12
	for i := 0; i < m.QDCount; i++ {
		q, used, err := decodeQuestion(b, off)
		if err != nil {
			return nil, fmt.Errorf("dnsdecode: question %d: %w", i, err)
		}
		m.Questions = append(m.Questions, q)
		off += used
	}
	for i := 0; i < m.ANCount; i++ {
		r, used, err := decodeRecord(b, off)
		if err != nil {
			return nil, fmt.Errorf("dnsdecode: answer %d: %w", i, err)
		}
		m.Answers = append(m.Answers, r)
		off += used
	}
	for i := 0; i < m.NSCount; i++ {
		r, used, err := decodeRecord(b, off)
		if err != nil {
			return nil, fmt.Errorf("dnsdecode: authority %d: %w", i, err)
		}
		m.Authority = append(m.Authority, r)
		off += used
	}
	for i := 0; i < m.ARCount; i++ {
		r, used, err := decodeRecord(b, off)
		if err != nil {
			return nil, fmt.Errorf("dnsdecode: additional %d: %w", i, err)
		}
		m.Additional = append(m.Additional, r)
		off += used
	}
	return m, nil
}

func decodeFlags(raw uint16) *Flags {
	qr := int((raw >> 15) & 0x01)
	opcode := int((raw >> 11) & 0x0F)
	rcode := int(raw & 0x0F)
	qrName := "query"
	if qr == 1 {
		qrName = "response"
	}
	return &Flags{
		QR:               qr,
		QRName:           qrName,
		Opcode:           opcode,
		OpcodeName:       opcodeName(opcode),
		AuthAnswer:       raw&(1<<10) != 0,
		Truncation:       raw&(1<<9) != 0,
		RecursionDesired: raw&(1<<8) != 0,
		RecursionAvail:   raw&(1<<7) != 0,
		AuthenticData:    raw&(1<<5) != 0,
		CheckingDisabled: raw&(1<<4) != 0,
		RCode:            rcode,
		RCodeName:        rcodeName(rcode),
	}
}

func decodeQuestion(b []byte, off int) (*Question, int, error) {
	start := off
	name, n, err := decodeName(b, off, 0)
	if err != nil {
		return nil, 0, err
	}
	off += n
	if off+4 > len(b) {
		return nil, 0, fmt.Errorf("question QTYPE/QCLASS truncated")
	}
	qtype := int(binary.BigEndian.Uint16(b[off : off+2]))
	qclass := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
	off += 4
	return &Question{
		Name:      name,
		Type:      qtype,
		TypeName:  rrTypeName(qtype),
		Class:     qclass,
		ClassName: classNameOrEDNS(qtype, qclass),
	}, off - start, nil
}

func decodeRecord(b []byte, off int) (*Record, int, error) {
	start := off
	name, n, err := decodeName(b, off, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("RR name: %w", err)
	}
	off += n
	if off+10 > len(b) {
		return nil, 0, fmt.Errorf("RR TYPE/CLASS/TTL/RDLENGTH truncated")
	}
	rrType := int(binary.BigEndian.Uint16(b[off : off+2]))
	rrClass := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
	ttl := binary.BigEndian.Uint32(b[off+4 : off+8])
	rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
	off += 10
	if off+rdlen > len(b) {
		return nil, 0, fmt.Errorf("RDATA (length %d) exceeds buffer", rdlen)
	}
	rdata := b[off : off+rdlen]
	r := &Record{
		Name:        name,
		Type:        rrType,
		TypeName:    rrTypeName(rrType),
		Class:       rrClass,
		ClassName:   classNameOrEDNS(rrType, rrClass),
		RDataLength: rdlen,
		RDataHex:    strings.ToUpper(hex.EncodeToString(rdata)),
	}
	// OPT records use TTL for extended RCODE + version + DO
	// flag, and class for UDP size; preserve TTL anyway for
	// non-OPT records.
	if rrType != 41 {
		r.TTL = ttl
	}
	decodeRDATA(r, rdata, b, off, rrType, ttl, rrClass)
	off += rdlen
	return r, off - start, nil
}

// decodeRDATA fills the type-specific RDATA fields. rdataOff
// is the offset of rdata within full — needed for name
// decompression, since DNS name pointers reference absolute
// offsets within the message.
func decodeRDATA(r *Record, rdata, full []byte, rdataOff, rrType int, ttl uint32, rrClass int) {
	switch rrType {
	case 1: // A
		if len(rdata) == 4 {
			r.IPv4 = net.IP(rdata).String()
		}
	case 28: // AAAA
		if len(rdata) == 16 {
			r.IPv6 = net.IP(rdata).String()
		}
	case 2, 5, 12: // NS, CNAME, PTR
		name, _, err := decodeName(full, rdataOff, 0)
		if err == nil {
			r.Target = name
		}
	case 15: // MX
		if len(rdata) >= 2 {
			pref := int(binary.BigEndian.Uint16(rdata[0:2]))
			name, _, err := decodeName(full, rdataOff+2, 0)
			if err == nil {
				r.MX = &MXData{Preference: pref, Exchange: name}
			}
		}
	case 16: // TXT
		off := 0
		for off < len(rdata) {
			l := int(rdata[off])
			off++
			if off+l > len(rdata) {
				break
			}
			r.TextRecords = append(r.TextRecords, string(rdata[off:off+l]))
			off += l
		}
	case 33: // SRV
		if len(rdata) >= 6 {
			prio := int(binary.BigEndian.Uint16(rdata[0:2]))
			weight := int(binary.BigEndian.Uint16(rdata[2:4]))
			port := int(binary.BigEndian.Uint16(rdata[4:6]))
			target, _, err := decodeName(full, rdataOff+6, 0)
			if err == nil {
				r.SRV = &SRVData{Priority: prio, Weight: weight, Port: port, Target: target}
			}
		}
	case 6: // SOA
		mname, n1, err := decodeName(full, rdataOff, 0)
		if err != nil {
			return
		}
		rname, n2, err := decodeName(full, rdataOff+n1, 0)
		if err != nil {
			return
		}
		base := rdataOff + n1 + n2
		if base+20 > len(full) {
			return
		}
		r.SOA = &SOAData{
			PrimaryNS:       mname,
			ResponsibleName: rname,
			Serial:          binary.BigEndian.Uint32(full[base : base+4]),
			RefreshSec:      binary.BigEndian.Uint32(full[base+4 : base+8]),
			RetrySec:        binary.BigEndian.Uint32(full[base+8 : base+12]),
			ExpireSec:       binary.BigEndian.Uint32(full[base+12 : base+16]),
			MinimumSec:      binary.BigEndian.Uint32(full[base+16 : base+20]),
		}
	case 41: // OPT (EDNS)
		opt := &OPTData{
			UDPSize:       rrClass,
			ExtendedRCode: int((ttl >> 24) & 0xFF),
			Version:       int((ttl >> 16) & 0xFF),
			DOFlag:        (ttl>>15)&0x01 == 1,
		}
		off := 0
		for off+4 <= len(rdata) {
			code := int(binary.BigEndian.Uint16(rdata[off : off+2]))
			length := int(binary.BigEndian.Uint16(rdata[off+2 : off+4]))
			off += 4
			if off+length > len(rdata) {
				break
			}
			opt.Options = append(opt.Options, OPTOption{
				Code:    code,
				Name:    ednsOptionName(code),
				Length:  length,
				DataHex: strings.ToUpper(hex.EncodeToString(rdata[off : off+length])),
			})
			off += length
		}
		r.OPT = opt
	case 48: // DNSKEY
		if len(rdata) >= 4 {
			flags := int(binary.BigEndian.Uint16(rdata[0:2]))
			r.DNSKEY = &DNSKEYData{
				Flags:         flags,
				IsKSK:         flags&0x0001 != 0,
				IsZSK:         flags&0x0100 != 0,
				Protocol:      int(rdata[2]),
				Algorithm:     int(rdata[3]),
				AlgorithmName: dnssecAlgName(int(rdata[3])),
				KeyTag:        computeKeyTag(rdata),
				PublicKeyHex:  strings.ToUpper(hex.EncodeToString(rdata[4:])),
			}
		}
	case 43: // DS
		if len(rdata) >= 4 {
			r.DS = &DSData{
				KeyTag:         int(binary.BigEndian.Uint16(rdata[0:2])),
				Algorithm:      int(rdata[2]),
				AlgorithmName:  dnssecAlgName(int(rdata[2])),
				DigestType:     int(rdata[3]),
				DigestTypeName: dsDigestName(int(rdata[3])),
				DigestHex:      strings.ToUpper(hex.EncodeToString(rdata[4:])),
			}
		}
	case 257: // CAA
		if len(rdata) >= 2 {
			flags := int(rdata[0])
			tagLen := int(rdata[1])
			if 2+tagLen <= len(rdata) {
				tag := string(rdata[2 : 2+tagLen])
				value := string(rdata[2+tagLen:])
				r.CAA = &CAAData{
					Flags:      flags,
					IsCritical: flags&0x80 != 0,
					Tag:        tag,
					Value:      value,
				}
			}
		}
	}
}

// decodeName walks a DNS name starting at off, following
// compression pointers. depth guards against pointer-loop
// denial-of-service.
func decodeName(b []byte, off, depth int) (string, int, error) {
	const maxDepth = 16
	if depth > maxDepth {
		return "", 0, fmt.Errorf("name pointer chain exceeded max depth (%d)", maxDepth)
	}
	var labels []string
	bytesRead := 0
	cur := off
	jumped := false
	for {
		if cur >= len(b) {
			return "", 0, fmt.Errorf("name walks past buffer at offset %d", cur)
		}
		l := b[cur]
		// Compression pointer? Top 2 bits set.
		if l&0xC0 == 0xC0 {
			if cur+2 > len(b) {
				return "", 0, fmt.Errorf("pointer truncated at offset %d", cur)
			}
			ptr := int(binary.BigEndian.Uint16(b[cur:cur+2])) & 0x3FFF
			if ptr >= len(b) {
				return "", 0, fmt.Errorf("pointer target %d outside buffer", ptr)
			}
			rest, _, err := decodeName(b, ptr, depth+1)
			if err != nil {
				return "", 0, err
			}
			if rest != "" {
				labels = append(labels, rest)
			}
			if !jumped {
				bytesRead = cur - off + 2
			}
			break
		}
		if l == 0 {
			if !jumped {
				bytesRead = cur - off + 1
			}
			break
		}
		if l&0xC0 != 0 {
			return "", 0, fmt.Errorf("unsupported label type 0x%02X at offset %d", l, cur)
		}
		cur++
		if cur+int(l) > len(b) {
			return "", 0, fmt.Errorf("label (length %d) exceeds buffer", l)
		}
		labels = append(labels, string(b[cur:cur+int(l)]))
		cur += int(l)
	}
	return strings.Join(labels, "."), bytesRead, nil
}

func opcodeName(o int) string {
	switch o {
	case 0:
		return "QUERY"
	case 1:
		return "IQUERY"
	case 2:
		return "STATUS"
	case 4:
		return "NOTIFY"
	case 5:
		return "UPDATE"
	case 6:
		return "DSO"
	}
	return fmt.Sprintf("Reserved (opcode %d)", o)
}

func rcodeName(r int) string {
	switch r {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	case 6:
		return "YXDOMAIN"
	case 7:
		return "YXRRSET"
	case 8:
		return "NXRRSET"
	case 9:
		return "NOTAUTH"
	case 10:
		return "NOTZONE"
	case 16:
		return "BADVERS / BADSIG"
	case 17:
		return "BADKEY"
	case 18:
		return "BADTIME"
	case 19:
		return "BADMODE"
	case 20:
		return "BADNAME"
	case 21:
		return "BADALG"
	case 22:
		return "BADTRUNC"
	case 23:
		return "BADCOOKIE"
	}
	return fmt.Sprintf("Reserved (RCODE %d)", r)
}

func rrTypeName(t int) string {
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
	case 13:
		return "HINFO"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 17:
		return "RP"
	case 18:
		return "AFSDB"
	case 24:
		return "SIG"
	case 25:
		return "KEY"
	case 28:
		return "AAAA"
	case 29:
		return "LOC"
	case 33:
		return "SRV"
	case 35:
		return "NAPTR"
	case 39:
		return "DNAME"
	case 41:
		return "OPT (EDNS)"
	case 42:
		return "APL"
	case 43:
		return "DS"
	case 44:
		return "SSHFP"
	case 45:
		return "IPSECKEY"
	case 46:
		return "RRSIG"
	case 47:
		return "NSEC"
	case 48:
		return "DNSKEY"
	case 49:
		return "DHCID"
	case 50:
		return "NSEC3"
	case 51:
		return "NSEC3PARAM"
	case 52:
		return "TLSA"
	case 53:
		return "SMIMEA"
	case 55:
		return "HIP"
	case 59:
		return "CDS"
	case 60:
		return "CDNSKEY"
	case 61:
		return "OPENPGPKEY"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 99:
		return "SPF"
	case 250:
		return "TSIG"
	case 251:
		return "IXFR"
	case 252:
		return "AXFR"
	case 255:
		return "ANY"
	case 256:
		return "URI"
	case 257:
		return "CAA"
	}
	return fmt.Sprintf("TYPE%d", t)
}

func classNameOrEDNS(rrType, class int) string {
	if rrType == 41 {
		return fmt.Sprintf("UDP size %d", class)
	}
	switch class {
	case 1:
		return "IN"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 254:
		return "NONE"
	case 255:
		return "ANY"
	}
	return fmt.Sprintf("CLASS%d", class)
}

func ednsOptionName(code int) string {
	switch code {
	case 3:
		return "NSID"
	case 5:
		return "DAU"
	case 6:
		return "DHU"
	case 7:
		return "N3U"
	case 8:
		return "ECS (Client Subnet)"
	case 9:
		return "EXPIRE"
	case 10:
		return "COOKIE"
	case 11:
		return "edns-tcp-keepalive"
	case 12:
		return "Padding"
	case 13:
		return "CHAIN"
	case 14:
		return "edns-key-tag"
	case 15:
		return "EDE (Extended DNS Error)"
	}
	return fmt.Sprintf("OPT%d", code)
}

func dnssecAlgName(a int) string {
	switch a {
	case 1:
		return "RSAMD5"
	case 3:
		return "DSA"
	case 5:
		return "RSASHA1"
	case 6:
		return "DSA-NSEC3-SHA1"
	case 7:
		return "RSASHA1-NSEC3-SHA1"
	case 8:
		return "RSASHA256"
	case 10:
		return "RSASHA512"
	case 12:
		return "ECC-GOST"
	case 13:
		return "ECDSAP256SHA256"
	case 14:
		return "ECDSAP384SHA384"
	case 15:
		return "ED25519"
	case 16:
		return "ED448"
	}
	return fmt.Sprintf("ALG%d", a)
}

func dsDigestName(d int) string {
	switch d {
	case 1:
		return "SHA-1"
	case 2:
		return "SHA-256"
	case 3:
		return "GOST R 34.11-94"
	case 4:
		return "SHA-384"
	}
	return fmt.Sprintf("DIGEST%d", d)
}

// computeKeyTag implements the DNSKEY key-tag algorithm
// from RFC 4034 Appendix B for algorithms other than algorithm
// 1 (RSAMD5 has a different / deprecated formula).
func computeKeyTag(rdata []byte) int {
	if len(rdata) < 4 {
		return 0
	}
	if rdata[3] == 1 {
		// RSAMD5 — deprecated; return 0.
		return 0
	}
	var ac uint32
	for i, b := range rdata {
		if i&1 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}
	ac += (ac >> 16) & 0xFFFF
	return int(ac & 0xFFFF)
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("dnsdecode: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("dnsdecode: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
