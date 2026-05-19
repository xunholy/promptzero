// Package ospf decodes OSPFv2 packets per RFC 2328. OSPFv3
// (RFC 5340) uses a different header layout and is not
// covered here.
//
// Wrap-vs-native judgement
//
//	Native. RFC 2328 is fully public; OSPFv2 wire format is
//	a tight 24-byte common header followed by per-type bodies
//	that are themselves bit-packed binary fields. No crypto
//	at the parse layer (Authentication field is surfaced as
//	hex; cryptographic verification belongs to a separate
//	Spec). Operators paste OSPF packet bytes (IP protocol
//	number 89, multicast to 224.0.0.5 / 224.0.0.6) from a
//	`tcpdump -X proto 89` line, a Wireshark Follow-IP-Stream
//	view, a Quagga / FRR / GoBGP / BIRD debug log, or any
//	OSPF-speaking router's tcpdump and get the documented
//	header + per-type body breakdown.
//
// What this package covers
//
//   - **24-byte common header** (RFC 2328 §A.3.1):
//
//   - Version (1 byte; 2 for OSPFv2)
//
//   - **Type** (1 byte) with **5-entry name table**:
//
//   - 1 Hello
//
//   - 2 Database Description (DBD)
//
//   - 3 Link State Request (LSR)
//
//   - 4 Link State Update (LSU)
//
//   - 5 Link State Acknowledgment (LSAck)
//
//   - Packet Length (uint16 BE)
//
//   - Router ID (4 bytes; IPv4-formatted)
//
//   - Area ID (4 bytes; IPv4-formatted, where 0.0.0.0 is
//     the backbone area)
//
//   - Checksum (uint16 BE; surfaced as hex)
//
//   - **AuType** (uint16 BE) with **3-entry name table**:
//
//   - 0 Null (no authentication)
//
//   - 1 Simple Password (cleartext password in the
//     Authentication field)
//
//   - 2 Cryptographic Authentication (MD5; the Auth
//     field carries metadata, the MD5 digest follows
//     the packet)
//
//   - Authentication (8 bytes; opaque per AuType)
//
//   - **Hello body** (RFC 2328 §A.3.2):
//
//   - Network Mask (4 bytes IPv4)
//
//   - HelloInterval (uint16 BE seconds)
//
//   - **Options** (1 byte) with bit-name decoding (E /
//     MC / NP / EA / DC / O)
//
//   - Rtr Pri (1 byte; designated-router election
//     priority)
//
//   - RouterDeadInterval (uint32 BE seconds)
//
//   - Designated Router (4 bytes IPv4)
//
//   - Backup Designated Router (4 bytes IPv4)
//
//   - List of Neighbors (4 bytes IPv4 each, until end of
//     packet)
//
//   - **Database Description body** (RFC 2328 §A.3.3):
//
//   - Interface MTU (uint16 BE)
//
//   - Options (1 byte; same bits as Hello)
//
//   - I (Init), M (More), MS (Master/Slave) flag byte
//
//   - DD Sequence Number (uint32 BE)
//
//   - List of LSA Headers (20 bytes each)
//
//   - **Link State Request body** (RFC 2328 §A.3.4):
//
//   - List of LSA-request entries (12 bytes each: LS Type
//     uint32 BE + Link State ID 4 bytes + Advertising
//     Router 4 bytes)
//
//   - **Link State Update body** (RFC 2328 §A.3.5):
//
//   - Number of LSAs (uint32 BE)
//
//   - LSAs follow (each starts with a 20-byte LSA Header;
//     we surface header info + remaining body as hex)
//
//   - **Link State Acknowledgment body** (RFC 2328 §A.3.6):
//
//   - List of LSA Headers (20 bytes each)
//
//   - **LSA Header** (20 bytes, used by DBD / LSU / LSAck):
//
//   - LS Age (uint16 BE seconds since origination)
//
//   - Options (1 byte)
//
//   - **LS Type** (1 byte) with **9-entry name table**:
//
//   - 1 Router LSA
//
//   - 2 Network LSA
//
//   - 3 Summary LSA (network)
//
//   - 4 Summary LSA (ASBR)
//
//   - 5 AS-External LSA
//
//   - 7 NSSA External LSA (RFC 3101)
//
//   - 9 Link-Local Opaque (RFC 5250)
//
//   - 10 Area-Local Opaque
//
//   - 11 AS-wide Opaque
//
//   - Link State ID (4 bytes IPv4)
//
//   - Advertising Router (4 bytes IPv4)
//
//   - LS Sequence Number (int32 BE; signed, starts at
//     0x80000001 and increments)
//
//   - LS Checksum (uint16 BE; surfaced as hex)
//
//   - Length (uint16 BE; total LSA size including this
//     20-byte header)
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IP framing — feed the OSPF bytes after the IPv4 / IPv6
//     header strip. OSPFv2 runs over IP protocol 89.
//
//   - OSPFv3 (RFC 5340) — different header layout (no Auth
//     field; uses IPsec for authentication); a future Spec.
//
//   - LSA body deep dissection — the LSA Header is decoded
//     but Router LSA links, Network LSA attached routers,
//     Summary LSA metric/cost, AS-External LSA forwarding
//     address are all surfaced as raw hex past the header.
//
//   - Cryptographic verification — AuType 2 (MD5) is
//     recognised but the digest verification belongs in a
//     separate Spec.
//
//   - Opaque LSA TLV walking (RFC 5250) — type 9/10/11
//     surface the LS Type name; the opaque payload is hex.
package ospf

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	Version      int    `json:"version"`
	Type         int    `json:"type"`
	TypeName     string `json:"type_name"`
	PacketLength int    `json:"packet_length"`
	RouterID     string `json:"router_id"`
	AreaID       string `json:"area_id"`
	ChecksumHex  string `json:"checksum_hex"`
	AuType       int    `json:"au_type"`
	AuTypeName   string `json:"au_type_name"`
	AuthHex      string `json:"authentication_hex"`
	TotalBytes   int    `json:"total_bytes"`

	Hello *HelloMsg `json:"hello,omitempty"`
	DBD   *DBDMsg   `json:"database_description,omitempty"`
	LSR   *LSRMsg   `json:"link_state_request,omitempty"`
	LSU   *LSUMsg   `json:"link_state_update,omitempty"`
	LSAck *LSAckMsg `json:"link_state_acknowledgment,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// HelloMsg is the body of Type 1.
type HelloMsg struct {
	NetworkMask            string   `json:"network_mask"`
	HelloInterval          uint16   `json:"hello_interval_seconds"`
	Options                int      `json:"options"`
	OptionsDecoded         []string `json:"options_decoded,omitempty"`
	RtrPri                 int      `json:"router_priority"`
	RouterDeadInterval     uint32   `json:"router_dead_interval_seconds"`
	DesignatedRouter       string   `json:"designated_router"`
	BackupDesignatedRouter string   `json:"backup_designated_router"`
	Neighbors              []string `json:"neighbors,omitempty"`
}

// DBDMsg is the body of Type 2.
type DBDMsg struct {
	InterfaceMTU     uint16      `json:"interface_mtu"`
	Options          int         `json:"options"`
	OptionsDecoded   []string    `json:"options_decoded,omitempty"`
	IBit             bool        `json:"i_init"`
	MBit             bool        `json:"m_more"`
	MSBit            bool        `json:"ms_master_slave"`
	DDSequenceNumber uint32      `json:"dd_sequence_number"`
	LSAHeaders       []LSAHeader `json:"lsa_headers,omitempty"`
}

// LSRMsg is the body of Type 3.
type LSRMsg struct {
	Requests []LSARequest `json:"requests,omitempty"`
}

// LSARequest is one 12-byte Link State Request entry.
type LSARequest struct {
	LSType            int    `json:"ls_type"`
	LSTypeName        string `json:"ls_type_name"`
	LinkStateID       string `json:"link_state_id"`
	AdvertisingRouter string `json:"advertising_router"`
}

// LSUMsg is the body of Type 4.
type LSUMsg struct {
	NumberOfLSAs int         `json:"number_of_lsas"`
	LSAs         []LSAHeader `json:"lsas,omitempty"`
}

// LSAckMsg is the body of Type 5.
type LSAckMsg struct {
	LSAHeaders []LSAHeader `json:"lsa_headers,omitempty"`
}

// LSAHeader is one 20-byte LSA Header.
type LSAHeader struct {
	LSAgeSeconds      uint16 `json:"ls_age_seconds"`
	Options           int    `json:"options"`
	LSType            int    `json:"ls_type"`
	LSTypeName        string `json:"ls_type_name"`
	LinkStateID       string `json:"link_state_id"`
	AdvertisingRouter string `json:"advertising_router"`
	LSSequenceNumber  int32  `json:"ls_sequence_number"`
	LSSequenceHex     string `json:"ls_sequence_hex"`
	LSChecksumHex     string `json:"ls_checksum_hex"`
	Length            int    `json:"length"`
	BodyHex           string `json:"body_hex,omitempty"`
}

// Decode parses a single OSPFv2 packet from hex.
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
		return nil, fmt.Errorf("OSPF header truncated (%d bytes; need ≥24)", len(b))
	}

	r := &Result{
		TotalBytes:   len(b),
		Version:      int(b[0]),
		Type:         int(b[1]),
		PacketLength: int(binary.BigEndian.Uint16(b[2:4])),
		RouterID:     ipv4String(b[4:8]),
		AreaID:       ipv4String(b[8:12]),
		ChecksumHex:  fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[12:14])),
		AuType:       int(binary.BigEndian.Uint16(b[14:16])),
		AuthHex:      strings.ToUpper(hex.EncodeToString(b[16:24])),
	}
	r.TypeName = typeName(r.Type)
	r.AuTypeName = auTypeName(r.AuType)

	if r.Version != 2 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"OSPF version is %d; this decoder targets OSPFv2 (version 2). Version 3 "+
				"(RFC 5340) has a different header layout — use a future ospf3_* Spec.",
			r.Version))
	}
	if r.PacketLength > len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"declared Packet Length %d exceeds buffer length %d (message truncated)",
			r.PacketLength, len(b)))
	}

	body := b[24:]
	if r.PacketLength > 24 && r.PacketLength <= len(b) {
		body = b[24:r.PacketLength]
	}

	switch r.Type {
	case 1:
		h, err := decodeHello(body)
		if err != nil {
			return nil, fmt.Errorf("hello body: %w", err)
		}
		r.Hello = h
	case 2:
		d, err := decodeDBD(body)
		if err != nil {
			return nil, fmt.Errorf("dbd body: %w", err)
		}
		r.DBD = d
	case 3:
		l, err := decodeLSR(body)
		if err != nil {
			return nil, fmt.Errorf("lsr body: %w", err)
		}
		r.LSR = l
	case 4:
		u, err := decodeLSU(body)
		if err != nil {
			return nil, fmt.Errorf("lsu body: %w", err)
		}
		r.LSU = u
	case 5:
		a, err := decodeLSAck(body)
		if err != nil {
			return nil, fmt.Errorf("lsack body: %w", err)
		}
		r.LSAck = a
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"uncatalogued OSPF Type %d (RFC 2328 defines 1-5)", r.Type))
	}

	return r, nil
}

func decodeHello(b []byte) (*HelloMsg, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("body too short (%d; need ≥20)", len(b))
	}
	h := &HelloMsg{
		NetworkMask:            ipv4String(b[0:4]),
		HelloInterval:          binary.BigEndian.Uint16(b[4:6]),
		Options:                int(b[6]),
		RtrPri:                 int(b[7]),
		RouterDeadInterval:     binary.BigEndian.Uint32(b[8:12]),
		DesignatedRouter:       ipv4String(b[12:16]),
		BackupDesignatedRouter: ipv4String(b[16:20]),
	}
	h.OptionsDecoded = decodeOptions(b[6])
	for off := 20; off+4 <= len(b); off += 4 {
		h.Neighbors = append(h.Neighbors, ipv4String(b[off:off+4]))
	}
	return h, nil
}

func decodeDBD(b []byte) (*DBDMsg, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("body too short (%d; need ≥8)", len(b))
	}
	d := &DBDMsg{
		InterfaceMTU:     binary.BigEndian.Uint16(b[0:2]),
		Options:          int(b[2]),
		IBit:             b[3]&0x04 != 0,
		MBit:             b[3]&0x02 != 0,
		MSBit:            b[3]&0x01 != 0,
		DDSequenceNumber: binary.BigEndian.Uint32(b[4:8]),
	}
	d.OptionsDecoded = decodeOptions(b[2])
	for off := 8; off+20 <= len(b); off += 20 {
		d.LSAHeaders = append(d.LSAHeaders, decodeLSAHeader(b[off:off+20]))
	}
	return d, nil
}

func decodeLSR(b []byte) (*LSRMsg, error) {
	l := &LSRMsg{}
	for off := 0; off+12 <= len(b); off += 12 {
		req := LSARequest{
			LSType:            int(binary.BigEndian.Uint32(b[off : off+4])),
			LinkStateID:       ipv4String(b[off+4 : off+8]),
			AdvertisingRouter: ipv4String(b[off+8 : off+12]),
		}
		req.LSTypeName = lsTypeName(req.LSType)
		l.Requests = append(l.Requests, req)
	}
	return l, nil
}

func decodeLSU(b []byte) (*LSUMsg, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("body too short (%d; need ≥4)", len(b))
	}
	u := &LSUMsg{
		NumberOfLSAs: int(binary.BigEndian.Uint32(b[0:4])),
	}
	off := 4
	for i := 0; i < u.NumberOfLSAs && off+20 <= len(b); i++ {
		lh := decodeLSAHeader(b[off : off+20])
		end := off + lh.Length
		if end > len(b) {
			end = len(b)
		}
		if lh.Length > 20 && end > off+20 {
			lh.BodyHex = strings.ToUpper(hex.EncodeToString(b[off+20 : end]))
		}
		u.LSAs = append(u.LSAs, lh)
		if lh.Length < 20 {
			break // malformed
		}
		off += lh.Length
	}
	return u, nil
}

func decodeLSAck(b []byte) (*LSAckMsg, error) {
	a := &LSAckMsg{}
	for off := 0; off+20 <= len(b); off += 20 {
		a.LSAHeaders = append(a.LSAHeaders, decodeLSAHeader(b[off:off+20]))
	}
	return a, nil
}

func decodeLSAHeader(b []byte) LSAHeader {
	seq := int32(binary.BigEndian.Uint32(b[12:16]))
	lh := LSAHeader{
		LSAgeSeconds:      binary.BigEndian.Uint16(b[0:2]),
		Options:           int(b[2]),
		LSType:            int(b[3]),
		LinkStateID:       ipv4String(b[4:8]),
		AdvertisingRouter: ipv4String(b[8:12]),
		LSSequenceNumber:  seq,
		LSSequenceHex:     fmt.Sprintf("0x%08X", uint32(seq)),
		LSChecksumHex:     fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[16:18])),
		Length:            int(binary.BigEndian.Uint16(b[18:20])),
	}
	lh.LSTypeName = lsTypeName(lh.LSType)
	return lh
}

func decodeOptions(o byte) []string {
	parts := []string{}
	if o&0x02 != 0 {
		parts = append(parts, "E (External)")
	}
	if o&0x04 != 0 {
		parts = append(parts, "MC (Multicast)")
	}
	if o&0x08 != 0 {
		parts = append(parts, "NP (NSSA)")
	}
	if o&0x10 != 0 {
		parts = append(parts, "EA (External Attribute LSA)")
	}
	if o&0x20 != 0 {
		parts = append(parts, "DC (Demand Circuit)")
	}
	if o&0x40 != 0 {
		parts = append(parts, "O (Opaque LSA)")
	}
	if o&0x80 != 0 {
		parts = append(parts, "DN (Down bit, RFC 4576)")
	}
	return parts
}

func typeName(t int) string {
	switch t {
	case 1:
		return "Hello"
	case 2:
		return "Database Description (DBD)"
	case 3:
		return "Link State Request (LSR)"
	case 4:
		return "Link State Update (LSU)"
	case 5:
		return "Link State Acknowledgment (LSAck)"
	}
	return fmt.Sprintf("uncatalogued type %d", t)
}

func auTypeName(a int) string {
	switch a {
	case 0:
		return "Null (no authentication)"
	case 1:
		return "Simple Password"
	case 2:
		return "Cryptographic Authentication (MD5)"
	}
	return fmt.Sprintf("uncatalogued AuType %d", a)
}

func lsTypeName(t int) string {
	switch t {
	case 1:
		return "Router LSA"
	case 2:
		return "Network LSA"
	case 3:
		return "Summary LSA (network)"
	case 4:
		return "Summary LSA (ASBR)"
	case 5:
		return "AS-External LSA"
	case 7:
		return "NSSA External LSA (RFC 3101)"
	case 9:
		return "Link-Local Opaque LSA (RFC 5250)"
	case 10:
		return "Area-Local Opaque LSA"
	case 11:
		return "AS-wide Opaque LSA"
	}
	return fmt.Sprintf("uncatalogued LS Type %d", t)
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
