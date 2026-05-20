// Package ospfv3 decodes OSPFv3 (RFC 5340) packets. OSPFv3 is
// the IPv6 sibling of OSPFv2 (RFC 2328, already covered by
// `internal/ospf`); the two protocols share the same Hello /
// DBD / LSR / LSU / LSAck packet-type ladder but use a slimmer
// 16-byte common header (OSPFv3 drops the AuType + 8-byte Auth
// field because IPv6 expects integrity to come from IP AH/ESP)
// and a richer LS Type encoding split into Flooding Scope
// (U/S2/S1 bits) + 13-bit Function Code. Used in every IPv6-
// routed network — service-provider cores, enterprise IPv6
// deployments, dual-stack data centres.
//
// Wrap-vs-native judgement
//
//	Native. RFC 5340 is fully public; OSPFv3 has a tight
//	16-byte common header followed by a per-type body whose
//	layouts are documented in §A.3 of the RFC. No crypto at
//	the parse layer — OSPFv3 specifies IP AH/ESP for
//	integrity, kept deliberately out of scope here. Operators
//	paste OSPFv3 bytes (IP protocol number 89, multicast to
//	FF02::5 for AllSPFRouters or FF02::6 for AllDRouters) from
//	a `tcpdump -X ip6 proto 89` line or a Wireshark Follow-
//	IPv6-Stream view and get the documented header + per-type
//	body breakdown.
//
// What this package covers
//
//   - **16-byte common header** (RFC 5340 §A.3.1):
//
//   - byte 0: Version (1 byte; must be 3).
//
//   - byte 1: **Type** with **5-entry name table**:
//     1 Hello, 2 Database Description, 3 Link State
//     Request, 4 Link State Update, 5 Link State
//     Acknowledgment.
//
//   - bytes 2-3: Length (uint16 BE; total packet length
//     including header).
//
//   - bytes 4-7: Router ID (uint32 BE; canonical dotted-
//     quad form even though it's an opaque 32-bit ID).
//
//   - bytes 8-11: Area ID (uint32 BE; same dotted-quad
//     form).
//
//   - bytes 12-13: Checksum (uint16 BE, hex-formatted).
//
//   - byte 14: **Instance ID** (uint8; allows multiple
//     OSPFv3 instances per interface — RFC 5838 extends
//     this for Address-Family support).
//
//   - byte 15: Reserved.
//
//   - **Hello body** (Type 1; RFC 5340 §A.3.2):
//
//   - bytes 0-3: Interface ID (uint32 BE; the local
//     interface identifier — unlike OSPFv2 which used
//     the IPv4 interface address).
//
//   - byte 4: Router Priority (uint8; default 1; 0 =
//     cannot become DR).
//
//   - bytes 5-7: **Options** (24-bit BE) decoded into
//     the **6 most-common named bits**: V6 (IPv6
//     forwarding), E (External / non-stub area), MC
//     (MOSPF), N (NSSA), R (Router participating in IPv6
//     routing), DC (Demand Circuits).
//
//   - bytes 8-9: HelloInterval (uint16 BE seconds).
//
//   - bytes 10-11: RouterDeadInterval (uint16 BE
//     seconds).
//
//   - bytes 12-15: Designated Router ID (uint32 BE
//     dotted-quad).
//
//   - bytes 16-19: Backup Designated Router ID (uint32
//     BE dotted-quad).
//
//   - bytes 20+: zero or more 4-byte Neighbor Router IDs.
//
//   - **Database Description body** (Type 2; RFC 5340
//     §A.3.3):
//
//   - byte 0: Reserved.
//
//   - bytes 1-3: Options (24-bit; same decode as Hello).
//
//   - bytes 4-5: Interface MTU (uint16 BE).
//
//   - byte 6: Reserved.
//
//   - byte 7: **I / M / MS bits** (low 3 bits of an 8-bit
//     flags byte): Init / More / Master-Slave.
//
//   - bytes 8-11: DD Sequence Number (uint32 BE).
//
//   - bytes 12+: zero or more LSA Headers (20 bytes each).
//
//   - **Link State Request body** (Type 3; RFC 5340 §A.3.4)
//     — array of 12-byte records: LS Type (uint32 BE) +
//     Link State ID (uint32 BE) + Advertising Router
//     (uint32 BE).
//
//   - **Link State Update body** (Type 4; RFC 5340 §A.3.5):
//
//   - bytes 0-3: Number of LSAs (uint32 BE).
//
//   - then N LSAs, each starting with the 20-byte LSA
//     Header. The full LSA body decoding (Router-LSA
//     Type 1 Link records, Network-LSA, Inter-Area-Prefix,
//     AS-External-LSA, Intra-Area-Prefix etc.) is
//     surfaced via the LSA Header summary; per-LSA body
//     walking is deferred (see Out of scope).
//
//   - **Link State Acknowledgment body** (Type 5; RFC 5340
//     §A.3.6) — array of 20-byte LSA Headers (no body).
//
//   - **20-byte LSA Header** (RFC 5340 §A.4.2):
//
//   - bytes 0-1: LS Age (uint16 BE; 0-3600 seconds).
//
//   - bytes 2-3: **LS Type** (uint16 BE) — OSPFv3 splits
//     this into 3-bit Flooding Scope (U/S2/S1 high bits)
//
//   - 13-bit Function Code. **9-entry function code
//     name table**: 0x2001 Router-LSA, 0x2002 Network-
//     LSA, 0x2003 Inter-Area-Prefix-LSA, 0x2004 Inter-
//     Area-Router-LSA, 0x4005 AS-External-LSA, 0x2006
//     Group-Membership-LSA (deprecated; MOSPF), 0x2007
//     Type-7-LSA (NSSA External), 0x0008 Link-LSA,
//     0x2009 Intra-Area-Prefix-LSA.
//
//   - bytes 4-7: Link State ID (uint32 BE).
//
//   - bytes 8-11: Advertising Router (uint32 BE dotted-
//     quad).
//
//   - bytes 12-15: LS Sequence Number (int32 BE; starts
//     at 0x80000001).
//
//   - bytes 16-17: LS Checksum (uint16 BE, hex).
//
//   - bytes 18-19: Length (uint16 BE; total LSA length
//     including header).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IPv6 framing — feed OSPFv3 bytes after the IPv6 header
//     strip. OSPFv3 runs over IP protocol 89.
//
//   - OSPFv2 (RFC 2328) — that's the existing
//     `ospf_packet_decode` Spec; this package handles only
//     the v3 / IPv6 variant.
//
//   - Per-LSA body parsing (Router-LSA Link records, Network-
//     LSA attached routers, Inter-Area-Prefix prefix records,
//     AS-External-LSA forwarding address + tag, Link-LSA
//     link-local address + prefix options, Intra-Area-Prefix
//     prefix list) — the LSA Header is decoded with Function
//     Code naming + Length; the per-Function-Code body
//     walker is a separate dissector that would warrant its
//     own Spec.
//
//   - OSPFv3 IP-AH/IP-ESP integrity verification — the spec
//     deliberately relies on the IPv6 security layer for
//     auth; this decoder does not attempt to verify any
//     wrapping authenticator.
//
//   - OSPFv3 routing-table reasoning — adjacency state
//     machine, SPF run, route summarisation — higher-level
//     analysis.
package ospfv3

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	Version     int    `json:"version"`
	Type        int    `json:"type"`
	TypeName    string `json:"type_name"`
	Length      int    `json:"length"`
	RouterID    string `json:"router_id"`
	AreaID      string `json:"area_id"`
	ChecksumHex string `json:"checksum_hex"`
	InstanceID  int    `json:"instance_id"`
	Reserved    int    `json:"reserved"`

	Hello *HelloBody    `json:"hello,omitempty"`
	DBD   *DBDBody      `json:"database_description,omitempty"`
	LSR   []LSReqRecord `json:"link_state_request,omitempty"`
	LSU   *LSUBody      `json:"link_state_update,omitempty"`
	LSAck []LSAHeader   `json:"link_state_acknowledgment,omitempty"`

	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// HelloBody is the decoded body of a Hello packet.
type HelloBody struct {
	InterfaceID           uint32   `json:"interface_id"`
	RouterPriority        int      `json:"router_priority"`
	Options               int      `json:"options"`
	OptionsHex            string   `json:"options_hex"`
	OptionFlags           Options  `json:"option_flags"`
	HelloIntervalSec      int      `json:"hello_interval_seconds"`
	RouterDeadIntervalSec int      `json:"router_dead_interval_seconds"`
	DesignatedRouterID    string   `json:"designated_router_id"`
	BackupDR_ID           string   `json:"backup_designated_router_id"`
	Neighbors             []string `json:"neighbors,omitempty"`
}

// Options is the decoded 24-bit Options field common to Hello
// + DBD bodies.
type Options struct {
	V6 bool `json:"v6"`
	E  bool `json:"e_external"`
	MC bool `json:"mc_mospf"`
	N  bool `json:"n_nssa"`
	R  bool `json:"r_router"`
	DC bool `json:"dc_demand_circuit"`
}

// DBDBody is the decoded body of a Database Description packet.
type DBDBody struct {
	Options          int         `json:"options"`
	OptionsHex       string      `json:"options_hex"`
	OptionFlags      Options     `json:"option_flags"`
	InterfaceMTU     int         `json:"interface_mtu"`
	FlagInit         bool        `json:"flag_init"`
	FlagMore         bool        `json:"flag_more"`
	FlagMasterSlave  bool        `json:"flag_master_slave"`
	DDSequenceNumber uint32      `json:"dd_sequence_number"`
	LSAHeaders       []LSAHeader `json:"lsa_headers,omitempty"`
}

// LSReqRecord is one 12-byte Link State Request record.
type LSReqRecord struct {
	LSType            uint32 `json:"ls_type"`
	LSTypeName        string `json:"ls_type_name"`
	LinkStateID       string `json:"link_state_id"`
	AdvertisingRouter string `json:"advertising_router"`
}

// LSUBody is the decoded body of a Link State Update packet.
type LSUBody struct {
	NumberOfLSAs uint32      `json:"number_of_lsas"`
	LSAHeaders   []LSAHeader `json:"lsa_headers,omitempty"`
}

// LSAHeader is the decoded 20-byte LSA Header.
type LSAHeader struct {
	LSAge             int    `json:"ls_age"`
	LSType            int    `json:"ls_type"`
	LSTypeHex         string `json:"ls_type_hex"`
	LSTypeName        string `json:"ls_type_name"`
	FloodingScope     int    `json:"flooding_scope"`
	FloodingScopeName string `json:"flooding_scope_name"`
	LinkStateID       string `json:"link_state_id"`
	AdvertisingRouter string `json:"advertising_router"`
	LSSequenceNumber  int32  `json:"ls_sequence_number"`
	ChecksumHex       string `json:"checksum_hex"`
	Length            int    `json:"length"`
}

// Decode parses a single OSPFv3 packet from hex.
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
	if len(b) < 16 {
		return nil, fmt.Errorf("OSPFv3 packet truncated (%d bytes; need ≥16 for common header)",
			len(b))
	}
	r := &Result{
		TotalBytes:  len(b),
		Version:     int(b[0]),
		Type:        int(b[1]),
		Length:      int(binary.BigEndian.Uint16(b[2:4])),
		RouterID:    dottedQuad(b[4:8]),
		AreaID:      dottedQuad(b[8:12]),
		ChecksumHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[12:14])),
		InstanceID:  int(b[14]),
		Reserved:    int(b[15]),
	}
	r.TypeName = typeName(r.Type)
	if r.Version != 3 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"version is %d (this Spec covers OSPFv3 — RFC 5340 — only)", r.Version))
	}
	body := b[16:]
	switch r.Type {
	case 1:
		h, err := decodeHello(body)
		if err != nil {
			return r, fmt.Errorf("hello body: %w", err)
		}
		r.Hello = h
	case 2:
		d, err := decodeDBD(body)
		if err != nil {
			return r, fmt.Errorf("DBD body: %w", err)
		}
		r.DBD = d
	case 3:
		recs, err := decodeLSR(body)
		if err != nil {
			return r, fmt.Errorf("LSR body: %w", err)
		}
		r.LSR = recs
	case 4:
		u, err := decodeLSU(body)
		if err != nil {
			return r, fmt.Errorf("LSU body: %w", err)
		}
		r.LSU = u
	case 5:
		hs, err := decodeLSAHeaders(body)
		if err != nil {
			return r, fmt.Errorf("LSAck body: %w", err)
		}
		r.LSAck = hs
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"uncatalogued OSPFv3 Type %d (RFC 5340 defines 1-5)", r.Type))
	}
	return r, nil
}

func decodeHello(b []byte) (*HelloBody, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("body truncated (%d; need 20)", len(b))
	}
	opts := (int(b[5]) << 16) | (int(b[6]) << 8) | int(b[7])
	h := &HelloBody{
		InterfaceID:           binary.BigEndian.Uint32(b[0:4]),
		RouterPriority:        int(b[4]),
		Options:               opts,
		OptionsHex:            fmt.Sprintf("0x%06X", opts),
		OptionFlags:           decodeOptions(opts),
		HelloIntervalSec:      int(binary.BigEndian.Uint16(b[8:10])),
		RouterDeadIntervalSec: int(binary.BigEndian.Uint16(b[10:12])),
		DesignatedRouterID:    dottedQuad(b[12:16]),
		BackupDR_ID:           dottedQuad(b[16:20]),
	}
	for off := 20; off+4 <= len(b); off += 4 {
		h.Neighbors = append(h.Neighbors, dottedQuad(b[off:off+4]))
	}
	return h, nil
}

func decodeDBD(b []byte) (*DBDBody, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("body truncated (%d; need 12)", len(b))
	}
	opts := (int(b[1]) << 16) | (int(b[2]) << 8) | int(b[3])
	flags := b[7]
	d := &DBDBody{
		Options:          opts,
		OptionsHex:       fmt.Sprintf("0x%06X", opts),
		OptionFlags:      decodeOptions(opts),
		InterfaceMTU:     int(binary.BigEndian.Uint16(b[4:6])),
		FlagInit:         flags&0x04 != 0,
		FlagMore:         flags&0x02 != 0,
		FlagMasterSlave:  flags&0x01 != 0,
		DDSequenceNumber: binary.BigEndian.Uint32(b[8:12]),
	}
	if len(b) > 12 {
		hs, err := decodeLSAHeaders(b[12:])
		if err != nil {
			return d, err
		}
		d.LSAHeaders = hs
	}
	return d, nil
}

func decodeLSR(b []byte) ([]LSReqRecord, error) {
	if len(b)%12 != 0 {
		return nil, fmt.Errorf("body length %d not a multiple of 12", len(b))
	}
	var out []LSReqRecord
	for off := 0; off+12 <= len(b); off += 12 {
		lt := binary.BigEndian.Uint32(b[off : off+4])
		out = append(out, LSReqRecord{
			LSType:            lt,
			LSTypeName:        lsTypeName(int(lt)),
			LinkStateID:       dottedQuad(b[off+4 : off+8]),
			AdvertisingRouter: dottedQuad(b[off+8 : off+12]),
		})
	}
	return out, nil
}

func decodeLSU(b []byte) (*LSUBody, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("body truncated (%d; need 4)", len(b))
	}
	u := &LSUBody{
		NumberOfLSAs: binary.BigEndian.Uint32(b[0:4]),
	}
	off := 4
	for i := uint32(0); i < u.NumberOfLSAs; i++ {
		if off+20 > len(b) {
			break
		}
		h, _ := decodeOneLSAHeader(b[off : off+20])
		u.LSAHeaders = append(u.LSAHeaders, h)
		// Skip the rest of the LSA body using its Length.
		off += h.Length
		if h.Length < 20 {
			break
		}
	}
	return u, nil
}

func decodeLSAHeaders(b []byte) ([]LSAHeader, error) {
	if len(b)%20 != 0 {
		return nil, fmt.Errorf("body length %d not a multiple of 20", len(b))
	}
	var out []LSAHeader
	for off := 0; off+20 <= len(b); off += 20 {
		h, _ := decodeOneLSAHeader(b[off : off+20])
		out = append(out, h)
	}
	return out, nil
}

func decodeOneLSAHeader(b []byte) (LSAHeader, error) {
	if len(b) < 20 {
		return LSAHeader{}, fmt.Errorf("LSA header truncated")
	}
	lt := int(binary.BigEndian.Uint16(b[2:4]))
	scope := (lt >> 13) & 0x07
	return LSAHeader{
		LSAge:             int(binary.BigEndian.Uint16(b[0:2])),
		LSType:            lt,
		LSTypeHex:         fmt.Sprintf("0x%04X", lt),
		LSTypeName:        lsTypeName(lt),
		FloodingScope:     scope,
		FloodingScopeName: floodingScopeName(scope),
		LinkStateID:       dottedQuad(b[4:8]),
		AdvertisingRouter: dottedQuad(b[8:12]),
		LSSequenceNumber:  int32(binary.BigEndian.Uint32(b[12:16])),
		ChecksumHex:       fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[16:18])),
		Length:            int(binary.BigEndian.Uint16(b[18:20])),
	}, nil
}

func decodeOptions(o int) Options {
	return Options{
		V6: o&0x000001 != 0,
		E:  o&0x000002 != 0,
		MC: o&0x000004 != 0,
		N:  o&0x000008 != 0,
		R:  o&0x000010 != 0,
		DC: o&0x000020 != 0,
	}
}

func typeName(t int) string {
	switch t {
	case 1:
		return "Hello"
	case 2:
		return "Database Description"
	case 3:
		return "Link State Request"
	case 4:
		return "Link State Update"
	case 5:
		return "Link State Acknowledgment"
	}
	return fmt.Sprintf("uncatalogued type %d", t)
}

func lsTypeName(lt int) string {
	switch lt & 0x1FFF {
	case 0x0001:
		return "Router-LSA"
	case 0x0002:
		return "Network-LSA"
	case 0x0003:
		return "Inter-Area-Prefix-LSA"
	case 0x0004:
		return "Inter-Area-Router-LSA"
	case 0x0005:
		return "AS-External-LSA"
	case 0x0006:
		return "Group-Membership-LSA"
	case 0x0007:
		return "Type-7-LSA (NSSA External)"
	case 0x0008:
		return "Link-LSA"
	case 0x0009:
		return "Intra-Area-Prefix-LSA"
	}
	return fmt.Sprintf("uncatalogued LS function code 0x%04X", lt&0x1FFF)
}

func floodingScopeName(s int) string {
	switch s {
	case 0:
		return "Link-Local"
	case 1:
		return "Area"
	case 2:
		return "AS"
	}
	return fmt.Sprintf("reserved scope %d", s)
}

// dottedQuad renders an OSPF 32-bit identifier (Router ID,
// Area ID, Link State ID, Advertising Router) as A.B.C.D —
// the canonical operator-visible form even when the field is
// not an IPv4 address per se.
func dottedQuad(b []byte) string {
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
