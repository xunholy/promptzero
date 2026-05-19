// Package igmp decodes Internet Group Management Protocol
// packets per RFC 3376 (IGMPv3) and RFC 2236 (IGMPv2). IGMPv1
// (RFC 1112) is recognised as a degenerate v2 form. MLD (the
// IPv6 equivalent, RFC 3810) is not covered here.
//
// Wrap-vs-native judgement
//
//	Native. Both RFCs are fully public; IGMP wire format is
//	a tight 8-byte fixed header for v2 (or a slightly larger
//	header for v3 with the QRV/QQIC byte + Number of Sources
//	+ Source Addresses tail) and a per-record list for
//	IGMPv3 Membership Reports. No crypto, no compression,
//	no varints (apart from the exp+mantissa Max Resp Code
//	encoding documented in RFC 3376 §4.1.1). Operators paste
//	IGMP bytes (IP protocol number 2, multicast to 224.0.0.1
//	for General Queries or 224.0.0.22 for IGMPv3 Reports)
//	from a `tcpdump -X proto 2` line, a Wireshark Follow-IP-
//	Stream view, or any IGMP-speaking router's tcpdump and
//	get the documented header + per-version body breakdown.
//
// What this package covers
//
//   - **Version auto-detection**: Type 0x11 with body length
//     8 = IGMPv1/v2 General Query; Type 0x11 with body length
//     ≥12 = IGMPv3 Membership Query; Type 0x22 = IGMPv3
//     Membership Report; Type 0x16 = IGMPv2 Membership Report;
//     Type 0x17 = IGMPv2 Leave Group; Type 0x12 = IGMPv1
//     Membership Report (legacy).
//
//   - **IGMPv2 fixed 8-byte header** (RFC 2236 §2):
//
//   - byte 0: **Type** with **5-entry name table**:
//     0x11 Membership Query, 0x12 IGMPv1 Membership
//     Report, 0x16 IGMPv2 Membership Report, 0x17 Leave
//     Group, 0x22 IGMPv3 Membership Report (dispatched
//     separately).
//
//   - byte 1: Max Resp Time (1/10 seconds for v2; encoded
//     Max Resp Code for v3 Query — see §4.1.1).
//
//   - bytes 2-3: Checksum (uint16 BE, hex-formatted).
//
//   - bytes 4-7: Group Address (4 bytes IPv4; 0.0.0.0 for
//     General Query).
//
//   - **IGMPv3 Query body extension** (RFC 3376 §4.1):
//
//   - byte 8: 4-bit Resv + 1-bit **S** (Suppress Router-
//     Side processing flag) + 3-bit **QRV** (Querier's
//     Robustness Variable; default 2)
//
//   - byte 9: **QQIC** (Querier's Query Interval Code —
//     same exp+mantissa encoding as Max Resp Code)
//
//   - bytes 10-11: Number of Sources (uint16 BE)
//
//   - N × 4 bytes: Source Addresses
//
//   - **IGMPv3 Membership Report body** (RFC 3376 §4.2):
//
//   - bytes 4-5: Reserved
//
//   - bytes 6-7: Number of Group Records (uint16 BE)
//
//   - Group Records (variable; each is 8-byte fixed
//     header + N source addresses + Aux Data):
//
//   - byte 0: **Record Type** with **6-entry name
//     table**: 1 MODE_IS_INCLUDE, 2 MODE_IS_EXCLUDE,
//     3 CHANGE_TO_INCLUDE_MODE, 4 CHANGE_TO_EXCLUDE_
//     MODE, 5 ALLOW_NEW_SOURCES, 6 BLOCK_OLD_SOURCES.
//
//   - byte 1: Aux Data Len (in 4-byte words; should
//     be 0 per RFC 3376).
//
//   - bytes 2-3: Number of Sources (uint16 BE).
//
//   - bytes 4-7: Multicast Address (IPv4).
//
//   - N × 4 bytes: Source Addresses.
//
//   - Aux Data Len × 4 bytes: Auxiliary Data
//     (deprecated; surfaced as raw hex).
//
//   - **Max Resp Code exp+mantissa encoding** (RFC 3376
//     §4.1.1) — when the byte value is < 128 it's the
//     direct centisecond count; when ≥ 128 it's split as
//     0x80 | (exp<<4) | mant → (mant | 0x10) << (exp + 3).
//     Surfaced both as the encoded byte and the decoded
//     value in centiseconds + milliseconds.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IP framing — feed IGMP bytes after the IPv4 header
//     strip. IGMP runs over IP protocol 2.
//
//   - MLD (Multicast Listener Discovery, RFC 3810) — the
//     IPv6 equivalent of IGMP; uses ICMPv6 type 130-132 and
//     143 (already partially decoded by
//     `icmp_packet_decode`); a future Spec would walk MLDv2.
//
//   - IGMP Router-Side state machine — Query intervals,
//     Robustness Variable retries, group-membership
//     timeout reasoning — that's higher-level analysis.
//
//   - IP Router Alert option (RFC 2113) — IGMP packets
//     should have it; checked at the IP layer.
package igmp

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
	TypeHex     string `json:"type_hex"`
	TypeName    string `json:"type_name"`
	ChecksumHex string `json:"checksum_hex"`
	TotalBytes  int    `json:"total_bytes"`

	// v1/v2 + v3 query common
	GroupAddress string `json:"group_address,omitempty"`

	// Max Resp Code encoding
	MaxRespCodeRaw int `json:"max_resp_code_raw,omitempty"`
	MaxRespCs      int `json:"max_resp_centiseconds,omitempty"`
	MaxRespMs      int `json:"max_resp_ms,omitempty"`

	// v3 Query extension
	SuppressRouterSide *bool    `json:"s_suppress_router_side,omitempty"`
	QRV                *int     `json:"qrv_querier_robustness,omitempty"`
	QQICRaw            *int     `json:"qqic_raw,omitempty"`
	QQICCs             *int     `json:"qqic_centiseconds,omitempty"`
	QQICMs             *int     `json:"qqic_ms,omitempty"`
	NumberOfSources    *int     `json:"number_of_sources,omitempty"`
	SourceAddresses    []string `json:"source_addresses,omitempty"`

	// v3 Report
	NumberOfGroupRecords *int          `json:"number_of_group_records,omitempty"`
	GroupRecords         []GroupRecord `json:"group_records,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// GroupRecord is one record inside an IGMPv3 Membership Report.
type GroupRecord struct {
	RecordType       int      `json:"record_type"`
	RecordTypeName   string   `json:"record_type_name"`
	AuxDataLengthW   int      `json:"aux_data_length_words"`
	NumberOfSources  int      `json:"number_of_sources"`
	MulticastAddress string   `json:"multicast_address"`
	SourceAddresses  []string `json:"source_addresses,omitempty"`
	AuxDataHex       string   `json:"aux_data_hex,omitempty"`
}

// Decode parses a single IGMP packet from hex.
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
	if len(b) < 8 {
		return nil, fmt.Errorf("IGMP packet truncated (%d bytes; need ≥8)", len(b))
	}

	r := &Result{
		TotalBytes:  len(b),
		Type:        int(b[0]),
		TypeHex:     fmt.Sprintf("0x%02X", b[0]),
		ChecksumHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[2:4])),
	}
	r.TypeName = typeName(r.Type)

	switch r.Type {
	case 0x11: // Membership Query (v1/v2/v3)
		if len(b) >= 12 {
			r.Version = 3
		} else {
			r.Version = 2
		}
		raw := int(b[1])
		r.MaxRespCodeRaw = raw
		r.MaxRespCs = decodeMaxRespCode(raw)
		r.MaxRespMs = r.MaxRespCs * 10
		r.GroupAddress = ipv4String(b[4:8])
		if r.Version == 3 {
			s := b[8]&0x08 != 0
			qrv := int(b[8] & 0x07)
			qqicRaw := int(b[9])
			qqicCs := decodeMaxRespCode(qqicRaw)
			qqicMs := qqicCs * 10
			nos := int(binary.BigEndian.Uint16(b[10:12]))
			r.SuppressRouterSide = &s
			r.QRV = &qrv
			r.QQICRaw = &qqicRaw
			r.QQICCs = &qqicCs
			r.QQICMs = &qqicMs
			r.NumberOfSources = &nos
			for i := 0; i < nos; i++ {
				off := 12 + i*4
				if off+4 > len(b) {
					break
				}
				r.SourceAddresses = append(r.SourceAddresses,
					ipv4String(b[off:off+4]))
			}
		}
	case 0x22: // IGMPv3 Membership Report
		r.Version = 3
		if len(b) < 8 {
			return nil, fmt.Errorf("IGMPv3 Report truncated (%d; need ≥8)", len(b))
		}
		nor := int(binary.BigEndian.Uint16(b[6:8]))
		r.NumberOfGroupRecords = &nor
		off := 8
		for i := 0; i < nor && off+8 <= len(b); i++ {
			rec, used, err := decodeGroupRecord(b[off:])
			if err != nil {
				return nil, fmt.Errorf("group record %d: %w", i, err)
			}
			r.GroupRecords = append(r.GroupRecords, rec)
			off += used
		}
	case 0x12: // IGMPv1 Membership Report
		r.Version = 1
		r.GroupAddress = ipv4String(b[4:8])
	case 0x16: // IGMPv2 Membership Report
		r.Version = 2
		raw := int(b[1])
		r.MaxRespCodeRaw = raw
		r.MaxRespCs = raw
		r.MaxRespMs = raw * 100
		r.GroupAddress = ipv4String(b[4:8])
	case 0x17: // Leave Group (v2)
		r.Version = 2
		r.GroupAddress = ipv4String(b[4:8])
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"uncatalogued IGMP Type 0x%02X (RFC 2236 + 3376 define 0x11/0x12/0x16/0x17/0x22)",
			r.Type))
	}
	return r, nil
}

func decodeGroupRecord(b []byte) (GroupRecord, int, error) {
	if len(b) < 8 {
		return GroupRecord{}, 0, fmt.Errorf("record header truncated (%d; need ≥8)",
			len(b))
	}
	rec := GroupRecord{
		RecordType:       int(b[0]),
		AuxDataLengthW:   int(b[1]),
		NumberOfSources:  int(binary.BigEndian.Uint16(b[2:4])),
		MulticastAddress: ipv4String(b[4:8]),
	}
	rec.RecordTypeName = recordTypeName(rec.RecordType)
	off := 8
	for i := 0; i < rec.NumberOfSources; i++ {
		if off+4 > len(b) {
			return rec, off, fmt.Errorf("source %d truncated", i)
		}
		rec.SourceAddresses = append(rec.SourceAddresses,
			ipv4String(b[off:off+4]))
		off += 4
	}
	auxBytes := rec.AuxDataLengthW * 4
	if off+auxBytes > len(b) {
		return rec, off, fmt.Errorf("aux data truncated")
	}
	if auxBytes > 0 {
		rec.AuxDataHex = strings.ToUpper(hex.EncodeToString(b[off : off+auxBytes]))
	}
	off += auxBytes
	return rec, off, nil
}

// decodeMaxRespCode applies the RFC 3376 §4.1.1 exp+mantissa
// encoding: if value < 128, it's the direct centisecond count;
// otherwise it's split as 0x80 | (exp<<4) | mant → (mant | 0x10)
// << (exp + 3) centiseconds.
func decodeMaxRespCode(v int) int {
	if v < 128 {
		return v
	}
	exp := (v >> 4) & 0x07
	mant := v & 0x0F
	return (mant | 0x10) << (exp + 3)
}

func typeName(t int) string {
	switch t {
	case 0x11:
		return "Membership Query"
	case 0x12:
		return "IGMPv1 Membership Report"
	case 0x16:
		return "IGMPv2 Membership Report"
	case 0x17:
		return "IGMPv2 Leave Group"
	case 0x22:
		return "IGMPv3 Membership Report"
	}
	return fmt.Sprintf("uncatalogued type 0x%02X", t)
}

func recordTypeName(rt int) string {
	switch rt {
	case 1:
		return "MODE_IS_INCLUDE"
	case 2:
		return "MODE_IS_EXCLUDE"
	case 3:
		return "CHANGE_TO_INCLUDE_MODE"
	case 4:
		return "CHANGE_TO_EXCLUDE_MODE"
	case 5:
		return "ALLOW_NEW_SOURCES"
	case 6:
		return "BLOCK_OLD_SOURCES"
	}
	return fmt.Sprintf("uncatalogued record type %d", rt)
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
