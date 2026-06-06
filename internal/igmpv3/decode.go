// SPDX-License-Identifier: AGPL-3.0-or-later

// Package igmpv3 decodes IGMPv3 (RFC 3376) — the IPv4 multicast group
// membership protocol, version 3. It is a network-reconnaissance source:
// an IGMPv3 Membership Report reveals exactly which multicast groups a
// host has joined and, via the source-filter records (INCLUDE / EXCLUDE
// mode), which senders it accepts or blocks — exposing the host's
// multicast-based services (mDNS 224.0.0.251, SSDP 239.255.255.250, PTP,
// streaming / IPTV groups), while a Membership Query reveals the active
// querier and its robustness / interval parameters. It is the v3
// companion to the project's internal/igmp (v1/v2), whose group-record
// and source-list structure is different enough to warrant its own
// decoder.
//
// # Wrap-vs-native judgement
//
//	Native. IGMPv3 is a fixed header followed by either a source list
//	(Query) or a list of group records, each a fixed header + an array
//	of 4-byte source addresses (Report). A byte-field read + two TLV-ish
//	walks; stdlib only (net for the IPv4 formatting), no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The Query and v3 Report layouts (including the group-record array
//	and the Max-Resp-Code / QQIC floating-point encoding of RFC 3376
//	§4.1) were verified field-for-field against scapy's IGMPv3 layer
//	(scapy.contrib.igmpv3). The 16-bit one's-complement checksum is
//	verified and surfaced as checksum_valid. Auxiliary record data
//	(rare, non-standard) is surfaced as raw hex.
package igmpv3

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// GroupRecord is one IGMPv3 group record from a Membership Report.
type GroupRecord struct {
	RecordType       int      `json:"record_type"`
	RecordTypeName   string   `json:"record_type_name"`
	AuxDataLen       int      `json:"aux_data_len"`
	NumSources       int      `json:"num_sources"`
	MulticastAddress string   `json:"multicast_address"`
	Sources          []string `json:"sources,omitempty"`
	AuxDataHex       string   `json:"aux_data_hex,omitempty"`
}

// Result is the decoded view of an IGMPv3 message.
type Result struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Checksum uint16 `json:"checksum"`
	CRCValid bool   `json:"checksum_valid"`

	// Query (type 0x11).
	MaxRespCode        *int   `json:"max_resp_code,omitempty"`
	MaxRespTimeMS      *int   `json:"max_resp_time_ms,omitempty"`
	GroupAddress       string `json:"group_address,omitempty"`
	QueryType          string `json:"query_type,omitempty"`
	SuppressRouterSide *bool  `json:"suppress_router_side_processing,omitempty"`
	QRV                *int   `json:"querier_robustness_variable,omitempty"`
	QQIC               *int   `json:"qqic,omitempty"`
	QQISeconds         *int   `json:"querier_query_interval_seconds,omitempty"`

	// Report (type 0x22).
	NumRecords int           `json:"num_records,omitempty"`
	Records    []GroupRecord `json:"records,omitempty"`

	Sources []string `json:"sources,omitempty"` // Query source list.
	Notes   []string `json:"notes,omitempty"`
}

// Decode parses an IGMPv3 message from hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("igmpv3: %d bytes — too short for an IGMPv3 message", len(b))
	}
	r := &Result{Type: int(b[0]), TypeName: typeName(b[0])}
	switch b[0] {
	case 0x11:
		r.Checksum = binary.BigEndian.Uint16(b[2:4])
		r.CRCValid = checksum(b) == 0
		if err := decodeQuery(r, b); err != nil {
			return nil, err
		}
	case 0x22:
		r.Checksum = binary.BigEndian.Uint16(b[2:4])
		r.CRCValid = checksum(b) == 0
		if err := decodeReport(r, b); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("igmpv3: type 0x%02x is not an IGMPv3 Query (0x11) or v3 Report (0x22)", b[0])
	}
	if !r.CRCValid {
		r.Notes = append(r.Notes, "checksum does not verify — the capture may be truncated or corrupt")
	}
	return r, nil
}

func decodeQuery(r *Result, b []byte) error {
	if len(b) < 12 {
		return fmt.Errorf("igmpv3: Query truncated (%d bytes, need >= 12)", len(b))
	}
	code := int(b[1])
	r.MaxRespCode = &code
	mrt := decodeFloat(b[1]) // units of 1/10 s
	ms := mrt * 100
	r.MaxRespTimeMS = &ms
	r.GroupAddress = net.IP(b[4:8]).String()
	s := b[8]&0x08 != 0
	qrv := int(b[8] & 0x07)
	r.SuppressRouterSide, r.QRV = &s, &qrv
	qqic := int(b[9])
	r.QQIC = &qqic
	qqi := decodeFloat(b[9])
	r.QQISeconds = &qqi
	num := int(binary.BigEndian.Uint16(b[10:12]))
	off := 12
	for i := 0; i < num && off+4 <= len(b); i++ {
		r.Sources = append(r.Sources, net.IP(b[off:off+4]).String())
		off += 4
	}
	switch {
	case r.GroupAddress == "0.0.0.0":
		r.QueryType = "general"
	case num == 0:
		r.QueryType = "group-specific"
	default:
		r.QueryType = "group-and-source-specific"
	}
	return nil
}

func decodeReport(r *Result, b []byte) error {
	r.NumRecords = int(binary.BigEndian.Uint16(b[6:8]))
	off := 8
	for i := 0; i < r.NumRecords; i++ {
		if off+8 > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf("record %d truncated", i))
			break
		}
		gr := GroupRecord{
			RecordType:     int(b[off]),
			RecordTypeName: recordTypeName(b[off]),
			AuxDataLen:     int(b[off+1]),
			NumSources:     int(binary.BigEndian.Uint16(b[off+2 : off+4])),
		}
		gr.MulticastAddress = net.IP(b[off+4 : off+8]).String()
		off += 8
		for s := 0; s < gr.NumSources && off+4 <= len(b); s++ {
			gr.Sources = append(gr.Sources, net.IP(b[off:off+4]).String())
			off += 4
		}
		auxBytes := gr.AuxDataLen * 4 // aux data length is in 32-bit words
		if auxBytes > 0 && off+auxBytes <= len(b) {
			gr.AuxDataHex = strings.ToUpper(hex.EncodeToString(b[off : off+auxBytes]))
			off += auxBytes
		}
		r.Records = append(r.Records, gr)
	}
	return nil
}

// decodeFloat implements the RFC 3376 §4.1.1 / §4.1.7 code encoding used
// by both Max Resp Code and QQIC: values < 128 are literal; values >= 128
// are a (mant, exp) float = (0x10 | mant) << (exp + 3).
func decodeFloat(c byte) int {
	if c < 128 {
		return int(c)
	}
	mant := int(c & 0x0f)
	exp := int((c >> 4) & 0x07)
	return (mant | 0x10) << (exp + 3)
}

func typeName(t byte) string {
	switch t {
	case 0x11:
		return "Membership Query"
	case 0x22:
		return "Version 3 Membership Report"
	}
	return fmt.Sprintf("0x%02x", t)
}

func recordTypeName(t byte) string {
	switch t {
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
	return fmt.Sprintf("unknown(%d)", t)
}

// checksum returns the 16-bit one's-complement sum of the message; 0 means valid.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("igmpv3: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("igmpv3: input is not valid hex: %w", err)
	}
	return b, nil
}
