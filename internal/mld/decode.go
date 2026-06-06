// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mld decodes MLD — Multicast Listener Discovery — the IPv6
// multicast-group membership protocol carried in ICMPv6: MLDv1 (RFC 2710)
// and MLDv2 (RFC 3810). MLD is the IPv6 counterpart of IGMP: a host emits an
// MLD Report to tell the on-link router which IPv6 multicast groups it wants
// to receive, and routers emit Queries to refresh that state. It is a
// network-reconnaissance source — an MLD Report reveals exactly which
// multicast groups a host has joined (and, via the MLDv2 source-filter
// records, which senders it includes or excludes), exposing the host's
// multicast-based services: mDNS / Bonjour (ff02::fb), LLMNR (ff02::1:3),
// SSDP / UPnP, the all-DHCP-servers group, PTP, and IPTV / streaming groups.
// An MLD Query reveals the active querier and its robustness / interval
// parameters. It is the IPv6 companion to the project's internal/igmp (v1/v2)
// and internal/igmpv3 (IPv4 multicast), and the MLD member of the ICMPv6
// family alongside internal/ndp.
//
// # Wrap-vs-native judgement
//
//	Native. MLD is a small ICMPv6 message: a fixed header + a multicast
//	address, and for MLDv2 either a source list (Query) or a list of group
//	records (each a fixed header + an array of 16-byte source addresses,
//	Report). A byte-field read + two walks; stdlib only (net for the IPv6
//	formatting), no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The MLDv1 Query / Report / Done layout, the MLDv2 Query (with the
//	S / QRV / QQIC fields and source list) and the MLDv2 Report group-record
//	array were verified field-for-field against scapy's MLD layers
//	(ICMPv6MLQuery / ICMPv6MLReport / ICMPv6MLDone / ICMPv6MLQuery2 /
//	ICMPv6MLReport2 / ICMPv6MLDMultAddrRec) and RFC 2710 / RFC 3810. The MLDv2
//	Maximum-Response-Code and QQIC floating-point encodings (RFC 3810 §5.1.3 /
//	§5.1.9) are decoded. The ICMPv6 checksum is computed over an IPv6
//	pseudo-header that is not present in a bare MLD capture, so it is surfaced
//	as raw hex without a validity claim (matching internal/ndp). A type 130
//	Query is dispatched to MLDv1 vs MLDv2 by length (RFC 3810 §8.1: an MLDv2
//	Query is ≥ 28 bytes). A non-MLD ICMPv6 type is rejected.
package mld

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the decoded view of an MLD (Multicast Listener Discovery) message.
type Result struct {
	Type        int    `json:"type"`
	TypeName    string `json:"type_name"`
	Code        int    `json:"code"`
	ChecksumHex string `json:"checksum_hex"`
	MLDVersion  int    `json:"mld_version,omitempty"`

	// Query / v1 Report / v1 Done
	MaxResponseDelayMs int    `json:"max_response_delay_ms,omitempty"`
	MulticastAddress   string `json:"multicast_address,omitempty"`
	GeneralQuery       bool   `json:"general_query,omitempty"`

	// MLDv2 Query extras
	SuppressRouterProcessing bool     `json:"suppress_router_side_processing,omitempty"`
	QRV                      int      `json:"qrv,omitempty"`
	QQICSeconds              int      `json:"qqic_seconds,omitempty"`
	QuerierSources           []string `json:"querier_sources,omitempty"`

	// MLDv2 Report
	Records []GroupRecord `json:"records,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// GroupRecord is one MLDv2 multicast address record from a Report.
type GroupRecord struct {
	RecordType       int      `json:"record_type"`
	RecordTypeName   string   `json:"record_type_name"`
	MulticastAddress string   `json:"multicast_address"`
	Sources          []string `json:"sources,omitempty"`
	AuxDataHex       string   `json:"aux_data_hex,omitempty"`
}

// Decode parses an MLD message (the ICMPv6 payload, starting at the ICMPv6
// Type byte) from hex (whitespace / ':' / '-' / '_' separators and a '0x'
// prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("mld: %d bytes — too short for the 4-byte ICMPv6 header", len(b))
	}
	typ := b[0]
	name := typeName(typ)
	if name == "" {
		return nil, fmt.Errorf("mld: ICMPv6 type %d is not an MLD message (130 Query / 131 Report / 132 Done / 143 v2 Report)", typ)
	}
	r := &Result{
		Type:        int(typ),
		TypeName:    name,
		Code:        int(b[1]),
		ChecksumHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[2:4])),
	}

	switch typ {
	case 143: // MLDv2 Report (RFC 3810 §5.2)
		r.MLDVersion = 2
		if err := decodeV2Report(r, b); err != nil {
			return nil, err
		}
	case 130: // Query — MLDv1 (24 bytes) or MLDv2 (≥ 28 bytes)
		if len(b) < 24 {
			return nil, fmt.Errorf("mld: Query is %d bytes — too short (need ≥24)", len(b))
		}
		r.MaxResponseDelayMs = mldv1MaxResp(binary.BigEndian.Uint16(b[4:6]))
		r.MulticastAddress = net.IP(b[8:24]).String()
		r.GeneralQuery = isUnspecified(b[8:24])
		if len(b) >= 28 { // MLDv2 Query
			r.MLDVersion = 2
			r.MaxResponseDelayMs = mldv2MaxResp(binary.BigEndian.Uint16(b[4:6]))
			r.SuppressRouterProcessing = b[24]&0x08 != 0
			r.QRV = int(b[24] & 0x07)
			r.QQICSeconds = decodeFloat8(b[25])
			n := int(binary.BigEndian.Uint16(b[26:28]))
			for i := 0; i < n; i++ {
				off := 28 + i*16
				if off+16 > len(b) {
					break
				}
				r.QuerierSources = append(r.QuerierSources, net.IP(b[off:off+16]).String())
			}
		} else {
			r.MLDVersion = 1
		}
	case 131, 132: // MLDv1 Report / Done (RFC 2710)
		r.MLDVersion = 1
		if len(b) < 24 {
			return nil, fmt.Errorf("mld: %s is %d bytes — too short (need 24)", name, len(b))
		}
		r.MulticastAddress = net.IP(b[8:24]).String()
	}

	r.Notes = append(r.Notes, "MLD — IPv6 multicast listener discovery (ICMPv6); a Report names the multicast groups the host has joined (mDNS ff02::fb, LLMNR ff02::1:3, SSDP, …) — multicast-service recon")
	if r.GeneralQuery {
		r.Notes = append(r.Notes, "general query (multicast address ::) — refreshes membership for all groups on the link")
	}
	return r, nil
}

func decodeV2Report(r *Result, b []byte) error {
	if len(b) < 8 {
		return fmt.Errorf("mld: MLDv2 Report is %d bytes — too short (need ≥8)", len(b))
	}
	n := int(binary.BigEndian.Uint16(b[6:8]))
	off := 8
	for i := 0; i < n; i++ {
		if off+20 > len(b) {
			break
		}
		rtype := b[off]
		auxLen := int(b[off+1]) // in 32-bit words
		nsrc := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		rec := GroupRecord{
			RecordType:       int(rtype),
			RecordTypeName:   recordTypeName(rtype),
			MulticastAddress: net.IP(b[off+4 : off+20]).String(),
		}
		p := off + 20
		for s := 0; s < nsrc; s++ {
			if p+16 > len(b) {
				break
			}
			rec.Sources = append(rec.Sources, net.IP(b[p:p+16]).String())
			p += 16
		}
		if auxLen > 0 && p+auxLen*4 <= len(b) {
			rec.AuxDataHex = strings.ToUpper(hex.EncodeToString(b[p : p+auxLen*4]))
			p += auxLen * 4
		}
		r.Records = append(r.Records, rec)
		off = p
	}
	return nil
}

// mldv1MaxResp: MLDv1 Maximum Response Delay is a plain 16-bit millisecond
// value (RFC 2710 §3.4).
func mldv1MaxResp(code uint16) int { return int(code) }

// mldv2MaxResp decodes the MLDv2 Maximum Response Code (RFC 3810 §5.1.3): a
// value < 0x8000 is milliseconds directly; otherwise a (mant, exp) float.
func mldv2MaxResp(code uint16) int {
	if code < 0x8000 {
		return int(code)
	}
	mant := int(code & 0x0FFF)
	exp := int((code >> 12) & 0x7)
	return (mant | 0x1000) << (exp + 3)
}

// decodeFloat8 decodes the 8-bit QQIC float code (RFC 3810 §5.1.9): a value
// < 128 is the value directly; otherwise a (mant, exp) float, in seconds.
func decodeFloat8(c byte) int {
	if c < 0x80 {
		return int(c)
	}
	mant := int(c & 0x0F)
	exp := int((c >> 4) & 0x07)
	return (mant | 0x10) << (exp + 3)
}

func isUnspecified(ip []byte) bool {
	for _, x := range ip {
		if x != 0 {
			return false
		}
	}
	return true
}

func typeName(t byte) string {
	switch t {
	case 130:
		return "Multicast_Listener_Query"
	case 131:
		return "Multicast_Listener_Report" // MLDv1
	case 132:
		return "Multicast_Listener_Done"
	case 143:
		return "Multicast_Listener_Report_v2"
	}
	return ""
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

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("mld: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("mld: input is not valid hex: %w", err)
	}
	return b, nil
}
