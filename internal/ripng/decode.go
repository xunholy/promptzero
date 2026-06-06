// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ripng decodes RIPng (RFC 2080) — the IPv6 distance-vector
// routing protocol (UDP 521). It is the IPv6 sibling of the project's
// internal/rip (RIPv1/v2, IPv4): a routing-reconnaissance and
// route-injection surface. RIPng has no authentication of its own, so a
// captured Response reveals the routes a router advertises (each IPv6
// prefix, its route tag and hop-count metric) and, because the protocol
// trusts any Response on the segment, an attacker on-link can inject or
// blackhole routes — decoding the advertisement is the first step of
// auditing that exposure.
//
// # Wrap-vs-native judgement
//
//	Native. RIPng is a 4-byte header (command / version / reserved)
//	followed by an array of fixed 20-byte route table entries
//	(128-bit prefix / route tag / prefix length / metric). A byte-field
//	read + an array walk; stdlib only (net for the IPv6 formatting), no
//	new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header and the route-table-entry layout — including the two
//	special entries of RFC 2080: the next-hop RTE (metric 0xFF, the
//	prefix field carries a next-hop address) and the infinity metric
//	(16, an unreachable route) — were verified field-for-field against
//	scapy's RIPng layer (scapy.contrib.ripng). Nothing is heuristically
//	guessed; every byte maps to a defined field.
package ripng

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Entry is one decoded RIPng route table entry.
type Entry struct {
	IsNextHop    bool   `json:"is_next_hop"`
	NextHop      string `json:"next_hop,omitempty"`
	Prefix       string `json:"prefix,omitempty"`
	PrefixLength int    `json:"prefix_length,omitempty"`
	RouteTag     int    `json:"route_tag,omitempty"`
	Metric       int    `json:"metric,omitempty"`
	MetricName   string `json:"metric_name,omitempty"`
}

// Result is the decoded view of a RIPng message.
type Result struct {
	Command           int      `json:"command"`
	CommandName       string   `json:"command_name"`
	Version           int      `json:"version"`
	Entries           []Entry  `json:"entries"`
	WholeTableRequest bool     `json:"whole_table_request,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

// Decode parses a RIPng message (the UDP-521 payload) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("ripng: %d bytes — too short for a RIPng header", len(b))
	}
	r := &Result{Command: int(b[0]), CommandName: commandName(b[0]), Version: int(b[1])}
	if b[0] != 1 && b[0] != 2 {
		return nil, fmt.Errorf("ripng: command %d is not request (1) or response (2)", b[0])
	}
	off := 4
	for off+20 <= len(b) {
		rte := b[off : off+20]
		off += 20
		metric := int(rte[19])
		e := Entry{RouteTag: int(binary.BigEndian.Uint16(rte[16:18])), PrefixLength: int(rte[18]), Metric: metric}
		if metric == 0xff {
			e.IsNextHop = true
			e.NextHop = net.IP(rte[0:16]).String()
			e.RouteTag, e.PrefixLength, e.Metric = 0, 0, 0
		} else {
			e.Prefix = net.IP(rte[0:16]).String()
			e.MetricName = metricName(metric)
		}
		r.Entries = append(r.Entries, e)
	}
	if off != len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf("%d trailing bytes are not a whole 20-byte route entry", len(b)-off))
	}
	// RFC 2080 §2.4.1: a request for the whole table is a single entry with
	// metric 16 (infinity) and a zero prefix / zero prefix length.
	if r.Command == 1 && len(r.Entries) == 1 {
		e := r.Entries[0]
		if e.Metric == 16 && e.PrefixLength == 0 && e.Prefix == "::" {
			r.WholeTableRequest = true
			r.Notes = append(r.Notes, "this is the RFC 2080 whole-table request (single ::/0 entry, metric 16)")
		}
	}
	if r.Command == 2 {
		r.Notes = append(r.Notes, "RIPng has no authentication: any on-link host can send a Response to inject or blackhole routes; metric 16 marks an unreachable (withdrawn) route, and a next-hop RTE (metric 0xFF) sets the gateway for the routes that follow")
	}
	return r, nil
}

func commandName(c byte) string {
	switch c {
	case 1:
		return "request"
	case 2:
		return "response"
	}
	return fmt.Sprintf("unknown(%d)", c)
}

func metricName(m int) string {
	if m == 16 {
		return "infinity (unreachable / withdrawn)"
	}
	return ""
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("ripng: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ripng: input is not valid hex: %w", err)
	}
	return b, nil
}
