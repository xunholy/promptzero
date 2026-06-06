// SPDX-License-Identifier: AGPL-3.0-or-later

// Package erspan decodes the ERSPAN (Encapsulated Remote SPAN) header —
// Cisco's protocol for carrying a port-mirror (SPAN) session across a
// routed network inside a GRE tunnel. Seeing ERSPAN in a capture is
// itself a finding: it means traffic on some switch is being mirrored
// and shipped elsewhere (lawful intercept, an IDS feed, or an attacker's
// exfiltration of mirrored traffic), and the encapsulated payload is the
// original mirrored Ethernet frame in the clear — so an ERSPAN capture
// both exposes the monitoring topology (session id, source VLAN) and
// lets the mirrored frame be peeled out for further analysis. It pairs
// with internal/gre (the tunnel that carries it) and the other L2
// decoders.
//
// # Wrap-vs-native judgement
//
//	Native. The ERSPAN header is a fixed bitfield — Type II is 8
//	octets, Type III is 12 — defined in the public ERSPAN spec
//	(draft-foschiano-erspan) and carried as the GRE payload with
//	protocol type 0x88BE (II) or 0x22EB (III). Decoding is bit-masking
//	a few words — a dependency is not justified. stdlib only, no new
//	go.mod dep.
//
// # What this package covers / verifiable
//
//	The Type II and Type III headers — version, source VLAN, class of
//	service, the truncated flag, the session id, and (II) the
//	port index / (III) the 32-bit timestamp — verified field-for-field
//	against scapy's ERSPAN_II / ERSPAN_III layers. The encapsulated
//	mirrored Ethernet frame is surfaced as raw hex (it can be fed to
//	the relevant L2/L3 decoder). The Type III platform-specific
//	sub-header flags beyond the timestamp are left in the raw
//	remainder rather than decoded into possibly-wrong fields.
package erspan

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an ERSPAN header.
type Result struct {
	Version   int    `json:"version"`
	Type      string `json:"type"` // "Type II" / "Type III"
	VLAN      int    `json:"vlan"`
	COS       int    `json:"cos"`
	Truncated bool   `json:"truncated"`
	SessionID int    `json:"session_id"`

	// Type II only.
	EncapType *int `json:"encap_type,omitempty"`
	Index     *int `json:"index,omitempty"`
	// Type III only.
	Timestamp *uint32 `json:"timestamp,omitempty"`

	MirroredFrameHex string   `json:"mirrored_frame_hex,omitempty"`
	Notes            []string `json:"notes,omitempty"`
}

const (
	greProtoERSPANII  = 0x88BE
	greProtoERSPANIII = 0x22EB
)

// Decode parses an ERSPAN header. The input is hex (whitespace / ':' /
// '-' / '_' separators and a '0x' prefix tolerated). It may begin at the
// ERSPAN header, or be a GRE packet (protocol 0x88BE / 0x22EB) whose
// payload is ERSPAN — the GRE header is then stripped.
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	// Strip a GRE header if this is a GRE-encapsulated ERSPAN packet.
	if len(b) >= 4 {
		proto := int(binary.BigEndian.Uint16(b[2:4]))
		if proto == greProtoERSPANII || proto == greProtoERSPANIII {
			if hdr := greHeaderLen(b[0]); hdr <= len(b) {
				b = b[hdr:]
			}
		}
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("erspan: %d bytes — too short for an ERSPAN header (min 8)", len(b))
	}
	ver := int(b[0] >> 4)
	r := &Result{Version: ver}
	switch ver {
	case 1:
		r.Type = "Type II"
		r.VLAN = int(binary.BigEndian.Uint16(b[0:2]) & 0x0FFF)
		w := binary.BigEndian.Uint16(b[2:4])
		r.COS = int(w>>13) & 0x07
		en := int(w>>11) & 0x03
		r.EncapType = &en
		r.Truncated = w&0x0400 != 0
		r.SessionID = int(w & 0x03FF)
		idx := int(binary.BigEndian.Uint32(b[4:8]) & 0x000FFFFF)
		r.Index = &idx
		r.MirroredFrameHex = strings.ToUpper(hex.EncodeToString(b[8:]))
	case 2:
		r.Type = "Type III"
		if len(b) < 12 {
			return nil, fmt.Errorf("erspan: Type III header truncated (%d bytes, need 12)", len(b))
		}
		r.VLAN = int(binary.BigEndian.Uint16(b[0:2]) & 0x0FFF)
		w := binary.BigEndian.Uint16(b[2:4])
		r.COS = int(w>>13) & 0x07
		r.Truncated = w&0x0400 != 0
		r.SessionID = int(w & 0x03FF)
		ts := binary.BigEndian.Uint32(b[4:8])
		r.Timestamp = &ts
		r.MirroredFrameHex = strings.ToUpper(hex.EncodeToString(b[12:]))
		r.Notes = append(r.Notes, "Type III platform-specific sub-header flags (bytes 8-11) beyond the timestamp are left in the raw remainder, not decoded")
	default:
		return nil, fmt.Errorf("erspan: version %d is not ERSPAN Type II (1) or Type III (2)", ver)
	}
	r.Notes = append(r.Notes,
		"the mirrored Ethernet frame is surfaced as hex (feed it to the relevant L2/L3 decoder)",
		"ERSPAN means a SPAN/port-mirror session is exporting traffic over GRE — note the monitoring topology (session id + source VLAN)")
	return r, nil
}

// greHeaderLen returns the GRE header length for the given GRE flags
// octet: a 4-octet base, +4 for a checksum (C), +4 for a key (K), +4 for
// a sequence number (S). ERSPAN GRE always sets S.
func greHeaderLen(flags byte) int {
	n := 4
	if flags&0x80 != 0 { // C
		n += 4
	}
	if flags&0x20 != 0 { // K
		n += 4
	}
	if flags&0x10 != 0 { // S
		n += 4
	}
	return n
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("erspan: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("erspan: input is not valid hex: %w", err)
	}
	return b, nil
}
