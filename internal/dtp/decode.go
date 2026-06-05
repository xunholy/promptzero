// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dtp decodes Cisco's Dynamic Trunking Protocol — the Layer-2
// protocol a Cisco switch port uses to negotiate whether a link becomes
// an 802.1Q/ISL trunk. DTP is the basis of the classic VLAN-hopping
// attack: a port left in a negotiating mode (dynamic desirable / dynamic
// auto, the default on many switches) can be talked into forming a trunk
// by a rogue host, giving it reach into every VLAN. Decoding a captured
// DTP frame surfaces the VTP domain name, the neighbour's MAC and the
// raw trunk-negotiation status — the reconnaissance a switch-security
// audit needs. It joins the project's other switch / Layer-2 decoders
// (internal/cdp, lldp, stp, lacp, vlan, macsec).
//
// # Wrap-vs-native judgement
//
//	Native. A DTP PDU is a one-octet version followed by 4-octet-header
//	TLVs (type + length + value), carried in an LLC/SNAP frame (OUI
//	0x00000C, PID 0x2004) to the Cisco 01:00:0C:CC:CC:CC multicast.
//	Decoding is a short TLV walk — a dependency is not justified.
//	stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The PDU structure — the version and the Domain / Status / DTP-Type
//	/ Neighbour TLVs — is fully decoded and was verified field-for-
//	field against scapy's DTP layer. DTP is a Cisco-proprietary,
//	reverse-engineered protocol whose status-byte bit semantics
//	(the exact dynamic-desirable vs dynamic-auto vs trunk encoding)
//	are not authoritatively standardised, so the status and trunk-type
//	octets are surfaced RAW (hex + decimal) rather than decoded into a
//	named mode that could be wrong. What IS certain — and stated — is
//	that the presence of DTP means the port is participating in trunk
//	negotiation (it is not in "nonegotiate"), which is the prerequisite
//	for the DTP VLAN-hopping attack.
package dtp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a DTP PDU.
type Result struct {
	Version      int      `json:"version"`
	Domain       string   `json:"domain,omitempty"` // the VTP/DTP domain name (an info leak)
	StatusByte   int      `json:"status_byte"`
	StatusHex    string   `json:"status_hex"`
	TrunkType    int      `json:"trunk_type_byte"`
	TrunkTypeHex string   `json:"trunk_type_hex"`
	NeighborMAC  string   `json:"neighbor_mac,omitempty"`
	UnknownTLVs  []TLV    `json:"unknown_tlvs,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// TLV is an unrecognised DTP TLV, surfaced raw.
type TLV struct {
	Type     int    `json:"type"`
	ValueHex string `json:"value_hex"`
}

// snapSig is the SNAP OUI (Cisco 0x00000C) + PID (DTP 0x2004) that
// prefixes a DTP PDU inside an LLC/SNAP frame.
var snapSig = []byte{0x00, 0x00, 0x0C, 0x20, 0x04}

// Decode parses a DTP PDU. The input is hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated). It may be the PDU itself
// (starting at the version octet), or any frame containing the LLC/SNAP
// DTP signature (OUI 0x00000C, PID 0x2004) — the bytes after the
// signature are then decoded.
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	// If the SNAP DTP signature is present, the PDU follows it.
	if i := indexOf(b, snapSig); i >= 0 {
		b = b[i+len(snapSig):]
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("dtp: empty PDU")
	}
	r := &Result{Version: int(b[0]), StatusHex: "0x00", TrunkTypeHex: "0x00"}
	off := 1
	sawTLV := false
	for off+4 <= len(b) {
		typ := int(binary.BigEndian.Uint16(b[off:]))
		length := int(binary.BigEndian.Uint16(b[off+2:]))
		if length < 4 || off+length > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf("malformed TLV at offset %d (declared length %d) — stopping", off, length))
			break
		}
		val := b[off+4 : off+length]
		sawTLV = true
		switch typ {
		case 0x0001: // Domain (VTP domain name)
			r.Domain = strings.TrimRight(string(val), "\x00")
		case 0x0002: // Trunk status
			if len(val) >= 1 {
				r.StatusByte = int(val[0])
				r.StatusHex = fmt.Sprintf("0x%02X", val[0])
			}
		case 0x0003: // DTP / trunk type
			if len(val) >= 1 {
				r.TrunkType = int(val[0])
				r.TrunkTypeHex = fmt.Sprintf("0x%02X", val[0])
			}
		case 0x0004: // Neighbour MAC
			if len(val) == 6 {
				r.NeighborMAC = macAddr(val)
			}
		default:
			r.UnknownTLVs = append(r.UnknownTLVs, TLV{Type: typ, ValueHex: strings.ToUpper(hex.EncodeToString(val))})
		}
		off += length
	}
	if !sawTLV {
		return nil, fmt.Errorf("dtp: no TLVs found after the version octet — not a DTP PDU")
	}
	r.Notes = append(r.Notes,
		"the presence of DTP means the port is participating in trunk negotiation (not in 'nonegotiate'), the prerequisite for the DTP VLAN-hopping attack — confirm the port mode on the switch",
		"the status and trunk-type octets are surfaced raw: DTP is Cisco-proprietary and its status-bit semantics are not authoritatively standardised, so they are not decoded into a named mode (no confidently-wrong guess)")
	return r, nil
}

func macAddr(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("dtp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("dtp: input is not valid hex: %w", err)
	}
	return b, nil
}
