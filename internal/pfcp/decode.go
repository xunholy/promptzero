// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pfcp decodes the Packet Forwarding Control Protocol (3GPP
// TS 29.244) — the control protocol of the N4 interface (5G SMF↔UPF) and
// the 4G Sxa/Sxb/Sxc CUPS interfaces, by which the control plane programs
// the user-plane function's packet-forwarding rules (PDRs / FARs / QERs /
// URRs) over UDP 8805. PFCP is a recognised 5G-core-security target: an
// attacker who can reach the N4 interface can forge PFCP Session
// Modification / Deletion messages to tear down or redirect a
// subscriber's bearer (a DoS or on-path attack), so decoding a captured
// PFCP exchange surfaces the message type, the session endpoint
// identifier (SEID) and the rule IEs being programmed. It joins the
// project's cellular decoders (internal/gtp, gtpv2, gsmtap, diameter).
//
// # Wrap-vs-native judgement
//
//	Native. The PFCP header is a fixed bitfield (version, the message-
//	priority / SEID flags, message type, length, optional SEID,
//	sequence) and the body is a list of TLV Information Elements
//	(2-octet type, 2-octet length, value). Decoding is byte-field
//	extraction + a TLV walk — a dependency is not justified. stdlib
//	only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header and the IE TLV structure were verified field-for-field
//	against scapy's PFCP layer. Message types and IE types are named
//	from the TS 29.244 tables; the Cause IE is decoded to its code.
//	Every other IE value — including the many grouped IEs that nest
//	further IEs — is surfaced as raw hex rather than decoded into a
//	possibly-wrong field (the IE value formats are numerous and
//	release-specific).
package pfcp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a PFCP message.
type Result struct {
	Version         int    `json:"version"`
	MessagePriority bool   `json:"message_priority_present"`
	SEIDPresent     bool   `json:"seid_present"`
	MessageType     int    `json:"message_type"`
	MessageName     string `json:"message_name"`
	Length          int    `json:"length"`
	SEID            string `json:"seid,omitempty"`
	SequenceNumber  int    `json:"sequence_number"`

	IEs   []IE     `json:"information_elements"`
	Notes []string `json:"notes,omitempty"`
}

// IE is one Information Element.
type IE struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	ValueHex string `json:"value_hex,omitempty"`
	Decoded  string `json:"decoded,omitempty"`
}

// Decode parses a PFCP message from hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("pfcp: %d bytes — too short for a PFCP header", len(b))
	}
	r := &Result{
		Version:         int(b[0] >> 5),
		MessagePriority: b[0]&0x02 != 0,
		SEIDPresent:     b[0]&0x01 != 0,
		MessageType:     int(b[1]),
		Length:          int(binary.BigEndian.Uint16(b[2:4])),
	}
	if r.Version != 1 {
		return nil, fmt.Errorf("pfcp: version %d is not PFCP (version 1, TS 29.244)", r.Version)
	}
	r.MessageName = messageName(r.MessageType)
	var off int
	if r.SEIDPresent {
		if len(b) < 16 {
			return nil, fmt.Errorf("pfcp: SEID flag set but only %d bytes (need 16)", len(b))
		}
		r.SEID = fmt.Sprintf("0x%016X", binary.BigEndian.Uint64(b[4:12]))
		r.SequenceNumber = int(b[12])<<16 | int(b[13])<<8 | int(b[14])
		off = 16
	} else {
		r.SequenceNumber = int(b[4])<<16 | int(b[5])<<8 | int(b[6])
		off = 8
	}

	// Walk the Information Elements (2-octet type, 2-octet length, value).
	for off+4 <= len(b) {
		ieType := int(binary.BigEndian.Uint16(b[off : off+2]))
		ieLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		valStart := off + 4
		valEnd := valStart + ieLen
		if valEnd > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf("IE at offset %d declares length %d beyond the buffer — stopping", off, ieLen))
			break
		}
		val := b[valStart:valEnd]
		ie := IE{Type: ieType, TypeName: ieName(ieType), Length: ieLen, ValueHex: strings.ToUpper(hex.EncodeToString(val))}
		if ieType == 19 && len(val) >= 1 { // Cause
			ie.Decoded = fmt.Sprintf("cause %d", val[0])
		}
		r.IEs = append(r.IEs, ie)
		off = valEnd
	}
	if r.MessageType == 54 || r.MessageType == 52 {
		r.Notes = append(r.Notes, "Session Deletion / Modification: forged PFCP session messages on N4 can tear down or redirect a subscriber's bearer (a 5G-core DoS / on-path attack) — confirm the source is the legitimate SMF")
	}
	r.Notes = append(r.Notes, "grouped IEs (those that nest further IEs) and non-Cause IE values are surfaced as raw hex (the IE value formats are numerous and release-specific; only the structure + Cause are decoded, to avoid confidently-wrong output)")
	return r, nil
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("pfcp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("pfcp: input is not valid hex: %w", err)
	}
	return b, nil
}
