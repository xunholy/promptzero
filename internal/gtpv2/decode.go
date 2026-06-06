// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gtpv2 decodes GTPv2-C — the GTP version-2 control plane (3GPP
// TS 29.274) that signals EPS bearer / session management across the LTE
// and 5G-NSA core (the S11 MME↔SGW, S5/S8 SGW↔PGW and S10/S16 interfaces,
// UDP port 2123). It is the control-plane companion to internal/gtp,
// which decodes the GTP-U user plane (TS 29.281) and explicitly defers
// GTP-C. GTP-C is a recognised telecom-security target: the roaming /
// core GTP plane has been abused for IMSI harvesting, subscriber
// tracking and the GTPdoor backdoor, and a captured Create-Session /
// Modify-Bearer exchange carries the subscriber's IMSI, MSISDN and MEI
// in the clear — so decoding it surfaces exactly those identifiers.
//
// # Wrap-vs-native judgement
//
//	Native. The GTPv2-C header is a fixed bitfield (version, the
//	piggyback / TEID / message-priority flags, message type, length,
//	optional TEID, sequence) and the body is a flat list of TLV
//	Information Elements (type, length, instance, value). Decoding is
//	byte-field extraction + a TLV walk — a dependency is not justified.
//	stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header and the IE TLV structure were verified field-for-field
//	against scapy's GTPv2 layer. Message types and IE types are named
//	from the TS 29.274 tables. The subscriber-identifier IEs that are
//	TBCD-encoded — IMSI, MSISDN and MEI — are decoded to their digit
//	strings (the standard telephony BCD, the headline value for the
//	IMSI-harvesting use case); every other IE value is surfaced as raw
//	hex rather than decoded into a possibly-wrong field (the IE value
//	formats are many and version-specific).
package gtpv2

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a GTPv2-C message.
type Result struct {
	Version         int    `json:"version"`
	Piggybacked     bool   `json:"piggybacked"`
	TEIDPresent     bool   `json:"teid_present"`
	MessagePriority bool   `json:"message_priority_present"`
	MessageType     int    `json:"message_type"`
	MessageName     string `json:"message_name"`
	Length          int    `json:"length"`
	TEID            string `json:"teid,omitempty"`
	SequenceNumber  int    `json:"sequence_number"`

	IMSI   string `json:"imsi,omitempty"`
	MSISDN string `json:"msisdn,omitempty"`
	MEI    string `json:"mei,omitempty"`

	IEs   []IE     `json:"information_elements"`
	Notes []string `json:"notes,omitempty"`
}

// IE is one Information Element.
type IE struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	Instance int    `json:"instance"`
	ValueHex string `json:"value_hex,omitempty"`
	Decoded  string `json:"decoded,omitempty"`
}

// Decode parses a GTPv2-C message from hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("gtpv2: %d bytes — too short for a GTPv2-C header", len(b))
	}
	r := &Result{
		Version:         int(b[0] >> 5),
		Piggybacked:     b[0]&0x10 != 0,
		TEIDPresent:     b[0]&0x08 != 0,
		MessagePriority: b[0]&0x04 != 0,
		MessageType:     int(b[1]),
		Length:          int(binary.BigEndian.Uint16(b[2:4])),
	}
	if r.Version != 2 {
		return nil, fmt.Errorf("gtpv2: version %d is not GTPv2 (this is the GTP-C decoder; use gtp_decode for GTP-U v1)", r.Version)
	}
	r.MessageName = messageName(r.MessageType)
	var off int
	if r.TEIDPresent {
		if len(b) < 12 {
			return nil, fmt.Errorf("gtpv2: TEID flag set but only %d bytes (need 12)", len(b))
		}
		r.TEID = fmt.Sprintf("0x%08X", binary.BigEndian.Uint32(b[4:8]))
		r.SequenceNumber = int(b[8])<<16 | int(b[9])<<8 | int(b[10])
		off = 12
	} else {
		r.SequenceNumber = int(b[4])<<16 | int(b[5])<<8 | int(b[6])
		off = 8
	}

	// Walk the Information Elements.
	for off+4 <= len(b) {
		ieType := int(b[off])
		ieLen := int(binary.BigEndian.Uint16(b[off+1 : off+3]))
		instance := int(b[off+3] & 0x0F)
		valStart := off + 4
		valEnd := valStart + ieLen
		if valEnd > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf("IE at offset %d declares length %d beyond the buffer — stopping", off, ieLen))
			break
		}
		val := b[valStart:valEnd]
		ie := IE{Type: ieType, TypeName: ieName(ieType), Length: ieLen, Instance: instance, ValueHex: strings.ToUpper(hex.EncodeToString(val))}
		switch ieType {
		case 1: // IMSI (TBCD)
			ie.Decoded = decodeTBCD(val)
			r.IMSI = ie.Decoded
		case 76: // MSISDN (TBCD)
			ie.Decoded = decodeTBCD(val)
			r.MSISDN = ie.Decoded
		case 75: // MEI (TBCD)
			ie.Decoded = decodeTBCD(val)
			r.MEI = ie.Decoded
		case 2: // Cause
			if len(val) >= 1 {
				ie.Decoded = fmt.Sprintf("cause %d", val[0])
			}
		}
		r.IEs = append(r.IEs, ie)
		off = valEnd
	}
	if r.IMSI != "" || r.MSISDN != "" || r.MEI != "" {
		r.Notes = append(r.Notes, "subscriber identifiers (IMSI / MSISDN / MEI) are carried in the clear in GTP-C — the IMSI-harvesting exposure that makes the GTP roaming/core plane a recognised telecom-security target")
	}
	r.Notes = append(r.Notes, "non-identifier IE values are surfaced as raw hex (the IE value formats are many and version-specific; only the TBCD identifiers + Cause are decoded, to avoid confidently-wrong output)")
	return r, nil
}

// decodeTBCD decodes a telephony BCD string (low nibble first, 0xF is a
// filler) into its digits — the encoding used for IMSI / MSISDN / MEI.
func decodeTBCD(b []byte) string {
	var sb strings.Builder
	for _, x := range b {
		lo := x & 0x0F
		hi := x >> 4
		if lo <= 9 {
			sb.WriteByte('0' + lo)
		}
		if hi <= 9 {
			sb.WriteByte('0' + hi)
		}
	}
	return sb.String()
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("gtpv2: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("gtpv2: input is not valid hex: %w", err)
	}
	return b, nil
}
