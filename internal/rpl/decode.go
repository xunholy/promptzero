// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rpl decodes the RPL (Routing Protocol for Low-Power and Lossy
// Networks, RFC 6550) control messages — the IPv6 routing protocol that
// builds the mesh ("DODAG") of a 6LoWPAN / IEEE 802.15.4 IoT network. It
// is carried in ICMPv6 type 155. RPL is a recognised IoT-routing attack
// surface: a malicious node can advertise a forged low **rank** in a DIO
// to draw the mesh's traffic through itself (a sinkhole / on-path
// attack), or bump the DODAG **version** to force a costly network-wide
// rebuild (a DoS) — both are visible in a captured DIO. Decoding RPL
// surfaces those fields, complementing the project's other IoT decoders
// (internal/ieee802154, zigbee, ndp).
//
// # Wrap-vs-native judgement
//
//	Native. The RPL control messages (DIS / DIO / DAO / DAO-ACK) are
//	fixed bitfield/byte layouts inside an ICMPv6 message (RFC 6550
//	§6). Decoding is byte-field extraction + bit-masking — a dependency
//	is not justified. stdlib only (net for the IPv6 formatting), no new
//	go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The ICMPv6 RPL header and the DIS / DIO / DAO / DAO-ACK bodies were
//	verified field-for-field against scapy's RPL layer. The trailing
//	RPL options (DODAG Configuration, Prefix Information, Transit
//	Information, Target, …) are a TLV list with varied bodies, so they
//	are surfaced as raw hex rather than decoded into possibly-wrong
//	fields. The ICMPv6 checksum is not verified — it covers an IPv6
//	pseudo-header that is not present in the ICMPv6 message alone.
package rpl

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the decoded view of an RPL control message.
type Result struct {
	ICMPv6Type  int    `json:"icmpv6_type"`
	Code        int    `json:"code"`
	MessageName string `json:"message_name"`

	// DIO (code 1) fields.
	RPLInstanceID *int   `json:"rpl_instance_id,omitempty"`
	Version       *int   `json:"version,omitempty"`
	Rank          *int   `json:"rank,omitempty"`
	Grounded      *bool  `json:"grounded,omitempty"`
	MOP           *int   `json:"mode_of_operation,omitempty"`
	MOPName       string `json:"mode_of_operation_name,omitempty"`
	Preference    *int   `json:"dodag_preference,omitempty"`
	DTSN          *int   `json:"dtsn,omitempty"`
	DODAGID       string `json:"dodag_id,omitempty"`

	// DAO / DAO-ACK fields.
	DAOSequence *int `json:"dao_sequence,omitempty"`
	DAOStatus   *int `json:"dao_status,omitempty"`

	OptionsHex string   `json:"options_hex,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

const icmpv6RPLType = 155

// Decode parses an RPL control message (the ICMPv6 type-155 message) from
// hex (whitespace / ':' / '-' / '_' separators and a '0x' prefix
// tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("rpl: %d bytes — too short for an ICMPv6 RPL header", len(b))
	}
	r := &Result{ICMPv6Type: int(b[0]), Code: int(b[1])}
	if r.ICMPv6Type != icmpv6RPLType {
		return nil, fmt.Errorf("rpl: ICMPv6 type %d is not RPL (155)", r.ICMPv6Type)
	}
	r.MessageName = codeName(r.Code)
	body := b[4:] // skip type + code + 2-byte checksum
	switch r.Code {
	case 0x00: // DIS
		// flags(1) + reserved(1) + options
		if len(body) >= 2 {
			r.OptionsHex = hexUpper(body[2:])
		}
	case 0x01: // DIO
		if len(body) < 24 {
			return nil, fmt.Errorf("rpl: DIO body truncated (%d bytes, need 24)", len(body))
		}
		id := int(body[0])
		ver := int(body[1])
		rank := int(binary.BigEndian.Uint16(body[2:4]))
		g := body[4]&0x80 != 0
		mop := int(body[4]>>3) & 0x07
		prf := int(body[4]) & 0x07
		dtsn := int(body[5])
		r.RPLInstanceID, r.Version, r.Rank = &id, &ver, &rank
		r.Grounded, r.MOP, r.Preference, r.DTSN = &g, &mop, &prf, &dtsn
		r.MOPName = mopName(mop)
		r.DODAGID = net.IP(body[8:24]).String()
		r.OptionsHex = hexUpper(body[24:])
		r.Notes = append(r.Notes, "rank + version are the RPL attack fields: a forged low rank draws mesh traffic through the advertiser (sinkhole / on-path); a bumped version forces a network-wide DODAG rebuild (DoS)")
	case 0x02: // DAO
		if len(body) < 4 {
			return nil, fmt.Errorf("rpl: DAO body truncated")
		}
		id := int(body[0])
		dFlag := body[1]&0x40 != 0
		seq := int(body[3])
		r.RPLInstanceID, r.DAOSequence = &id, &seq
		off := 4
		if dFlag {
			if len(body) < off+16 {
				return nil, fmt.Errorf("rpl: DAO D-flag set but DODAGID truncated")
			}
			r.DODAGID = net.IP(body[off : off+16]).String()
			off += 16
		}
		if off <= len(body) {
			r.OptionsHex = hexUpper(body[off:])
		}
	case 0x03: // DAO-ACK
		if len(body) < 3 {
			return nil, fmt.Errorf("rpl: DAO-ACK body truncated")
		}
		id := int(body[0])
		dFlag := body[1]&0x80 != 0
		seq := int(body[2])
		status := 0
		if len(body) >= 4 {
			status = int(body[3])
		}
		r.RPLInstanceID, r.DAOSequence, r.DAOStatus = &id, &seq, &status
		off := 4
		if dFlag && len(body) >= off+16 {
			r.DODAGID = net.IP(body[off : off+16]).String()
			off += 16
		}
		if off <= len(body) {
			r.OptionsHex = hexUpper(body[off:])
		}
	default:
		r.OptionsHex = hexUpper(body)
		r.Notes = append(r.Notes, fmt.Sprintf("RPL code %d (%s): body surfaced raw", r.Code, r.MessageName))
	}
	r.Notes = append(r.Notes,
		"trailing RPL options are surfaced as raw hex (the option TLV bodies are varied; only the message header is decoded, to avoid confidently-wrong output)",
		"the ICMPv6 checksum is not verified — it covers an IPv6 pseudo-header not present in the ICMPv6 message alone")
	return r, nil
}

func codeName(c int) string {
	switch c {
	case 0x00:
		return "DIS (DODAG Information Solicitation)"
	case 0x01:
		return "DIO (DODAG Information Object)"
	case 0x02:
		return "DAO (Destination Advertisement Object)"
	case 0x03:
		return "DAO-ACK"
	case 0x07:
		return "DCO (Destination Cleanup Object)"
	case 0x08:
		return "DCO-ACK"
	}
	return fmt.Sprintf("RPL code %d", c)
}

func mopName(m int) string {
	switch m {
	case 0:
		return "No downward routes"
	case 1:
		return "Non-storing"
	case 2:
		return "Storing without multicast"
	case 3:
		return "Storing with multicast"
	}
	return fmt.Sprintf("reserved (%d)", m)
}

func hexUpper(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("rpl: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("rpl: input is not valid hex: %w", err)
	}
	return b, nil
}
