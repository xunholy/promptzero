// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gxrp decodes GARP (Generic Attribute Registration Protocol,
// IEEE 802.1D-2004 §12.10) and its two applications, GVRP (GARP VLAN
// Registration Protocol) and GMRP (GARP Multicast Registration Protocol).
// It is the fourth leg of the project's Cisco/L2 VLAN-attack decoder
// family alongside internal/dtp, internal/vtp and internal/vqp:
// **GVRP dynamic VLAN registration is an L2 attack surface** — a host
// that emits GVRP JoinIn attributes can register arbitrary VLANs onto a
// trunk it is attached to (extending the trunk's allowed-VLAN set), a
// VLAN-hopping primitive; GMRP does the equivalent for multicast group
// membership. A captured GARP PDU reveals which VLANs / multicast groups
// are being registered or withdrawn, and by which event (Join / Leave /
// LeaveAll).
//
// # Wrap-vs-native judgement
//
//	Native. A GARP PDU is a 2-byte protocol id followed by a list of
//	messages, each a type byte + a list of (length, event, value)
//	attributes, with 0x00 end-marks terminating the attribute and
//	message lists. A byte-field read + two nested walks; stdlib only,
//	no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The GARP framing (proto id, message type, attribute len/event,
//	end-marks) was verified field-for-field against scapy's GARP layer
//	(scapy.contrib.gxrp). The GVRP-vs-GMRP application is keyed in the
//	standard by the L2 destination MAC, which is NOT carried in the PDU;
//	this decoder therefore infers the attribute value kind from its
//	length — a 2-byte value is a VLAN id (GVRP), a 6-byte value a group
//	MAC (GMRP), a 1-byte value a GMRP service — which are non-overlapping
//	and deterministic in practice, and the raw value is always surfaced
//	alongside the interpretation with a note naming the definitive
//	signal. Unknown value lengths are surfaced as raw hex only.
package gxrp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Attribute is one decoded GARP attribute.
type Attribute struct {
	Length    int    `json:"length"`
	Event     int    `json:"event"`
	EventName string `json:"event_name"`
	Kind      string `json:"kind,omitempty"` // inferred: vlan / group_mac / gmrp_service
	VLAN      *int   `json:"vlan,omitempty"`
	GroupMAC  string `json:"group_mac,omitempty"`
	Service   string `json:"gmrp_service,omitempty"`
	ValueHex  string `json:"value_hex,omitempty"`
}

// Message is one decoded GARP message (a list of attributes of one type).
type Message struct {
	Type       int         `json:"type"`
	Attributes []Attribute `json:"attributes"`
}

// Result is the decoded view of a GARP PDU.
type Result struct {
	ProtocolID int       `json:"protocol_id"`
	Messages   []Message `json:"messages"`
	Notes      []string  `json:"notes,omitempty"`
}

// Decode parses a GARP / GVRP / GMRP PDU (the LLC payload) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 3 {
		return nil, fmt.Errorf("gxrp: %d bytes — too short for a GARP PDU", len(b))
	}
	r := &Result{ProtocolID: int(binary.BigEndian.Uint16(b[0:2]))}
	if r.ProtocolID != 0x0001 {
		return nil, fmt.Errorf("gxrp: protocol id 0x%04x is not GARP (0x0001)", r.ProtocolID)
	}
	off := 2
	for off < len(b) {
		if b[off] == 0x00 { // GARP end-mark
			break
		}
		msg := Message{Type: int(b[off])}
		off++
		for off < len(b) {
			if b[off] == 0x00 { // message end-mark
				off++
				break
			}
			ln := int(b[off])
			if ln < 2 || off+ln > len(b) {
				r.Notes = append(r.Notes, fmt.Sprintf("attribute length %d at offset %d is invalid or overruns", ln, off))
				off = len(b)
				break
			}
			event := int(b[off+1])
			value := b[off+2 : off+ln]
			msg.Attributes = append(msg.Attributes, decodeAttribute(ln, event, value))
			off += ln
		}
		r.Messages = append(r.Messages, msg)
	}
	r.Notes = append(r.Notes,
		"GVRP JoinIn attributes register VLANs onto the attached trunk (a VLAN-hopping primitive); LeaveAll/Leave withdraw them",
		"the GVRP-vs-GMRP application is keyed by the L2 destination MAC (01:80:c2:00:00:21 = GVRP, ...:20 = GMRP), which is not in this PDU — the attribute kind here is inferred from the value length and the raw value is always shown")
	return r, nil
}

func decodeAttribute(ln, event int, value []byte) Attribute {
	a := Attribute{Length: ln, Event: event, EventName: eventName(event)}
	switch len(value) {
	case 0:
		// LeaveAll and similar carry no value.
	case 2:
		v := int(binary.BigEndian.Uint16(value))
		a.Kind, a.VLAN = "vlan", &v
	case 6:
		a.Kind, a.GroupMAC = "group_mac", net.HardwareAddr(value).String()
	case 1:
		a.Kind, a.Service = "gmrp_service", serviceName(value[0])
	}
	// Always surface the raw value alongside any typed interpretation.
	if len(value) > 0 {
		a.ValueHex = strings.ToUpper(hex.EncodeToString(value))
	}
	return a
}

func eventName(e int) string {
	switch e {
	case 0:
		return "LeaveAll"
	case 1:
		return "JoinEmpty"
	case 2:
		return "JoinIn"
	case 3:
		return "LeaveEmpty"
	case 4:
		return "LeaveIn"
	case 5:
		return "Empty"
	}
	return fmt.Sprintf("unknown(%d)", e)
}

func serviceName(s byte) string {
	switch s {
	case 0:
		return "All Groups"
	case 1:
		return "All Unregistered Groups"
	}
	return fmt.Sprintf("unknown(%d)", s)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("gxrp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("gxrp: input is not valid hex: %w", err)
	}
	return b, nil
}
