// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nsh decodes the Network Service Header (NSH, RFC 8300) — the
// Service Function Chaining (SFC) encapsulation that steers a packet
// through an ordered chain of service functions (firewalls, DPI, NAT,
// load-balancers) in SDN / NFV / cloud fabrics. It joins the project's
// tunnel-decap decoder family (gre, geneve, vxlan, mpls, sflow, etherip):
// a captured NSH packet reveals the **service path** (SPI) and the current
// **service index** (SI) a packet is being steered along — the SFC routing
// topology — and carries the original packet inside, so decoding it
// decaps the steered inner flow.
//
// # Wrap-vs-native judgement
//
//	Native. NSH is a 4-byte base header (version / OAM / TTL / length /
//	MD type / next protocol) + a 4-byte service-path header (SPI + SI) +
//	context headers, then the inner packet. A byte/bitfield read + the
//	existing inner-IP decode path; stdlib only, no new go.mod dep. The same
//	chain-to-ipdecode pattern as gre / sflow / etherip.
//
// # Verifiable / no confidently-wrong output
//
//	The base + service-path header (version, OAM, TTL, length, MD type,
//	next protocol, SPI, SI) was verified field-for-field against scapy's
//	NSH layer (scapy.contrib.nsh). The context headers are surfaced as raw
//	hex (MD type 1 is a fixed 16 bytes; MD type 2 is a varied TLV list, so
//	it is not field-decoded). The inner packet is decoded in place via
//	internal/ipdecode when next protocol is IPv4 / IPv6 (degrading to an
//	inner_decode_error + raw on failure); an Ethernet inner has its L2
//	header surfaced and its IP payload chained; other next protocols are
//	left raw.
package nsh

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/xunholy/promptzero/internal/ipdecode"
)

// Result is the decoded view of an NSH packet.
type Result struct {
	Version       int    `json:"version"`
	OAM           bool   `json:"oam"`
	TTL           int    `json:"ttl"`
	LengthWords   int    `json:"length_words"`
	MDType        int    `json:"md_type"`
	MDTypeName    string `json:"md_type_name"`
	NextProtocol  int    `json:"next_protocol"`
	NextProtoName string `json:"next_protocol_name"`
	ServicePathID int    `json:"service_path_id"` // SPI
	ServiceIndex  int    `json:"service_index"`   // SI

	ContextHeadersHex string `json:"context_headers_hex,omitempty"`

	InnerDstMAC      string           `json:"inner_dst_mac,omitempty"`
	InnerSrcMAC      string           `json:"inner_src_mac,omitempty"`
	InnerEtherType   string           `json:"inner_ether_type,omitempty"`
	InnerPacket      *ipdecode.Packet `json:"inner_packet,omitempty"`
	InnerFrameHex    string           `json:"inner_frame_hex,omitempty"`
	InnerDecodeError string           `json:"inner_decode_error,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// Decode parses an NSH packet from hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("nsh: %d bytes — too short for the 8-byte NSH base + service-path header", len(b))
	}
	r := &Result{
		Version:       int(b[0] >> 6),
		OAM:           b[0]&0x20 != 0,
		TTL:           int(b[0]&0x0f)<<2 | int(b[1]>>6),
		LengthWords:   int(b[1] & 0x3f),
		MDType:        int(b[2] & 0x0f),
		NextProtocol:  int(b[3]),
		ServicePathID: int(b[4])<<16 | int(b[5])<<8 | int(b[6]),
		ServiceIndex:  int(b[7]),
	}
	r.MDTypeName = mdTypeName(r.MDType)
	r.NextProtoName = nextProtoName(r.NextProtocol)

	// length is the total NSH header in 4-byte words (base + service-path +
	// context). It must be at least 2 (the two mandatory 4-byte headers).
	hdrBytes := r.LengthWords * 4
	if r.LengthWords < 2 || hdrBytes > len(b) {
		r.Notes = append(r.Notes, "NSH length field is invalid or points past the captured bytes — context + inner not decoded")
		return r, nil
	}
	if ctx := b[8:hdrBytes]; len(ctx) > 0 {
		r.ContextHeadersHex = hexUpper(ctx)
	}
	inner := b[hdrBytes:]
	r.decodeInner(inner)
	r.Notes = append(r.Notes, fmt.Sprintf("NSH steers this packet along service path %d at service index %d (SFC); the original packet is carried inside and decoded as %s", r.ServicePathID, r.ServiceIndex, r.NextProtoName))
	return r, nil
}

func (r *Result) decodeInner(inner []byte) {
	if len(inner) == 0 {
		return
	}
	switch r.NextProtocol {
	case 1, 2: // IPv4 / IPv6
		if pkt, err := ipdecode.DecodeBytes(inner); err == nil {
			r.InnerPacket = pkt
		} else {
			r.InnerDecodeError = err.Error()
			r.InnerFrameHex = hexUpper(inner)
		}
	case 3: // Ethernet
		if len(inner) < 14 {
			r.InnerFrameHex = hexUpper(inner)
			return
		}
		r.InnerDstMAC = net.HardwareAddr(inner[0:6]).String()
		r.InnerSrcMAC = net.HardwareAddr(inner[6:12]).String()
		et := binary.BigEndian.Uint16(inner[12:14])
		r.InnerEtherType = fmt.Sprintf("0x%04X", et)
		if et == 0x0800 || et == 0x86DD {
			if pkt, err := ipdecode.DecodeBytes(inner[14:]); err == nil {
				r.InnerPacket = pkt
			} else {
				r.InnerDecodeError = err.Error()
				r.InnerFrameHex = hexUpper(inner)
			}
		} else {
			r.InnerFrameHex = hexUpper(inner)
		}
	default:
		r.InnerFrameHex = hexUpper(inner)
	}
}

func mdTypeName(t int) string {
	switch t {
	case 0:
		return "reserved"
	case 1:
		return "Fixed-Length context (Type 1)"
	case 2:
		return "Variable-Length context (Type 2)"
	case 15:
		return "Experimental"
	}
	return fmt.Sprintf("0x%X", t)
}

func nextProtoName(p int) string {
	switch p {
	case 1:
		return "IPv4"
	case 2:
		return "IPv6"
	case 3:
		return "Ethernet"
	case 4:
		return "NSH"
	case 5:
		return "MPLS"
	case 254:
		return "Experiment 1"
	case 255:
		return "Experiment 2"
	}
	return fmt.Sprintf("0x%02X", p)
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
		return nil, fmt.Errorf("nsh: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("nsh: input is not valid hex: %w", err)
	}
	return b, nil
}
