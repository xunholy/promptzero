// SPDX-License-Identifier: AGPL-3.0-or-later

// Package etherip decodes EtherIP (RFC 3378) — the protocol that tunnels a
// whole Ethernet frame inside an IP packet (IP protocol 97). It completes
// the project's tunnel-decap decoder family alongside internal/gre,
// internal/geneve, internal/vxlan, internal/mpls and internal/sflow: a
// captured EtherIP packet is an L2-over-IP tunnel (used for transparent
// bridging / L2 VPNs, and as a data-exfiltration / pivot encapsulation),
// so decoding it surfaces the tunnelled inner Ethernet frame — the MAC
// addresses, the EtherType, and (when the inner payload is IP) the
// encapsulated flow's addresses / protocol / ports via internal/ipdecode.
//
// # Wrap-vs-native judgement
//
//	Native. An EtherIP packet is a 2-byte header (a 4-bit version + 12-bit
//	reserved) followed by an Ethernet frame. A byte-field read + the
//	existing inner-IP decode path; stdlib only, no new go.mod dep. The
//	same chain-to-ipdecode pattern as gre / sflow.
//
// # Verifiable / no confidently-wrong output
//
//	The 2-byte header and the inner Ethernet header were verified
//	field-for-field against scapy's EtherIP layer (scapy.contrib.etherip).
//	The version is required to be 3 (RFC 3378) — a non-EtherIP packet is
//	rejected, not mis-decoded. When the inner EtherType is IPv4 / IPv6 the
//	L3 payload is decoded in place via internal/ipdecode (degrading to an
//	inner_decode_error + raw payload on a parse failure); a non-IP
//	EtherType leaves the inner frame surfaced as raw hex.
package etherip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/xunholy/promptzero/internal/ipdecode"
)

// Result is the decoded view of an EtherIP packet.
type Result struct {
	Version  int `json:"version"`
	Reserved int `json:"reserved"`

	InnerDstMAC   string `json:"inner_dst_mac"`
	InnerSrcMAC   string `json:"inner_src_mac"`
	EtherType     int    `json:"ether_type"`
	EtherTypeHex  string `json:"ether_type_hex"`
	EtherTypeName string `json:"ether_type_name"`

	InnerFrameHex    string           `json:"inner_frame_hex,omitempty"`
	InnerPacket      *ipdecode.Packet `json:"inner_packet,omitempty"`
	InnerDecodeError string           `json:"inner_decode_error,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// Decode parses an EtherIP packet (the IP-protocol-97 payload) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("etherip: %d bytes — too short for an EtherIP header", len(b))
	}
	version := int(b[0] >> 4)
	if version != 3 {
		return nil, fmt.Errorf("etherip: version %d is not 3 (RFC 3378) — not an EtherIP packet", version)
	}
	r := &Result{
		Version:  version,
		Reserved: int(b[0]&0x0f)<<8 | int(b[1]),
	}
	frame := b[2:]
	if len(frame) < 14 {
		r.Notes = append(r.Notes, "inner Ethernet frame truncated (need a 14-byte header)")
		if len(frame) > 0 {
			r.InnerFrameHex = hexUpper(frame)
		}
		return r, nil
	}
	r.InnerDstMAC = net.HardwareAddr(frame[0:6]).String()
	r.InnerSrcMAC = net.HardwareAddr(frame[6:12]).String()
	r.EtherType = int(binary.BigEndian.Uint16(frame[12:14]))
	r.EtherTypeHex = fmt.Sprintf("0x%04X", r.EtherType)
	r.EtherTypeName = etherTypeName(r.EtherType)
	l3 := frame[14:]
	switch r.EtherType {
	case 0x0800, 0x86DD: // IPv4 / IPv6 — decode the encapsulated L3 in place
		if len(l3) > 0 {
			if pkt, err := ipdecode.DecodeBytes(l3); err == nil {
				r.InnerPacket = pkt
			} else {
				r.InnerDecodeError = err.Error()
				r.InnerFrameHex = hexUpper(frame)
			}
		}
	default:
		if len(l3) > 0 {
			r.InnerFrameHex = hexUpper(frame)
		}
	}
	r.Notes = append(r.Notes, "EtherIP tunnels a full Ethernet frame over IP (protocol 97) — an L2 bridging / VPN encapsulation that can also carry exfiltrated traffic; the inner frame's MACs + EtherType (and any IP flow) are surfaced")
	return r, nil
}

func etherTypeName(t int) string {
	switch t {
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0x0806:
		return "ARP"
	case 0x8100:
		return "802.1Q VLAN"
	case 0x88A8:
		return "802.1ad QinQ"
	case 0x8847:
		return "MPLS unicast"
	case 0x8863:
		return "PPPoE Discovery"
	case 0x8864:
		return "PPPoE Session"
	}
	return fmt.Sprintf("0x%04X", t)
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
		return nil, fmt.Errorf("etherip: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("etherip: input is not valid hex: %w", err)
	}
	return b, nil
}
