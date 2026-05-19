// Package arpdecode decodes Address Resolution Protocol (ARP)
// and Reverse ARP (RARP) packets per RFC 826 + RFC 903 + the
// RFC 5227 IPv4 address-conflict-detection extensions
// (gratuitous ARP / ARP probe / ARP announcement).
//
// Wrap-vs-native judgement
//
//	Native. RFC 826 is fully public (one of the oldest
//	standards-track RFCs from 1982); ARP wire format is
//	a tight 8-byte fixed header followed by 4 length-
//	parameterised address fields. No crypto, no compression,
//	no varints. Operators paste ARP-payload bytes (after the
//	Ethernet header strip; EtherType 0x0806 for ARP or
//	0x8035 for RARP) from a `tcpdump -i ethX -X ether proto
//	arp` line, a Wireshark Follow-Frame view, or any
//	ARP-emitting tool and get every documented field plus
//	the higher-level RFC 5227 detection patterns.
//
// What this package covers
//
//   - **8-byte fixed header**:
//
//   - Hardware Type (2 bytes BE): 11-entry name table per
//     IANA (1 Ethernet / 6 IEEE 802 / 7 ARCNET / 15 Frame
//     Relay / 16 ATM / 17 HDLC / 18 Fibre Channel / 19 ATM
//     (alternate) / 20 Serial Line / 32 InfiniBand).
//
//   - Protocol Type (2 bytes BE): the EtherType of the
//     protocol address being resolved. 4 documented:
//     0x0800 IPv4 / 0x86DD IPv6 / 0x8035 RARP / 0x809B
//     AppleTalk.
//
//   - HLEN (1 byte): hardware address length, typically 6
//     for Ethernet.
//
//   - PLEN (1 byte): protocol address length, typically 4
//     for IPv4 or 16 for IPv6.
//
//   - Operation (2 bytes BE) with **10-entry name table**:
//     1 Request / 2 Reply / 3 RARP Request / 4 RARP Reply
//     / 5 DRARP-Request / 6 DRARP-Reply / 7 DRARP-Error /
//     8 InARP-Request / 9 InARP-Reply / 10 ARP-NAK.
//
//   - **4 address fields** (sizes from HLEN / PLEN):
//
//   - Sender Hardware Address (HLEN bytes; formatted as
//     MAC for HLEN=6).
//
//   - Sender Protocol Address (PLEN bytes; formatted as
//     IPv4 for PLEN=4, IPv6 for PLEN=16).
//
//   - Target Hardware Address (HLEN bytes).
//
//   - Target Protocol Address (PLEN bytes).
//
//   - **RFC 5227 detection patterns** for IPv4 ARP:
//
//   - **Gratuitous ARP**: opcode is Request or Reply AND
//     Sender Protocol Address == Target Protocol Address.
//     Used for unsolicited announcement that an IP is
//     claimed by this MAC.
//
//   - **ARP Probe** (RFC 5227 §1.1): opcode Request AND
//     Sender Protocol Address == 0.0.0.0 AND Target
//     Protocol Address is the address being probed (host
//     sends this before claiming the address to detect
//     conflicts).
//
//   - **ARP Announcement** (RFC 5227 §1.2): opcode Request
//     AND Sender Protocol Address == Target Protocol
//     Address (similar to gratuitous but specifically the
//     post-probe announcement).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Ethernet framing — feed the ARP payload bytes after
//     the dst MAC + src MAC + EtherType bytes.
//
//   - Neighbor Discovery Protocol (IPv6's ARP replacement)
//     — already handled by `icmp_packet_decode` (NDP
//     Neighbor Solicitation / Advertisement / Redirect).
//
//   - 802.1Q VLAN tag stripping — feed the post-tag ARP
//     payload.
//
//   - ARP table state — we decode individual packets; ARP
//     cache reconstruction belongs in a session-tracker.
package arpdecode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	HardwareType     int      `json:"hardware_type"`
	HardwareTypeName string   `json:"hardware_type_name"`
	ProtocolType     int      `json:"protocol_type"`
	ProtocolTypeHex  string   `json:"protocol_type_hex"`
	ProtocolTypeName string   `json:"protocol_type_name"`
	HLEN             int      `json:"hardware_address_length"`
	PLEN             int      `json:"protocol_address_length"`
	Operation        int      `json:"operation"`
	OperationName    string   `json:"operation_name"`
	SenderHardware   string   `json:"sender_hardware_address"`
	SenderProtocol   string   `json:"sender_protocol_address"`
	TargetHardware   string   `json:"target_hardware_address"`
	TargetProtocol   string   `json:"target_protocol_address"`
	TotalBytes       int      `json:"total_bytes"`
	Notes            []string `json:"notes,omitempty"`
}

// Decode parses an ARP/RARP packet from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("ARP header truncated (%d bytes; need ≥8)", len(b))
	}

	r := &Result{
		HardwareType: int(binary.BigEndian.Uint16(b[0:2])),
		ProtocolType: int(binary.BigEndian.Uint16(b[2:4])),
		HLEN:         int(b[4]),
		PLEN:         int(b[5]),
		Operation:    int(binary.BigEndian.Uint16(b[6:8])),
		TotalBytes:   len(b),
	}
	r.HardwareTypeName = hardwareTypeName(r.HardwareType)
	r.ProtocolTypeHex = fmt.Sprintf("0x%04X", r.ProtocolType)
	r.ProtocolTypeName = protocolTypeName(r.ProtocolType)
	r.OperationName = operationName(r.Operation)

	expected := 8 + 2*r.HLEN + 2*r.PLEN
	if len(b) < expected {
		return nil, fmt.Errorf("packet too short for HLEN=%d PLEN=%d (need %d bytes, have %d)",
			r.HLEN, r.PLEN, expected, len(b))
	}

	off := 8
	sha := b[off : off+r.HLEN]
	off += r.HLEN
	spa := b[off : off+r.PLEN]
	off += r.PLEN
	tha := b[off : off+r.HLEN]
	off += r.HLEN
	tpa := b[off : off+r.PLEN]

	r.SenderHardware = formatHardwareAddress(sha)
	r.SenderProtocol = formatProtocolAddress(r.ProtocolType, spa)
	r.TargetHardware = formatHardwareAddress(tha)
	r.TargetProtocol = formatProtocolAddress(r.ProtocolType, tpa)

	// RFC 5227 detection patterns for IPv4 ARP.
	if r.ProtocolType == 0x0800 && r.PLEN == 4 {
		spaZero := isAllZero(spa)
		spaEqTpa := bytesEqual(spa, tpa)
		switch {
		case r.Operation == 1 && spaZero && !isAllZero(tpa):
			r.Notes = append(r.Notes,
				fmt.Sprintf("ARP Probe (RFC 5227 §1.1): sender %s is probing %s "+
					"to detect address conflicts before claiming it",
					r.SenderProtocol, r.TargetProtocol))
		case r.Operation == 1 && spaEqTpa:
			r.Notes = append(r.Notes,
				fmt.Sprintf("ARP Announcement (RFC 5227 §1.2): sender %s is "+
					"announcing claim of the address post-probe",
					r.SenderProtocol))
		case (r.Operation == 1 || r.Operation == 2) && spaEqTpa && !spaZero:
			r.Notes = append(r.Notes,
				fmt.Sprintf("Gratuitous ARP: opcode=%s with sender=target=%s "+
					"(typically a cache-update / address-takeover signal)",
					r.OperationName, r.SenderProtocol))
		}
	}

	return r, nil
}

func hardwareTypeName(t int) string {
	switch t {
	case 1:
		return "Ethernet"
	case 6:
		return "IEEE 802 Networks"
	case 7:
		return "ARCNET"
	case 15:
		return "Frame Relay"
	case 16:
		return "ATM"
	case 17:
		return "HDLC"
	case 18:
		return "Fibre Channel"
	case 19:
		return "ATM (alternate)"
	case 20:
		return "Serial Line"
	case 32:
		return "InfiniBand"
	}
	return fmt.Sprintf("hardware type %d (uncatalogued)", t)
}

func protocolTypeName(t int) string {
	switch t {
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0x8035:
		return "RARP (reverse-ARP self-reference)"
	case 0x809B:
		return "AppleTalk"
	}
	return fmt.Sprintf("protocol 0x%04X (uncatalogued EtherType)", t)
}

func operationName(o int) string {
	switch o {
	case 1:
		return "Request"
	case 2:
		return "Reply"
	case 3:
		return "RARP Request"
	case 4:
		return "RARP Reply"
	case 5:
		return "DRARP-Request"
	case 6:
		return "DRARP-Reply"
	case 7:
		return "DRARP-Error"
	case 8:
		return "InARP-Request"
	case 9:
		return "InARP-Reply"
	case 10:
		return "ARP-NAK"
	}
	return fmt.Sprintf("operation %d (uncatalogued)", o)
}

func formatHardwareAddress(b []byte) string {
	if len(b) == 6 {
		return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
			b[0], b[1], b[2], b[3], b[4], b[5])
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func formatProtocolAddress(protoType int, b []byte) string {
	switch protoType {
	case 0x0800: // IPv4
		if len(b) == 4 {
			return net.IP(b).String()
		}
	case 0x86DD: // IPv6
		if len(b) == 16 {
			return net.IP(b).String()
		}
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
