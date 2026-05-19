// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dhcp decodes DHCPv4 packets per RFC 2131 (the
// envelope) + RFC 2132 (the options). DHCP is the second
// most-captured protocol on any wired network capture after
// DNS — every laptop / phone / IoT device that joins a
// network speaks it on UDP/67-68 the moment it links up.
//
// # Wrap-vs-native judgement
//
// Native. DHCP wraps a fixed-format 240-byte BOOTP header
// (RFC 951 + 1542) around a magic cookie (0x63825363) and a
// variable-length options list. Each option is `[code:1]
// [length:1][data:length]` with code 0xFF marking the end.
// Pasting a hex blob from Wireshark / tshark / a tcpdump-of-
// 67/68 capture is enough — no key material, no cryptography,
// no live network attach.
//
// # What this package covers
//
//   - BOOTP envelope (RFC 951 + RFC 2131 §2): op
//     (BOOTREQUEST / BOOTREPLY), htype + hlen (Ethernet
//     supported with hardware addresses rendered as colon
//     MAC), hops, xid (transaction ID), secs (seconds
//     elapsed since lease start), flags (broadcast bit +
//     reserved), ciaddr / yiaddr / siaddr / giaddr in
//     dotted-decimal, 16-byte chaddr (first hlen bytes are
//     the actual hardware address), null-trimmed sname +
//     file fields.
//   - Magic cookie validation: the 4-byte 0x63825363 at
//     offset 236 must be present for the packet to be
//     considered DHCP (rather than vanilla BOOTP).
//   - DHCP options walker with type-specific decode for the
//     operationally-important options (RFC 2132 §3 + RFC
//     3046 / 3203 / 4361 / 4702 extensions):
//   - **53 DHCP Message Type** — DISCOVER / OFFER /
//     REQUEST / DECLINE / ACK / NAK / RELEASE / INFORM /
//     LEASEQUERY / LEASEUNASSIGNED / LEASEUNKNOWN /
//     LEASEACTIVE / BULKLEASEQUERY / LEASEQUERYDONE /
//     ACTIVELEASEQUERY / LEASEQUERYSTATUS / TLS.
//   - **1 Subnet Mask**, **3 Router**, **6 DNS Servers**,
//     **42 NTP Servers**, **44 NetBIOS Name Servers**,
//     **45 NetBIOS Datagram Distribution Server** — each
//     is a list of IPv4 addresses.
//   - **12 Host Name**, **14 Merit Dump File**, **15
//     Domain Name**, **17 Root Path**, **19 IP Forward**,
//     **40 NIS Domain**, **66 TFTP Server Name**, **67
//     Boot File Name** — each is an ASCII string.
//   - **28 Broadcast Address**, **50 Requested IP**, **54
//     DHCP Server Identifier** — single IPv4.
//   - **51 IP Address Lease Time**, **57 Maximum DHCP
//     Message Size**, **58 Renewal Time**, **59
//     Rebinding Time** — durations / sizes in seconds /
//     bytes.
//   - **55 Parameter Request List** — list of option
//     codes the client is asking the server to include,
//     rendered with option-name lookup so operators see
//     "[Subnet Mask, Router, DNS Server, Domain Name, …]"
//     rather than "[1, 3, 6, 15, …]".
//   - **60 Vendor Class Identifier**, **61 Client
//     Identifier**, **77 User Class** — vendor / client
//     fingerprinting strings.
//   - **81 Client FQDN** (RFC 4702) — flags + A-record
//     result + AAAA-record result + FQDN.
//   - **82 Relay Agent Information** (RFC 3046) — with
//     sub-option walk (Agent Circuit ID, Agent Remote
//     ID, etc.).
//   - **119 Domain Search** (RFC 3397) — compressed list
//     of search-domain FQDNs.
//   - **121 Classless Static Route** (RFC 3442) — list
//     of (destination, mask, gateway) tuples.
//   - Every option that isn't decoded above is still
//     reported with code + name + length + raw hex.
//   - End-of-options (255) and Pad (0) markers are handled
//     correctly.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - DHCPv6 (RFC 8415) — entirely different envelope
//     (transaction ID + IA_NA + IA_TA + options); deferred
//     to a separate Spec.
//   - DHCP authentication (option 90, RFC 3118) — niche;
//     surfaced as raw hex.
//   - PXE / boot-time vendor-specific options — pass-through
//     as raw hex with the option name "Vendor-specific
//     Information".
//   - Encapsulated relay forms — operators feed the inner
//     DHCP message after stripping outer transport.
package dhcp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Packet is the decoded DHCPv4 message view.
type Packet struct {
	HexInput    string    `json:"hex_input"`
	Op          int       `json:"op"`
	OpName      string    `json:"op_name"`
	HType       int       `json:"htype"`
	HTypeName   string    `json:"htype_name"`
	HLen        int       `json:"hlen"`
	Hops        int       `json:"hops"`
	XID         uint32    `json:"xid"`
	Secs        int       `json:"secs"`
	Flags       int       `json:"flags"`
	Broadcast   bool      `json:"broadcast"`
	CiAddr      string    `json:"ciaddr"`
	YiAddr      string    `json:"yiaddr"`
	SiAddr      string    `json:"siaddr"`
	GiAddr      string    `json:"giaddr"`
	ClientHwHex string    `json:"client_hw_hex"`
	ClientHwMAC string    `json:"client_hw_mac,omitempty"`
	ServerName  string    `json:"server_name,omitempty"`
	BootFile    string    `json:"boot_file,omitempty"`
	MagicCookie string    `json:"magic_cookie"`
	MessageType string    `json:"message_type,omitempty"`
	Options     []*Option `json:"options,omitempty"`
}

// Option is one decoded DHCP option.
//
// Only the field that matches the option's type is populated;
// the raw bytes are always exposed via DataHex.
type Option struct {
	Code            int         `json:"code"`
	Name            string      `json:"name"`
	Length          int         `json:"length"`
	DataHex         string      `json:"data_hex,omitempty"`
	StringValue     string      `json:"string_value,omitempty"`
	IPv4            string      `json:"ipv4,omitempty"`
	IPv4List        []string    `json:"ipv4_list,omitempty"`
	Uint32Value     uint32      `json:"uint32_value,omitempty"`
	ParameterList   []string    `json:"parameter_list,omitempty"`
	DomainSearch    []string    `json:"domain_search,omitempty"`
	ClasslessRoutes []Route     `json:"classless_routes,omitempty"`
	FQDN            *FQDNOption `json:"fqdn,omitempty"`
	RelayAgent      []SubOption `json:"relay_agent_sub_options,omitempty"`
}

// Route is one entry in option 121 (Classless Static Route).
type Route struct {
	Destination string `json:"destination"`
	PrefixLen   int    `json:"prefix_length"`
	Gateway     string `json:"gateway"`
}

// FQDNOption is the decoded option-81 body.
type FQDNOption struct {
	Flags      int    `json:"flags"`
	ARecord    int    `json:"a_record_result"`
	AAAARecord int    `json:"aaaa_record_result"`
	FQDN       string `json:"fqdn"`
}

// SubOption is one entry inside an option whose payload is
// itself a list of [code, length, data] triples (e.g. option
// 82 Relay Agent Information).
type SubOption struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Length  int    `json:"length"`
	DataHex string `json:"data_hex,omitempty"`
}

// Decode parses a hex-encoded DHCPv4 packet.
func Decode(hexBlob string) (*Packet, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw DHCPv4 packet.
func DecodeBytes(b []byte) (*Packet, error) {
	if len(b) < 240 {
		return nil, fmt.Errorf(
			"dhcp: packet too short (%d bytes); minimum is 240 (236-byte BOOTP header + 4-byte magic cookie)",
			len(b))
	}
	p := &Packet{
		HexInput:    strings.ToUpper(hex.EncodeToString(b)),
		Op:          int(b[0]),
		OpName:      opName(int(b[0])),
		HType:       int(b[1]),
		HTypeName:   htypeName(int(b[1])),
		HLen:        int(b[2]),
		Hops:        int(b[3]),
		XID:         binary.BigEndian.Uint32(b[4:8]),
		Secs:        int(binary.BigEndian.Uint16(b[8:10])),
		Flags:       int(binary.BigEndian.Uint16(b[10:12])),
		CiAddr:      net.IP(b[12:16]).String(),
		YiAddr:      net.IP(b[16:20]).String(),
		SiAddr:      net.IP(b[20:24]).String(),
		GiAddr:      net.IP(b[24:28]).String(),
		ClientHwHex: strings.ToUpper(hex.EncodeToString(b[28:44])),
	}
	p.Broadcast = p.Flags&0x8000 != 0
	if p.HType == 1 && p.HLen == 6 {
		p.ClientHwMAC = net.HardwareAddr(b[28:34]).String()
	}
	p.ServerName = trimNull(b[44:108])
	p.BootFile = trimNull(b[108:236])
	cookie := binary.BigEndian.Uint32(b[236:240])
	p.MagicCookie = fmt.Sprintf("0x%08X", cookie)
	if cookie != 0x63825363 {
		return nil, fmt.Errorf(
			"dhcp: bad magic cookie 0x%08X (want 0x63825363); not a DHCP packet (possibly vanilla BOOTP)",
			cookie)
	}
	if len(b) > 240 {
		opts, msgType, err := decodeOptions(b[240:])
		if err != nil {
			return nil, fmt.Errorf("dhcp: options: %w", err)
		}
		p.Options = opts
		p.MessageType = msgType
	}
	return p, nil
}

func decodeOptions(b []byte) ([]*Option, string, error) {
	var out []*Option
	var msgType string
	off := 0
	for off < len(b) {
		code := int(b[off])
		off++
		switch code {
		case 0:
			// Pad — single byte, no length.
			continue
		case 255:
			// End of options.
			return out, msgType, nil
		}
		if off >= len(b) {
			return nil, "", fmt.Errorf("option %d length byte missing", code)
		}
		length := int(b[off])
		off++
		if off+length > len(b) {
			return nil, "", fmt.Errorf("option %d declared length %d exceeds buffer", code, length)
		}
		data := b[off : off+length]
		off += length
		opt := &Option{
			Code:    code,
			Name:    optionName(code),
			Length:  length,
			DataHex: strings.ToUpper(hex.EncodeToString(data)),
		}
		decodeOption(opt, data)
		if code == 53 && len(data) == 1 {
			msgType = messageTypeName(int(data[0]))
		}
		out = append(out, opt)
	}
	return out, msgType, nil
}

func decodeOption(o *Option, data []byte) {
	switch o.Code {
	case 53: // DHCP Message Type
		if len(data) == 1 {
			o.StringValue = messageTypeName(int(data[0]))
		}
	case 1, 28, 50, 54: // Subnet Mask, Broadcast, Requested IP, Server ID
		if len(data) == 4 {
			o.IPv4 = net.IP(data).String()
		}
	case 3, 6, 42, 44, 45: // Router, DNS, NTP, NetBIOS NS, NetBIOS DDS
		for i := 0; i+4 <= len(data); i += 4 {
			o.IPv4List = append(o.IPv4List, net.IP(data[i:i+4]).String())
		}
	case 12, 14, 15, 17, 40, 60, 61, 66, 67, 77: // String options
		o.StringValue = string(data)
	case 51, 57, 58, 59: // Time / size durations (4-byte unsigned)
		if len(data) == 4 {
			o.Uint32Value = binary.BigEndian.Uint32(data)
		} else if len(data) == 2 {
			o.Uint32Value = uint32(binary.BigEndian.Uint16(data))
		}
	case 55: // Parameter Request List
		for _, b := range data {
			o.ParameterList = append(o.ParameterList, optionName(int(b)))
		}
	case 81: // Client FQDN
		if len(data) >= 3 {
			o.FQDN = &FQDNOption{
				Flags:      int(data[0]),
				ARecord:    int(data[1]),
				AAAARecord: int(data[2]),
				FQDN:       trimNull(data[3:]),
			}
		}
	case 82: // Relay Agent Information — sub-options walk
		off := 0
		for off+2 <= len(data) {
			sc := int(data[off])
			sl := int(data[off+1])
			off += 2
			if off+sl > len(data) {
				break
			}
			o.RelayAgent = append(o.RelayAgent, SubOption{
				Code:    sc,
				Name:    relayAgentSubOptionName(sc),
				Length:  sl,
				DataHex: strings.ToUpper(hex.EncodeToString(data[off : off+sl])),
			})
			off += sl
		}
	case 119: // Domain Search (RFC 3397)
		names, err := decodeDomainSearch(data)
		if err == nil {
			o.DomainSearch = names
		}
	case 121: // Classless Static Route (RFC 3442)
		o.ClasslessRoutes = decodeClasslessRoutes(data)
	}
}

// decodeDomainSearch parses option 119 — a list of FQDNs in
// the same compressed format as DNS messages. Pointers
// reference earlier offsets *within the option data block*.
func decodeDomainSearch(data []byte) ([]string, error) {
	var out []string
	off := 0
	for off < len(data) {
		name, n, err := decodeName(data, off, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, name)
		off += n
	}
	return out, nil
}

func decodeName(b []byte, off, depth int) (string, int, error) {
	const maxDepth = 16
	if depth > maxDepth {
		return "", 0, fmt.Errorf("pointer chain exceeded max depth")
	}
	var labels []string
	bytesRead := 0
	cur := off
	jumped := false
	for {
		if cur >= len(b) {
			return "", 0, fmt.Errorf("walked past buffer")
		}
		l := b[cur]
		if l&0xC0 == 0xC0 {
			if cur+2 > len(b) {
				return "", 0, fmt.Errorf("pointer truncated")
			}
			ptr := int(binary.BigEndian.Uint16(b[cur:cur+2])) & 0x3FFF
			if ptr >= len(b) {
				return "", 0, fmt.Errorf("pointer target outside buffer")
			}
			rest, _, err := decodeName(b, ptr, depth+1)
			if err != nil {
				return "", 0, err
			}
			if rest != "" {
				labels = append(labels, rest)
			}
			if !jumped {
				bytesRead = cur - off + 2
			}
			break
		}
		if l == 0 {
			if !jumped {
				bytesRead = cur - off + 1
			}
			break
		}
		cur++
		if cur+int(l) > len(b) {
			return "", 0, fmt.Errorf("label exceeds buffer")
		}
		labels = append(labels, string(b[cur:cur+int(l)]))
		cur += int(l)
	}
	return strings.Join(labels, "."), bytesRead, nil
}

// decodeClasslessRoutes parses option 121 — a packed list of
// (destination, prefix-length, gateway) tuples where the
// destination bytes are compressed (only `ceil(prefix/8)`
// bytes are encoded; the remainder is zero-padded).
func decodeClasslessRoutes(data []byte) []Route {
	var routes []Route
	off := 0
	for off < len(data) {
		if off+1 > len(data) {
			break
		}
		prefix := int(data[off])
		off++
		destBytes := (prefix + 7) / 8
		if off+destBytes+4 > len(data) {
			break
		}
		dest := make(net.IP, 4)
		copy(dest, data[off:off+destBytes])
		off += destBytes
		gw := net.IP(data[off : off+4])
		off += 4
		routes = append(routes, Route{
			Destination: dest.String(),
			PrefixLen:   prefix,
			Gateway:     gw.String(),
		})
	}
	return routes
}

func opName(op int) string {
	switch op {
	case 1:
		return "BOOTREQUEST"
	case 2:
		return "BOOTREPLY"
	}
	return fmt.Sprintf("Unknown (op %d)", op)
}

func htypeName(h int) string {
	switch h {
	case 1:
		return "Ethernet"
	case 6:
		return "IEEE 802 Networks"
	case 7:
		return "ARCNET"
	case 11:
		return "LocalTalk"
	case 12:
		return "LocalNet"
	case 14:
		return "SMDS"
	case 15:
		return "Frame Relay"
	case 16:
		return "ATM"
	case 17:
		return "HDLC"
	case 18:
		return "Fibre Channel"
	case 19:
		return "ATM (RFC 2225)"
	case 20:
		return "Serial Line"
	}
	return fmt.Sprintf("HType %d", h)
}

func messageTypeName(t int) string {
	switch t {
	case 1:
		return "DISCOVER"
	case 2:
		return "OFFER"
	case 3:
		return "REQUEST"
	case 4:
		return "DECLINE"
	case 5:
		return "ACK"
	case 6:
		return "NAK"
	case 7:
		return "RELEASE"
	case 8:
		return "INFORM"
	case 9:
		return "FORCERENEW"
	case 10:
		return "LEASEQUERY"
	case 11:
		return "LEASEUNASSIGNED"
	case 12:
		return "LEASEUNKNOWN"
	case 13:
		return "LEASEACTIVE"
	case 14:
		return "BULKLEASEQUERY"
	case 15:
		return "LEASEQUERYDONE"
	case 16:
		return "ACTIVELEASEQUERY"
	case 17:
		return "LEASEQUERYSTATUS"
	case 18:
		return "TLS"
	}
	return fmt.Sprintf("Unknown message type %d", t)
}

func optionName(c int) string {
	switch c {
	case 0:
		return "Pad"
	case 1:
		return "Subnet Mask"
	case 2:
		return "Time Offset"
	case 3:
		return "Router"
	case 4:
		return "Time Server"
	case 5:
		return "Name Server"
	case 6:
		return "DNS Server"
	case 7:
		return "Log Server"
	case 8:
		return "Cookie Server"
	case 9:
		return "LPR Server"
	case 10:
		return "Impress Server"
	case 11:
		return "Resource Location Server"
	case 12:
		return "Host Name"
	case 13:
		return "Boot File Size"
	case 14:
		return "Merit Dump File"
	case 15:
		return "Domain Name"
	case 16:
		return "Swap Server"
	case 17:
		return "Root Path"
	case 18:
		return "Extensions Path"
	case 19:
		return "IP Forwarding Enable/Disable"
	case 23:
		return "Default IP TTL"
	case 26:
		return "Interface MTU"
	case 28:
		return "Broadcast Address"
	case 31:
		return "Perform Router Discovery"
	case 33:
		return "Static Route"
	case 35:
		return "ARP Cache Timeout"
	case 40:
		return "NIS Domain"
	case 41:
		return "NIS Servers"
	case 42:
		return "NTP Servers"
	case 43:
		return "Vendor-specific Information"
	case 44:
		return "NetBIOS Name Server"
	case 45:
		return "NetBIOS Datagram Distribution Server"
	case 46:
		return "NetBIOS Node Type"
	case 47:
		return "NetBIOS Scope"
	case 50:
		return "Requested IP Address"
	case 51:
		return "IP Address Lease Time"
	case 52:
		return "Option Overload"
	case 53:
		return "DHCP Message Type"
	case 54:
		return "DHCP Server Identifier"
	case 55:
		return "Parameter Request List"
	case 56:
		return "Message"
	case 57:
		return "Maximum DHCP Message Size"
	case 58:
		return "Renewal Time"
	case 59:
		return "Rebinding Time"
	case 60:
		return "Vendor Class Identifier"
	case 61:
		return "Client Identifier"
	case 64:
		return "NIS+ Domain"
	case 65:
		return "NIS+ Servers"
	case 66:
		return "TFTP Server Name"
	case 67:
		return "Boot File Name"
	case 77:
		return "User Class"
	case 81:
		return "Client FQDN"
	case 82:
		return "Relay Agent Information"
	case 90:
		return "Authentication"
	case 91:
		return "Client-Last-Transaction-Time"
	case 92:
		return "Associated-IP"
	case 93:
		return "Client System Architecture"
	case 94:
		return "Client Network Device Interface"
	case 97:
		return "Client UUID/GUID"
	case 100:
		return "PCode (POSIX Timezone)"
	case 101:
		return "TCode (TZ Database Timezone)"
	case 116:
		return "DHCP Auto-Configuration"
	case 118:
		return "Subnet Selection"
	case 119:
		return "Domain Search"
	case 120:
		return "SIP Servers"
	case 121:
		return "Classless Static Route"
	case 125:
		return "Vendor-Identifying Vendor-Specific Information"
	case 255:
		return "End"
	}
	return fmt.Sprintf("Option %d", c)
}

func relayAgentSubOptionName(c int) string {
	switch c {
	case 1:
		return "Agent Circuit ID"
	case 2:
		return "Agent Remote ID"
	case 4:
		return "DOCSIS Device Class"
	case 5:
		return "Link Selection"
	case 6:
		return "Subscriber ID"
	case 7:
		return "RADIUS Attributes"
	case 8:
		return "Authentication"
	case 9:
		return "Vendor-Specific Information"
	case 10:
		return "Relay Agent Flags"
	case 11:
		return "Server Identifier Override"
	}
	return fmt.Sprintf("Sub-Option %d", c)
}

func trimNull(b []byte) string {
	end := len(b)
	for end > 0 && b[end-1] == 0x00 {
		end--
	}
	return string(b[:end])
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("dhcp: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("dhcp: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
