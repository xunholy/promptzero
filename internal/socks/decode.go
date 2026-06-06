// SPDX-License-Identifier: AGPL-3.0-or-later

// Package socks decodes the SOCKS proxy protocol (SOCKS4 / SOCKS4a /
// SOCKS5, RFC 1928) — the proxy / pivot / exfil channel. A captured SOCKS
// exchange is a network-reconnaissance source: the **request reveals the
// proxied destination** (host or IP + port) a client is reaching through
// the proxy, which is exactly what matters when analysing a capture for
// data-exfiltration channels, malware command-and-control over a SOCKS
// proxy, or an attacker pivoting through a compromised host's proxy. It is
// an application-layer complement to the project's other capture decoders.
//
// # Wrap-vs-native judgement
//
//	Native. SOCKS is a tiny fixed wire format — a version byte then a
//	command/atyp + address + port (no checksums, no length-prefixed
//	containers beyond the SOCKS5 domain octet). A byte-field read; stdlib
//	only (net for the IP formatting), no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	Implemented to RFC 1928 (SOCKS5) / the SOCKS4/4a spec. The SOCKS5
//	IPv4 / IPv6 request+reply and the SOCKS4 request were cross-checked
//	against scapy's SOCKS layer; the SOCKS5 **domain** address and the
//	SOCKS4 **reply** are hand-verified against the RFC because scapy's
//	layer is wrong for those two (it encodes the domain as DNS labels and
//	omits the SOCKS4-reply bound address — RFC 1928 §5 specifies a plain
//	1-octet-length + name with no NUL, and a SOCKS4 reply is 8 bytes).
//	Because a lone SOCKS5 message does not always distinguish a request
//	from a reply (both share cmd/rep + rsv + atyp + addr + port, and the
//	values 1-3 are valid as either a command or a reply code), the
//	unambiguous **destination address + port** is always surfaced, and the
//	leading byte is reported as a command when it can only be one, as a
//	reply when it can only be that, and with both readings noted when it
//	is genuinely ambiguous — never guessed.
package socks

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the decoded view of a SOCKS message.
type Result struct {
	Version     int    `json:"version"`
	MessageKind string `json:"message_kind"`

	Command     *int   `json:"command,omitempty"`
	CommandName string `json:"command_name,omitempty"`
	ReplyCode   *int   `json:"reply_code,omitempty"`
	ReplyName   string `json:"reply_name,omitempty"`

	AddressType string `json:"address_type,omitempty"`
	DestAddress string `json:"dest_address,omitempty"`
	DestPort    *int   `json:"dest_port,omitempty"`

	UserID      string   `json:"user_id,omitempty"`      // SOCKS4
	AuthMethods []string `json:"auth_methods,omitempty"` // SOCKS5 greeting

	Notes []string `json:"notes,omitempty"`
}

// Decode parses a SOCKS message (a single TCP-payload message) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("socks: %d bytes — too short for a SOCKS message", len(b))
	}
	switch b[0] {
	case 0x04:
		return decodeV4Request(b)
	case 0x00:
		return decodeV4Reply(b)
	case 0x05:
		return decodeV5(b)
	default:
		return nil, fmt.Errorf("socks: version byte 0x%02x is not SOCKS4 (0x04) / SOCKS4-reply (0x00) / SOCKS5 (0x05)", b[0])
	}
}

func decodeV4Request(b []byte) (*Result, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("socks: SOCKS4 request truncated")
	}
	r := &Result{Version: 4, MessageKind: "socks4_request"}
	cd := int(b[1])
	r.Command, r.CommandName = &cd, v4Command(cd)
	port := int(binary.BigEndian.Uint16(b[2:4]))
	r.DestPort = &port
	ip := net.IP(b[4:8])
	r.AddressType = "ipv4"
	r.DestAddress = ip.String()
	// userid is a NUL-terminated string after the IP.
	rest := b[8:]
	uid, after := nulString(rest)
	r.UserID = uid
	// SOCKS4a: dst IP 0.0.0.x (x != 0) signals a domain name follows the userid.
	if b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] != 0 {
		if dom, _ := nulString(after); dom != "" {
			r.AddressType = "domain"
			r.DestAddress = dom
			r.Notes = append(r.Notes, "SOCKS4a: the destination is a domain name resolved by the proxy")
		}
	}
	r.Notes = append(r.Notes, "SOCKS4 request: the client asks the proxy to "+r.CommandName+" to "+r.DestAddress+fmt.Sprintf(":%d", port))
	return r, nil
}

func decodeV4Reply(b []byte) (*Result, error) {
	// RFC: a SOCKS4 reply is 8 bytes: VN(0) CD DSTPORT(2) DSTIP(4).
	if len(b) < 8 {
		return nil, fmt.Errorf("socks: SOCKS4 reply truncated (need 8 bytes)")
	}
	r := &Result{Version: 4, MessageKind: "socks4_reply"}
	cd := int(b[1])
	r.ReplyCode, r.ReplyName = &cd, v4ReplyName(cd)
	port := int(binary.BigEndian.Uint16(b[2:4]))
	r.DestPort = &port
	r.AddressType = "ipv4"
	r.DestAddress = net.IP(b[4:8]).String()
	return r, nil
}

func decodeV5(b []byte) (*Result, error) {
	// A 2-byte v5 message is the server's method selection.
	if len(b) == 2 {
		r := &Result{Version: 5, MessageKind: "socks5_method_selection"}
		r.AuthMethods = []string{v5Method(b[1])}
		r.Notes = append(r.Notes, "SOCKS5 method selection: the server chose auth method "+v5Method(b[1]))
		return r, nil
	}
	// A request/reply has rsv (b[2]) == 0 and a valid atyp (b[3]); its total
	// length must match the address type exactly. Otherwise it is a greeting.
	if len(b) >= 4 && b[2] == 0x00 && isATYP(b[3]) {
		if r, ok := decodeV5RequestReply(b); ok {
			return r, nil
		}
	}
	// Greeting: VN NMETHODS METHODS... (length == 2 + nmethods).
	if n := int(b[1]); len(b) == 2+n && n > 0 {
		r := &Result{Version: 5, MessageKind: "socks5_greeting"}
		for _, m := range b[2:] {
			r.AuthMethods = append(r.AuthMethods, v5Method(m))
		}
		r.Notes = append(r.Notes, "SOCKS5 greeting: the client offers these auth methods")
		return r, nil
	}
	r := &Result{Version: 5, MessageKind: "socks5_unrecognised"}
	r.Notes = append(r.Notes, "SOCKS5 message did not match a greeting / method-selection / request / reply structure; raw bytes: "+hexUpper(b))
	return r, nil
}

func decodeV5RequestReply(b []byte) (*Result, bool) {
	atyp := b[3]
	addr, port, ok := v5AddrPort(atyp, b[4:])
	if !ok {
		return nil, false
	}
	r := &Result{Version: 5, AddressType: atypName(atyp), DestAddress: addr}
	p := port
	r.DestPort = &p
	lead := int(b[1])
	switch {
	case lead == 0: // only a reply code can be 0 (succeeded); a command cannot
		r.MessageKind = "socks5_reply"
		r.ReplyCode, r.ReplyName = &lead, v5ReplyName(lead)
	case lead >= 1 && lead <= 3: // valid as a command OR a reply code — ambiguous
		r.MessageKind = "socks5_request_or_reply"
		r.Command, r.CommandName = &lead, v5Command(lead)
		r.Notes = append(r.Notes, fmt.Sprintf("ambiguous leading byte %d: as a request it is command %q; as a reply it is %q — a single SOCKS5 message does not distinguish the two", lead, v5Command(lead), v5ReplyName(lead)))
	case lead >= 4 && lead <= 8: // only a reply code (commands are 1-3)
		r.MessageKind = "socks5_reply"
		r.ReplyCode, r.ReplyName = &lead, v5ReplyName(lead)
	default:
		return nil, false // not a valid command or reply code
	}
	verb := "destination"
	if r.MessageKind == "socks5_reply" {
		verb = "bound address"
	}
	r.Notes = append(r.Notes, fmt.Sprintf("SOCKS5 %s: %s:%d", verb, addr, port))
	return r, true
}

// v5AddrPort decodes the SOCKS5 address (by atyp) + 2-byte port from a, per
// RFC 1928 §5, and requires it to consume a exactly.
func v5AddrPort(atyp byte, a []byte) (string, int, bool) {
	switch atyp {
	case 1: // IPv4
		if len(a) != 4+2 {
			return "", 0, false
		}
		return net.IP(a[0:4]).String(), int(binary.BigEndian.Uint16(a[4:6])), true
	case 4: // IPv6
		if len(a) != 16+2 {
			return "", 0, false
		}
		return net.IP(a[0:16]).String(), int(binary.BigEndian.Uint16(a[16:18])), true
	case 3: // domain: 1-octet length + name (no NUL), then port
		if len(a) < 1 {
			return "", 0, false
		}
		dl := int(a[0])
		if len(a) != 1+dl+2 {
			return "", 0, false
		}
		return string(a[1 : 1+dl]), int(binary.BigEndian.Uint16(a[1+dl : 1+dl+2])), true
	}
	return "", 0, false
}

func isATYP(b byte) bool { return b == 1 || b == 3 || b == 4 }

func atypName(a byte) string {
	switch a {
	case 1:
		return "ipv4"
	case 3:
		return "domain"
	case 4:
		return "ipv6"
	}
	return fmt.Sprintf("0x%02x", a)
}

func v5Command(c int) string {
	switch c {
	case 1:
		return "CONNECT"
	case 2:
		return "BIND"
	case 3:
		return "UDP ASSOCIATE"
	}
	return fmt.Sprintf("cmd-%d", c)
}

func v5ReplyName(c int) string {
	names := []string{
		"succeeded", "general SOCKS server failure", "connection not allowed by ruleset",
		"network unreachable", "host unreachable", "connection refused", "TTL expired",
		"command not supported", "address type not supported",
	}
	if c >= 0 && c < len(names) {
		return names[c]
	}
	return fmt.Sprintf("reply-%d", c)
}

func v5Method(m byte) string {
	switch m {
	case 0x00:
		return "no authentication"
	case 0x01:
		return "GSSAPI"
	case 0x02:
		return "username/password"
	case 0xff:
		return "no acceptable methods"
	}
	if m >= 0x80 && m <= 0xfe {
		return fmt.Sprintf("private method 0x%02x", m)
	}
	return fmt.Sprintf("IANA-assigned 0x%02x", m)
}

func v4Command(c int) string {
	switch c {
	case 1:
		return "CONNECT"
	case 2:
		return "BIND"
	}
	return fmt.Sprintf("cmd-%d", c)
}

func v4ReplyName(c int) string {
	switch c {
	case 90:
		return "request granted"
	case 91:
		return "request rejected or failed"
	case 92:
		return "request rejected: SOCKS server cannot connect to identd"
	case 93:
		return "request rejected: user-id mismatch"
	}
	return fmt.Sprintf("reply-%d", c)
}

func nulString(b []byte) (string, []byte) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:]
		}
	}
	return string(b), nil
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
		return nil, fmt.Errorf("socks: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("socks: input is not valid hex: %w", err)
	}
	return b, nil
}
