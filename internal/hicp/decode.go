// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hicp decodes HICP (Host IP Configuration Protocol, UDP 3250) —
// the HMS Anybus protocol for discovering and (re)configuring industrial
// Ethernet gateway modules. It joins the project's OT / ICS decoder family
// (modbus, dnp3, iec104, s7comm, enip, profinetdcp, opcua, ethercat,
// knxnetip) as an industrial device-discovery decoder, the HMS-Anybus
// analogue of profinetdcp. HICP is an OT attack surface: a broadcast
// **Module Scan** enumerates every Anybus gateway on the segment, and a
// **Configure** message can change a module's IP / subnet / gateway /
// hostname — and the Module Scan Response advertises whether the module is
// password-protected (PSWD = OFF means that reconfiguration is
// unauthenticated). A captured HICP exchange is industrial-asset inventory
// + a misconfiguration / hijack signal.
//
// # Wrap-vs-native judgement
//
//	Native. HICP is a small text protocol: a command keyword, then a list
//	of "Key = value;" pairs terminated by a NUL. A prefix check + a
//	key-value split; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The message-type detection and the Key=value field parsing were
//	verified against scapy's HICP layer (scapy.contrib.hicp). The HICP
//	specification is not public — scapy itself is built from the Wireshark
//	dissector + the HMS DLL — so the parser is deliberately generic: it
//	surfaces every Key=value pair it finds (mapping the documented keys to
//	named fields and keeping the rest), and normalises the MAC (HICP is
//	inconsistent, using both '-' and ':' separators). Nothing is guessed
//	beyond the documented key set.
package hicp

import (
	"fmt"
	"net"
	"strings"
)

// Field is one parsed HICP "Key = value" pair.
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Result is the decoded view of a HICP message.
type Result struct {
	MessageType string `json:"message_type"`

	ProtocolVersion string `json:"protocol_version,omitempty"`
	FieldbusType    string `json:"fieldbus_type,omitempty"`
	ModuleVersion   string `json:"module_version,omitempty"`
	MACAddress      string `json:"mac_address,omitempty"`
	IPAddress       string `json:"ip_address,omitempty"`
	SubnetMask      string `json:"subnet_mask,omitempty"`
	GatewayAddress  string `json:"gateway_address,omitempty"`
	DHCP            string `json:"dhcp,omitempty"`
	PasswordState   string `json:"password,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	DNS1            string `json:"dns1,omitempty"`
	DNS2            string `json:"dns2,omitempty"`
	TargetMAC       string `json:"target_mac,omitempty"` // Configure

	Fields []Field  `json:"fields,omitempty"`
	Notes  []string `json:"notes,omitempty"`
}

// Decode parses a HICP message (the UDP-3250 payload) from hex (whitespace
// / ':' / '-' / '_' separators and a '0x' prefix tolerated) — or accepts
// the raw ASCII message directly.
func Decode(input string) (*Result, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, fmt.Errorf("hicp: empty input")
	}
	// HICP is an ASCII protocol; accept the text directly, or hex if it
	// decodes and looks like the HICP text.
	text := s
	if b, ok := tryHex(s); ok {
		text = string(b)
	}
	text = strings.TrimRight(text, "\x00")
	r := &Result{}

	switch {
	case hasPrefixFold(text, "Module scan response"):
		r.MessageType = "module_scan_response"
		parseFields(r, text)
	case hasPrefixFold(text, "Module scan"):
		r.MessageType = "module_scan"
		r.Notes = append(r.Notes, "HICP Module Scan: a broadcast that enumerates every HMS Anybus gateway on the segment")
		return r, nil
	case hasPrefixFold(text, "Configure"):
		r.MessageType = "configure"
		// "Configure: <target-mac>;Key = value;..."
		rest := text
		if i := strings.IndexByte(text, ':'); i >= 0 {
			rest = text[i+1:]
		}
		if j := strings.IndexByte(rest, ';'); j >= 0 {
			r.TargetMAC = normaliseMAC(strings.TrimSpace(rest[:j]))
		}
		parseFields(r, text)
		r.Notes = append(r.Notes, "HICP Configure: re-programs a module's IP / subnet / gateway / hostname — an unauthenticated reconfiguration / hijack if the module has no password set")
	case hasPrefixFold(text, "Reconfigured"):
		r.MessageType = "reconfigured"
	case hasPrefixFold(text, "Invalid Configuration"):
		r.MessageType = "invalid_configuration"
	case hasPrefixFold(text, "Invalid Password"):
		r.MessageType = "invalid_password"
	case hasPrefixFold(text, "To:"):
		r.MessageType = "wink"
		r.TargetMAC = normaliseMAC(strings.TrimSpace(strings.TrimPrefix(text, "To:")))
	case strings.Contains(text, "="):
		// A bare Key=value blob is a Module Scan Response (the response
		// carries no command keyword).
		r.MessageType = "module_scan_response"
		parseFields(r, text)
	default:
		return nil, fmt.Errorf("hicp: %q is not a recognised HICP message", trunc(text))
	}

	if r.MessageType == "module_scan_response" {
		r.Notes = append(r.Notes, "HICP Module Scan Response: an HMS Anybus gateway advertising its identity + network config (industrial-asset inventory)")
		if strings.EqualFold(r.PasswordState, "OFF") {
			r.Notes = append(r.Notes, "PSWD = OFF: the module accepts unauthenticated Configure — it can be re-IP'd / renamed by any host on the segment")
		}
	}
	return r, nil
}

// parseFields splits the "Key = value;" list and maps the documented keys.
func parseFields(r *Result, text string) {
	for _, part := range strings.Split(text, ";") {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(part[:eq])
		val := strings.TrimSpace(part[eq+1:])
		if key == "" {
			continue
		}
		r.Fields = append(r.Fields, Field{Key: key, Value: val})
		switch strings.ToUpper(key) {
		case "PROTOCOL VERSION":
			r.ProtocolVersion = val
		case "FB TYPE":
			r.FieldbusType = val
		case "MODULE VERSION":
			r.ModuleVersion = val
		case "MAC":
			r.MACAddress = normaliseMAC(val)
		case "IP":
			r.IPAddress = val
		case "SN":
			r.SubnetMask = val
		case "GW":
			r.GatewayAddress = val
		case "DHCP":
			r.DHCP = val
		case "PSWD":
			r.PasswordState = val
		case "HN":
			r.Hostname = val
		case "DNS1":
			r.DNS1 = val
		case "DNS2":
			r.DNS2 = val
		}
	}
}

// normaliseMAC accepts the HICP MAC in either '-' or ':' form and returns
// the canonical colon form; non-MAC values are returned unchanged.
func normaliseMAC(s string) string {
	c := strings.ReplaceAll(s, "-", ":")
	if hw, err := net.ParseMAC(c); err == nil {
		return hw.String()
	}
	return s
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func tryHex(s string) ([]byte, bool) {
	t := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	t = rep.Replace(t)
	if t == "" || len(t)%2 != 0 {
		return nil, false
	}
	b := make([]byte, len(t)/2)
	for i := 0; i < len(b); i++ {
		hi, ok1 := hexVal(t[2*i])
		lo, ok2 := hexVal(t[2*i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		b[i] = hi<<4 | lo
	}
	// Only treat as hex when the decoded bytes look like the HICP ASCII text
	// (printable + the '=' / ';' it uses); otherwise the input was plain text.
	if !looksLikeHICPText(b) {
		return nil, false
	}
	return b, true
}

func looksLikeHICPText(b []byte) bool {
	hasEq := false
	for _, c := range b {
		if c == '=' {
			hasEq = true
		}
		if c != 0 && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return hasEq || hasPrefixFold(string(b), "Module scan") || hasPrefixFold(string(b), "To:")
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func trunc(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
