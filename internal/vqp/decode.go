// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vqp decodes the Cisco VLAN Query Protocol (VQP) — the wire
// protocol of VMPS (VLAN Membership Policy Server), by which a switch
// asks a server "what VLAN should this source MAC be put on?" and the
// server answers with a VLAN name (UDP 1589). VQP is the third leg of
// the project's Cisco VLAN-attack decoder family alongside internal/dtp
// (DTP, trunk-negotiation VLAN-hopping) and internal/vtp (VTP,
// VLAN-database tampering): dynamic VLAN assignment by MAC is an attack
// surface — a host that spoofs a MAC the server maps to a privileged
// VLAN (e.g. a voice / management VLAN, the voiphopper / yersinia
// technique) lands its port in that VLAN, and a server that answers with
// errorcode shutdownPort / accessDenied is the lockout response. A
// captured VQP exchange reveals the queried **MAC**, the switch **port**,
// the VTP **domain** and the assigned **VLAN name**.
//
// # Wrap-vs-native judgement
//
//	Native. VQP is a fixed 8-byte header (version / opcode / response
//	code / data-count / sequence) followed by a list of
//	type(4)+length(2)+value entries — a byte-field read + a TLV walk.
//	stdlib only (net for the IP/MAC formatting), no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header and the entry TLV layout (datatype enum 0x0C01..0x0C08)
//	were verified field-for-field against scapy's VQP layer
//	(scapy.contrib.vqp). Typed entry values are decoded by their
//	datatype: clientIPAddress -> IPv4, Req/ResMACAddress -> MAC, the
//	name fields (portName / VLANName / Domain) -> printable ASCII; the
//	ethernetPacket / unknown entry bodies are surfaced as raw hex. A
//	non-printable name body is surfaced as hex rather than mangled.
package vqp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Entry is one decoded VQP data field.
type Entry struct {
	DataType     int    `json:"data_type"`
	DataTypeName string `json:"data_type_name"`
	Length       int    `json:"length"`
	Value        string `json:"value,omitempty"`
	ValueHex     string `json:"value_hex,omitempty"`
}

// Result is the decoded view of a VQP message.
type Result struct {
	Version      int      `json:"version"`
	Opcode       int      `json:"opcode"`
	OpcodeName   string   `json:"opcode_name"`
	ResponseCode int      `json:"response_code"`
	ResponseName string   `json:"response_code_name"`
	Flag         int      `json:"flag"`
	FlagName     string   `json:"flag_name,omitempty"`
	Sequence     uint32   `json:"sequence"`
	Entries      []Entry  `json:"entries"`
	Notes        []string `json:"notes,omitempty"`
}

// Decode parses a VQP message (the UDP-1589 payload) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("vqp: %d bytes — too short for the 8-byte VQP header", len(b))
	}
	if b[0] != 0x01 {
		return nil, fmt.Errorf("vqp: version byte 0x%02x is not 0x01 (not VQP)", b[0])
	}
	r := &Result{
		Version:      int(b[0]),
		Opcode:       int(b[1]),
		OpcodeName:   opcodeName(b[1]),
		ResponseCode: int(b[2]),
		ResponseName: responseName(b[2]),
		Flag:         int(b[3]),
		FlagName:     flagName(b[3]),
		Sequence:     binary.BigEndian.Uint32(b[4:8]),
	}
	off := 8
	for off+6 <= len(b) {
		dt := int(binary.BigEndian.Uint32(b[off : off+4]))
		ln := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		off += 6
		if off+ln > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf("entry datatype 0x%04X claims %d bytes but only %d remain — truncated", dt, ln, len(b)-off))
			break
		}
		val := b[off : off+ln]
		off += ln
		r.Entries = append(r.Entries, decodeEntry(dt, ln, val))
	}
	if r.OpcodeName == "responseVLAN" && (r.ResponseCode == 3 || r.ResponseCode == 4) {
		r.Notes = append(r.Notes, "VMPS denied the port: response code "+r.ResponseName+" — the switch will deny access or shut the port down (the VMPS lockout response)")
	}
	r.Notes = append(r.Notes,
		"VMPS assigns a port's VLAN by source MAC: the ReqMACAddress + VLANName fields reveal the MAC-to-VLAN mapping; spoofing a MAC the server maps to a privileged VLAN (e.g. a voice / management VLAN) is the voiphopper / yersinia VLAN-assignment attack",
		"ethernetPacket / unknown entry bodies are surfaced as raw hex (varied content)")
	return r, nil
}

func decodeEntry(dt, ln int, val []byte) Entry {
	e := Entry{DataType: dt, DataTypeName: dataTypeName(dt), Length: ln}
	switch dt {
	case 0x0C01: // clientIPAddress
		if ln == 4 {
			e.Value = net.IP(val).String()
			return e
		}
	case 0x0C06, 0x0C08: // ReqMACAddress / ResMACAddress
		if ln == 6 {
			e.Value = net.HardwareAddr(val).String()
			return e
		}
	case 0x0C02, 0x0C03, 0x0C04: // portName / VLANName / Domain
		if s, ok := printableASCII(val); ok {
			e.Value = s
			return e
		}
	}
	e.ValueHex = hexUpper(val)
	return e
}

func opcodeName(o byte) string {
	switch o {
	case 1:
		return "requestPort"
	case 2:
		return "responseVLAN"
	case 3:
		return "requestReconfirm"
	case 4:
		return "responseReconfirm"
	}
	return fmt.Sprintf("unknown(%d)", o)
}

func responseName(c byte) string {
	switch c {
	case 0:
		return "none"
	case 3:
		return "accessDenied"
	case 4:
		return "shutdownPort"
	case 5:
		return "wrongDomain"
	}
	return fmt.Sprintf("unknown(%d)", c)
}

func flagName(f byte) string {
	switch f {
	case 2:
		return "inGoodResponse"
	case 6:
		return "inRequests"
	}
	return ""
}

func dataTypeName(dt int) string {
	switch dt {
	case 0x0C01:
		return "clientIPAddress"
	case 0x0C02:
		return "portName"
	case 0x0C03:
		return "VLANName"
	case 0x0C04:
		return "Domain"
	case 0x0C05:
		return "ethernetPacket"
	case 0x0C06:
		return "ReqMACAddress"
	case 0x0C07:
		return "unknown"
	case 0x0C08:
		return "ResMACAddress"
	}
	return fmt.Sprintf("0x%04X", dt)
}

func printableASCII(b []byte) (string, bool) {
	s := strings.TrimRight(string(b), "\x00")
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return s, true
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
		return nil, fmt.Errorf("vqp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("vqp: input is not valid hex: %w", err)
	}
	return b, nil
}
