// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hci decodes Bluetooth HCI (Host Controller Interface) packets — the
// transport between a Bluetooth host stack and its controller, and exactly
// what a btsnoop / hcidump capture contains. Every Bluetooth and BLE operation
// passes through HCI, so decoding an HCI capture is the foundational view of
// what a host (or an attacker's host) is doing: scanning, advertising,
// connecting, reading a remote's features, setting advertising data. It is the
// transport layer beneath the project's BLE decoders (internal/ble, btuuid,
// the GATT / advertising tooling). A captured HCI packet identifies the
// **operation** — a command (with its OGF group + opcode, e.g. LE Set Scan
// Enable / LE Create Connection / LE Set Advertising Data), an event (Command
// Complete / Command Status / Disconnection / an LE Meta sub-event such as an
// Advertising Report or Connection Complete), or an ACL data fragment — which
// is the recon headline for Bluetooth-stack analysis.
//
// # Wrap-vs-native judgement
//
//	Native. An HCI (H4) packet is a 1-byte transport indicator then a small
//	fixed header: a command is a 16-bit little-endian opcode (OGF in the top 6
//	bits, OCF in the low 10) + a length; an event is a code + a length; ACL is
//	a handle/flags word + a length. A byte read + bit-field splits + opcode /
//	event tables; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The H4 transport indicators, the OGF groups, the well-known command
//	opcodes, the event codes and the LE-Meta sub-event codes follow the
//	Bluetooth Core specification (scapy's HCI type field carries non-standard
//	extras, so the spec is the authority). The well-known opcodes / events are
//	named; an opcode outside the named set is reported by its OGF group + OCF
//	(never guessed), and an unknown event by code. The command / event
//	parameters are surfaced as raw hex (they are per-command and the table is
//	vast) except where a fixed, unambiguous field is defined — the Command
//	Complete / Command Status embedded opcode, and the LE-Meta sub-event code.
package hci

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a Bluetooth HCI packet.
type Result struct {
	PacketType    string `json:"packet_type"`
	PacketTypeHex string `json:"packet_type_hex"`

	// Command
	OpcodeHex   string `json:"opcode_hex,omitempty"`
	OGF         string `json:"ogf,omitempty"`
	OCF         string `json:"ocf,omitempty"`
	CommandName string `json:"command_name,omitempty"`

	// Event
	EventCodeHex string `json:"event_code_hex,omitempty"`
	EventName    string `json:"event_name,omitempty"`
	SubeventName string `json:"le_subevent_name,omitempty"`
	ForOpcodeHex string `json:"for_command_opcode,omitempty"` // Command Complete/Status
	ForCommand   string `json:"for_command_name,omitempty"`

	// ACL
	ConnectionHandle string `json:"connection_handle,omitempty"`

	ParamLength int      `json:"param_length,omitempty"`
	ParamsHex   string   `json:"params_hex,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

// Decode parses a Bluetooth HCI (H4) packet — the transport indicator byte
// then the HCI packet — from hex (whitespace / ':' / '-' / '_' separators and
// a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("hci: empty input")
	}
	ptype := b[0]
	r := &Result{PacketTypeHex: fmt.Sprintf("0x%02X", ptype), PacketType: packetType(ptype)}
	body := b[1:]

	switch ptype {
	case 0x01: // Command
		if len(body) < 3 {
			return r, fmt.Errorf("hci: command truncated (need opcode + length)")
		}
		op := binary.LittleEndian.Uint16(body[0:2])
		setOpcode(r, op)
		r.ParamLength = int(body[2])
		if len(body) > 3 {
			r.ParamsHex = hexUpper(body[3:])
		}
	case 0x04: // Event
		if len(body) < 2 {
			return r, fmt.Errorf("hci: event truncated (need code + length)")
		}
		code := body[0]
		r.EventCodeHex = fmt.Sprintf("0x%02X", code)
		r.EventName = eventName(code)
		r.ParamLength = int(body[1])
		params := body[2:]
		switch code {
		case 0x0E: // Command Complete: num_pkts(1) opcode(2) ...
			if len(params) >= 3 {
				op := binary.LittleEndian.Uint16(params[1:3])
				r.ForOpcodeHex = fmt.Sprintf("0x%04X", op)
				r.ForCommand = commandName(op)
			}
		case 0x0F: // Command Status: status(1) num_pkts(1) opcode(2)
			if len(params) >= 4 {
				op := binary.LittleEndian.Uint16(params[2:4])
				r.ForOpcodeHex = fmt.Sprintf("0x%04X", op)
				r.ForCommand = commandName(op)
			}
		case 0x3E: // LE Meta: subevent(1) ...
			if len(params) >= 1 {
				r.SubeventName = leSubevent(params[0])
			}
		}
		if len(params) > 0 {
			r.ParamsHex = hexUpper(params)
		}
	case 0x02: // ACL data
		if len(body) < 4 {
			return r, fmt.Errorf("hci: ACL packet truncated (need handle + length)")
		}
		hf := binary.LittleEndian.Uint16(body[0:2])
		r.ConnectionHandle = fmt.Sprintf("0x%03X (PB=%d BC=%d)", hf&0x0FFF, (hf>>12)&0x3, (hf>>14)&0x3)
		r.ParamLength = int(binary.LittleEndian.Uint16(body[2:4]))
		if len(body) > 4 {
			r.ParamsHex = hexUpper(body[4:])
		}
	default:
		if len(body) > 0 {
			r.ParamsHex = hexUpper(body)
		}
	}

	r.Notes = append(r.Notes, "Bluetooth HCI (H4) — the host↔controller transport (btsnoop / hcidump); the command opcode / event code names the operation; parameters are surfaced raw (per-command)")
	return r, nil
}

func setOpcode(r *Result, op uint16) {
	ogf := op >> 10
	ocf := op & 0x03FF
	r.OpcodeHex = fmt.Sprintf("0x%04X", op)
	r.OGF = fmt.Sprintf("0x%02X (%s)", ogf, ogfName(byte(ogf)))
	r.OCF = fmt.Sprintf("0x%03X", ocf)
	r.CommandName = commandName(op)
}

func packetType(t byte) string {
	switch t {
	case 0x01:
		return "Command"
	case 0x02:
		return "ACL Data"
	case 0x03:
		return "Synchronous (SCO) Data"
	case 0x04:
		return "Event"
	case 0x05:
		return "ISO Data"
	}
	return fmt.Sprintf("unknown transport indicator 0x%02X", t)
}

func ogfName(ogf byte) string {
	switch ogf {
	case 0x01:
		return "Link Control"
	case 0x02:
		return "Link Policy"
	case 0x03:
		return "Controller & Baseband"
	case 0x04:
		return "Informational Parameters"
	case 0x05:
		return "Status Parameters"
	case 0x06:
		return "Testing"
	case 0x08:
		return "LE Controller"
	case 0x3F:
		return "Vendor-Specific"
	}
	return "reserved"
}

func commandName(op uint16) string {
	names := map[uint16]string{
		0x0401: "Inquiry",
		0x0405: "Create Connection",
		0x0406: "Disconnect",
		0x0C01: "Set Event Mask",
		0x0C03: "Reset",
		0x0C13: "Write Local Name",
		0x0C1A: "Write Scan Enable",
		0x1001: "Read Local Version Information",
		0x1009: "Read BD_ADDR",
		0x2001: "LE Set Event Mask",
		0x2002: "LE Read Buffer Size",
		0x2005: "LE Set Random Address",
		0x2006: "LE Set Advertising Parameters",
		0x2008: "LE Set Advertising Data",
		0x2009: "LE Set Scan Response Data",
		0x200A: "LE Set Advertise Enable",
		0x200B: "LE Set Scan Parameters",
		0x200C: "LE Set Scan Enable",
		0x200D: "LE Create Connection",
		0x2013: "LE Add Device To Filter Accept List",
		0x2016: "LE Read Remote Features",
		0x2018: "LE Encrypt",
		0x2019: "LE Rand",
		0x201A: "LE Start Encryption",
		0x2022: "LE Set Data Length",
	}
	if n, ok := names[op]; ok {
		return n
	}
	return fmt.Sprintf("command OGF 0x%02X / OCF 0x%03X", op>>10, op&0x03FF)
}

func eventName(c byte) string {
	names := map[byte]string{
		0x01: "Inquiry Complete",
		0x02: "Inquiry Result",
		0x03: "Connection Complete",
		0x04: "Connection Request",
		0x05: "Disconnection Complete",
		0x06: "Authentication Complete",
		0x08: "Encryption Change",
		0x0C: "Read Remote Version Information Complete",
		0x0E: "Command Complete",
		0x0F: "Command Status",
		0x10: "Hardware Error",
		0x13: "Number Of Completed Packets",
		0x1B: "Max Slots Change",
		0x3E: "LE Meta",
		0xFF: "Vendor-Specific",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("event 0x%02X", c)
}

func leSubevent(c byte) string {
	names := map[byte]string{
		0x01: "LE Connection Complete",
		0x02: "LE Advertising Report",
		0x03: "LE Connection Update Complete",
		0x04: "LE Read Remote Features Complete",
		0x05: "LE Long Term Key Request",
		0x06: "LE Remote Connection Parameter Request",
		0x07: "LE Data Length Change",
		0x0A: "LE Enhanced Connection Complete",
		0x0B: "LE Directed Advertising Report",
		0x0D: "LE Extended Advertising Report",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("LE sub-event 0x%02X", c)
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("hci: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hci: input is not valid hex: %w", err)
	}
	return b, nil
}
