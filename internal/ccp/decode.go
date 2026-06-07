// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ccp decodes CCP — the CAN Calibration Protocol (ASAM) — the
// CAN-native predecessor of XCP that an ECU calibration tool uses to read and
// write an ECU's memory: connect to a station, characterise (DAQ) measurement,
// download calibration data, and flash (PROGRAM). It is still in production
// ECUs (especially older GM / European powertrain modules) and is the CAN-bus
// sibling of internal/xcp. CCP is a real automotive-security target: it
// exposes direct ECU memory UPLOAD (read) / DNLOAD (write) and a PROGRAM /
// CLEAR_MEMORY flash sequence, with the only access control being the optional
// GET_SEED / UNLOCK seed-and-key handshake — so an attacker on the CAN bus who
// speaks CCP can exfiltrate calibration/firmware, tamper with calibration, or
// reflash the ECU. A captured CCP frame identifies the **operation** — a
// session CONNECT (and the target station address), a SEED & KEY auth, a
// memory UPLOAD, a calibration DNLOAD, a PROGRAM flash — or, on the slave side,
// the Command Return Message (with its return code), an event, or DAQ
// measurement data. It joins the project's automotive family (internal/xcp,
// uds, kwp, obd2, doip, isotp, canfd).
//
// # Wrap-vs-native judgement
//
//	Native. A CCP frame is the 8-byte CAN payload: a CRO (Command Receive
//	Object — command byte + counter + params, master → slave) or a DTO (Data
//	Transmission Object — a packet id selecting a Command Return Message /
//	event / DAQ data, slave → master). A byte lookup + a small return-code
//	table; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The command table and the return-code table are code-generated from
//	scapy's authoritative CCP layer (scapy.contrib.automotive.ccp). Like XCP,
//	CCP is direction-dependent — a command byte (master → slave) and a DTO
//	packet id (slave → master) share the same byte space — so the caller
//	supplies the direction; without it the command interpretation is used and
//	the ambiguity is noted. Only the command byte / packet id, the counter,
//	the return code and (for CONNECT) the little-endian station address are
//	decoded; the remaining command/response parameters are surfaced as raw hex
//	(their layout is command-specific and address-granularity-dependent),
//	never reinterpreted here.
package ccp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a CCP frame.
type Result struct {
	Direction string `json:"direction"`

	// CRO (command, master → slave)
	Command        string `json:"command,omitempty"`
	CommandHex     string `json:"command_hex,omitempty"`
	CommandCounter *int   `json:"command_counter,omitempty"`
	StationAddress string `json:"station_address,omitempty"`

	// DTO (response/data, slave → master)
	PacketIDHex string `json:"packet_id_hex,omitempty"`
	DTOType     string `json:"dto_type,omitempty"`
	ReturnCode  string `json:"return_code,omitempty"`
	Counter     *int   `json:"counter,omitempty"`

	SecurityRelevance string   `json:"security_relevance,omitempty"`
	ParamsHex         string   `json:"params_hex,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

// Decode parses a CCP frame (the CAN payload) from hex. direction selects the
// interpretation: "command" / "cro" / "master" (master → slave, the default)
// or "response" / "dto" / "slave" (slave → master). Separators (':' '-' '_'
// whitespace) and a '0x' prefix are tolerated.
func Decode(input, direction string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("ccp: empty — need at least one byte")
	}
	r := &Result{}
	resp := false
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "response", "dto", "slave", "s2m":
		resp = true
		r.Direction = "response (DTO, slave → master)"
	case "", "command", "cro", "master", "m2s":
		r.Direction = "command (CRO, master → slave)"
		if direction == "" {
			r.Notes = append(r.Notes, "direction not specified — interpreted as a command (CRO, master → slave); for a slave DTO pass direction=response (the command byte and the DTO packet id share the same byte space)")
		}
	default:
		return nil, fmt.Errorf("ccp: unknown direction %q (use 'command' or 'response')", direction)
	}

	if resp {
		decodeDTO(r, b)
	} else {
		decodeCRO(r, b)
	}
	r.Notes = append(r.Notes, "CCP (CAN Calibration Protocol) — the CAN-native ECU calibration/measurement/flash bus (XCP predecessor); command parameters are surfaced raw (address-granularity-dependent)")
	return r, nil
}

func decodeCRO(r *Result, b []byte) {
	cmd := b[0]
	r.Command = commandName(cmd)
	r.CommandHex = fmt.Sprintf("0x%02X", cmd)
	r.SecurityRelevance = commandSecurity(cmd)
	if len(b) >= 2 {
		ctr := int(b[1])
		r.CommandCounter = &ctr
	}
	// CONNECT (0x01) params: a 2-byte little-endian station address.
	if cmd == 0x01 && len(b) >= 4 {
		r.StationAddress = fmt.Sprintf("0x%04X", binary.LittleEndian.Uint16(b[2:4]))
	}
	if len(b) > 2 {
		r.ParamsHex = strings.ToUpper(hex.EncodeToString(b[2:]))
	}
}

func decodeDTO(r *Result, b []byte) {
	pid := b[0]
	r.PacketIDHex = fmt.Sprintf("0x%02X", pid)
	switch pid {
	case 0xFF: // Command Return Message
		r.DTOType = "Command Return Message (CRM)"
		if len(b) >= 2 {
			r.ReturnCode = returnCodeName(b[1])
		}
		if len(b) >= 3 {
			ctr := int(b[2])
			r.Counter = &ctr
		}
		if len(b) > 3 {
			r.ParamsHex = strings.ToUpper(hex.EncodeToString(b[3:]))
		}
	case 0xFE: // Event message
		r.DTOType = "Event message"
		if len(b) >= 2 {
			r.ReturnCode = returnCodeName(b[1])
		}
		if len(b) > 2 {
			r.ParamsHex = strings.ToUpper(hex.EncodeToString(b[2:]))
		}
	default: // 0x00-0xFD — DAQ-DTO (the ODT number)
		r.DTOType = fmt.Sprintf("DAQ-DTO (ODT number %d — measurement data)", pid)
		if len(b) > 1 {
			r.ParamsHex = strings.ToUpper(hex.EncodeToString(b[1:]))
		}
	}
}

// commandSecurity flags the security-relevant CCP commands.
func commandSecurity(cmd byte) string {
	switch cmd {
	case 0x01:
		return "session start (CONNECT)"
	case 0x12, 0x13:
		return "SEED & KEY authentication — GET_SEED / UNLOCK grant access to protected resources; the only CCP access control"
	case 0x04, 0x0F:
		return "ECU memory READ (UPLOAD / SHORT_UP) — calibration / firmware exfiltration"
	case 0x03, 0x23, 0x19:
		return "ECU memory WRITE (DNLOAD / MOVE) — calibration tampering"
	case 0x18, 0x22, 0x10:
		return "FLASH programming (PROGRAM / CLEAR_MEMORY) — ECU reflash"
	}
	return ""
}

func commandName(cmd byte) string {
	names := map[byte]string{
		0x01: "CONNECT",
		0x02: "SET_MTA",
		0x03: "DNLOAD",
		0x04: "UPLOAD",
		0x05: "TEST",
		0x06: "START_STOP",
		0x07: "DISCONNECT",
		0x08: "START_STOP_ALL",
		0x09: "GET_ACTIVE_CAL_PAGE",
		0x0C: "SET_S_STATUS",
		0x0D: "GET_S_STATUS",
		0x0E: "BUILD_CHKSUM",
		0x0F: "SHORT_UP",
		0x10: "CLEAR_MEMORY",
		0x11: "SELECT_CAL_PAGE",
		0x12: "GET_SEED",
		0x13: "UNLOCK",
		0x14: "GET_DAQ_SIZE",
		0x15: "SET_DAQ_PTR",
		0x16: "WRITE_DAQ",
		0x17: "EXCHANGE_ID",
		0x18: "PROGRAM",
		0x19: "MOVE",
		0x1B: "GET_CCP_VERSION",
		0x20: "DIAG_SERVICE",
		0x21: "ACTION_SERVICE",
		0x22: "PROGRAM_6",
		0x23: "DNLOAD_6",
	}
	if n, ok := names[cmd]; ok {
		return n
	}
	return fmt.Sprintf("unknown command 0x%02X", cmd)
}

func returnCodeName(c byte) string {
	names := map[byte]string{
		0x00: "acknowledge / no error",
		0x01: "DAQ processor overload",
		0x10: "command processor busy",
		0x11: "DAQ processor busy",
		0x12: "internal timeout",
		0x18: "key request",
		0x19: "session status request",
		0x20: "cold start request",
		0x21: "cal. data init. request",
		0x22: "DAQ list init. request",
		0x23: "code update request",
		0x30: "unknown command",
		0x31: "command syntax",
		0x32: "parameter(s) out of range",
		0x33: "access denied",
		0x34: "overload",
		0x35: "access locked",
		0x36: "resource/function not available",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", c)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("ccp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ccp: input is not valid hex: %w", err)
	}
	return b, nil
}
