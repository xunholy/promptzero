// SPDX-License-Identifier: AGPL-3.0-or-later

// Package xcp decodes XCP — the ASAM MCD-1 XCP Universal Measurement and
// Calibration Protocol — the master/slave protocol an ECU calibration tool
// uses to read and write an ECU's memory: measurement (DAQ/STIM), calibration
// (download), and flash programming (PROGRAM). It runs over CAN (XCP-on-CAN),
// Ethernet, FlexRay and others. XCP is a real automotive-security target: it
// exposes direct ECU memory upload/download and a PROGRAM (reflash) sequence,
// and access protection is the optional SEED & KEY (GET_SEED / UNLOCK)
// handshake that is frequently weak or absent — so an attacker on the bus who
// speaks XCP can read calibration/firmware, tamper with calibration values, or
// reflash the ECU. A captured XCP packet identifies the **operation** in
// flight — a session CONNECT, a SEED & KEY auth, a memory UPLOAD (read), a
// calibration DOWNLOAD (write), a PROGRAM flash sequence — or, on the slave
// side, the positive/negative response (with the error code) — which is the
// recon headline for ECU calibration-bus reconnaissance. It joins the
// project's automotive family (internal/uds, kwp, obd2, isotp, canfd, j1850).
//
// # Wrap-vs-native judgement
//
//	Native. An XCP packet is a 1-byte Packet Identifier (PID) — the command
//	code (master → slave) or the response/error/event class (slave → master)
//	— followed by command-specific parameters. A byte lookup + a small
//	sub-code table for the error / event packets; stdlib only, no new go.mod
//	dep.
//
// # Verifiable / no confidently-wrong output
//
//	The command-code table (0xC7-0xFF), the error-code table and the
//	event-code table are code-generated from scapy's authoritative XCP layer
//	(scapy.contrib.automotive.xcp). XCP is direction-dependent — the same PID
//	(0xFC-0xFF) is a command master → slave but a response/event/service class
//	slave → master — so the caller supplies the direction; without it the
//	command interpretation is used and the ambiguity is noted. Only the PID +
//	(for ERR/EV) the sub-code are decoded; the command/response parameters are
//	surfaced as raw hex (their layout is command-specific and often
//	address-granularity-dependent), never reinterpreted here.
package xcp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an XCP packet.
type Result struct {
	PID       int    `json:"pid"`
	PIDHex    string `json:"pid_hex"`
	Direction string `json:"direction"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`

	ErrorCodeHex string `json:"error_code_hex,omitempty"`
	ErrorName    string `json:"error_name,omitempty"`
	EventCodeHex string `json:"event_code_hex,omitempty"`
	EventName    string `json:"event_name,omitempty"`

	SecurityRelevance string   `json:"security_relevance,omitempty"`
	PayloadHex        string   `json:"payload_hex,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

// Decode parses an XCP packet (the CTO/DTO starting at the PID byte) from hex.
// direction selects the interpretation: "command" / "master" (master → slave,
// the default) or "response" / "slave" (slave → master). Separators (':' '-'
// '_' whitespace) and a '0x' prefix are tolerated.
func Decode(input, direction string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("xcp: empty — need at least the PID byte")
	}
	pid := b[0]
	r := &Result{PID: int(pid), PIDHex: fmt.Sprintf("0x%02X", pid)}

	resp := false
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "response", "slave", "s2m", "slave-to-master":
		resp = true
		r.Direction = "response (slave → master)"
	case "", "command", "master", "m2s", "master-to-slave":
		r.Direction = "command (master → slave)"
		if direction == "" {
			r.Notes = append(r.Notes, "direction not specified — interpreted as a command (master → slave); for a slave response pass direction=response (the PID 0xFC-0xFF are ambiguous between command and response)")
		}
	default:
		return nil, fmt.Errorf("xcp: unknown direction %q (use 'command' or 'response')", direction)
	}

	body := b[1:]
	if resp {
		decodeResponse(r, pid, body)
	} else {
		decodeCommand(r, pid, body)
	}
	if len(body) > 0 && r.PayloadHex == "" {
		r.PayloadHex = strings.ToUpper(hex.EncodeToString(body))
	}
	r.Notes = append(r.Notes, "ASAM XCP (Universal Measurement and Calibration Protocol) — the ECU calibration/measurement/flash bus; command parameters are surfaced raw (address-granularity-dependent)")
	return r, nil
}

func decodeCommand(r *Result, pid byte, body []byte) {
	switch {
	case pid >= 0xC7:
		r.Kind = "command"
		r.Name = commandName(pid)
		r.SecurityRelevance = commandSecurity(pid)
	case pid <= 0xBF:
		r.Kind = "stim"
		r.Name = "STIM (stimulation DTO — master-written measurement data)"
	default: // 0xC0-0xC6
		r.Kind = "command"
		r.Name = fmt.Sprintf("reserved/unknown command 0x%02X", pid)
	}
}

func decodeResponse(r *Result, pid byte, body []byte) {
	switch pid {
	case 0xFF:
		r.Kind = "positive_response"
		r.Name = "RES (positive response)"
	case 0xFE:
		r.Kind = "error"
		r.Name = "ERR (negative response)"
		if len(body) >= 1 {
			r.ErrorCodeHex = fmt.Sprintf("0x%02X", body[0])
			r.ErrorName = errorName(body[0])
		}
	case 0xFD:
		r.Kind = "event"
		r.Name = "EV (event)"
		if len(body) >= 1 {
			r.EventCodeHex = fmt.Sprintf("0x%02X", body[0])
			r.EventName = eventName(body[0])
		}
	case 0xFC:
		r.Kind = "service_request"
		r.Name = "SERV (service request)"
	default: // 0x00-0xFB
		r.Kind = "daq"
		r.Name = "DAQ (data acquisition DTO — slave measurement data)"
	}
}

// commandSecurity flags the security-relevant XCP commands.
func commandSecurity(pid byte) string {
	switch pid {
	case 0xFF:
		return "session start (CONNECT)"
	case 0xF8, 0xF7:
		return "SEED & KEY authentication — GET_SEED / UNLOCK grant access to protected resources; weak or absent here is the access-control gap"
	case 0xF5, 0xF4:
		return "ECU memory READ (UPLOAD) — calibration / firmware exfiltration"
	case 0xF0, 0xEF, 0xEE, 0xED, 0xEC:
		return "ECU memory WRITE (DOWNLOAD / MODIFY_BITS) — calibration tampering"
	}
	if pid >= 0xC8 && pid <= 0xD2 {
		return "FLASH programming (PROGRAM sequence) — ECU reflash"
	}
	return ""
}

func commandName(pid byte) string {
	names := map[byte]string{
		0xC7: "WRITE_DAQ_MULTIPLE",
		0xC8: "PROGRAM_VERIFY",
		0xC9: "PROGRAM_MAX",
		0xCA: "PROGRAM_NEXT",
		0xCB: "PROGRAM_FORMAT",
		0xCC: "PROGRAM_PREPARE",
		0xCD: "GET_SECTOR_INFO",
		0xCE: "GET_PGM_PROCESSOR_INFO",
		0xCF: "PROGRAM_RESET",
		0xD0: "PROGRAM",
		0xD1: "PROGRAM_CLEAR",
		0xD2: "PROGRAM_START",
		0xD3: "ALLOC_ODT_ENTRY",
		0xD4: "ALLOC_ODT",
		0xD5: "ALLOC_DAQ",
		0xD6: "FREE_DAQ",
		0xD7: "GET_DAQ_EVENT_INFO",
		0xD8: "GET_DAQ_LIST_INFO",
		0xD9: "GET_DAQ_RESOLUTION_INFO",
		0xDA: "GET_DAQ_PROCESSOR_INFO",
		0xDB: "READ_DAQ",
		0xDC: "GET_DAQ_CLOCK",
		0xDD: "START_STOP_SYNCH",
		0xDE: "START_STOP_DAQ_LIST",
		0xDF: "GET_DAQ_LIST_MODE",
		0xE0: "SET_DAQ_LIST_MODE",
		0xE1: "WRITE_DAQ",
		0xE2: "SET_DAQ_PTR",
		0xE3: "CLEAR_DAQ_LIST",
		0xE4: "COPY_CAL_PAGE",
		0xE5: "GET_SEGMENT_MODE",
		0xE6: "SET_SEGMENT_MODE",
		0xE7: "GET_PAGE_INFO",
		0xE8: "GET_SEGMENT_INFO",
		0xE9: "GET_PAG_PROCESSOR_INFO",
		0xEA: "GET_CAL_PAGE",
		0xEB: "SET_CAL_PAGE",
		0xEC: "MODIFY_BITS",
		0xED: "SHORT_DOWNLOAD",
		0xEE: "DOWNLOAD_MAX",
		0xEF: "DOWNLOAD_NEXT",
		0xF0: "DOWNLOAD",
		0xF1: "USER_CMD",
		0xF2: "TRANSPORT_LAYER_CMD",
		0xF3: "BUILD_CHECKSUM",
		0xF4: "SHORT_UPLOAD",
		0xF5: "UPLOAD",
		0xF6: "SET_MTA",
		0xF7: "UNLOCK",
		0xF8: "GET_SEED",
		0xF9: "SET_REQUEST",
		0xFA: "GET_ID",
		0xFB: "GET_COMM_MODE_INFO",
		0xFC: "SYNCH",
		0xFD: "GET_STATUS",
		0xFE: "DISCONNECT",
		0xFF: "CONNECT",
	}
	if n, ok := names[pid]; ok {
		return n
	}
	return fmt.Sprintf("unknown command 0x%02X", pid)
}

func errorName(c byte) string {
	names := map[byte]string{
		0x00: "ERR_CMD_SYNCH",
		0x10: "ERR_CMD_BUSY",
		0x11: "ERR_DAQ_ACTIVE",
		0x12: "ERR_PGM_ACTIVE",
		0x20: "ERR_CMD_UNKNOWN",
		0x21: "ERR_CMD_SYNTAX",
		0x22: "ERR_OUT_OF_RANGE",
		0x23: "ERR_WRITE_PROTECTED",
		0x24: "ERR_ACCESS_DENIED",
		0x25: "ERR_ACCESS_LOCKED",
		0x26: "ERR_PAGE_NOT_VALID",
		0x27: "ERR_MODE_NOT_VALID",
		0x28: "ERR_SEGMENT_NOT_VALID",
		0x29: "ERR_SEQUENCE",
		0x2A: "ERR_DAQ_CONFIG",
		0x30: "ERR_MEMORY_OVERFLOW",
		0x31: "ERR_GENERIC",
		0x32: "ERR_VERIFY",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("unknown error 0x%02X", c)
}

func eventName(c byte) string {
	names := map[byte]string{
		0x00: "EV_RESUME_MODE",
		0x01: "EV_CLEAR_DAQ",
		0x02: "EV_STORE_DAQ",
		0x03: "EV_STORE_CAL",
		0x05: "EV_CMD_PENDING",
		0x06: "EV_DAQ_OVERLOAD",
		0x07: "EV_SESSION_TERMINATED",
		0xFE: "EV_USER",
		0xFF: "EV_TRANSPORT",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("unknown event 0x%02X", c)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("xcp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("xcp: input is not valid hex: %w", err)
	}
	return b, nil
}
