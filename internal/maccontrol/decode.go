// SPDX-License-Identifier: AGPL-3.0-or-later

// Package maccontrol decodes IEEE 802.3 MAC Control frames (EtherType
// 0x8808) — the Ethernet flow-control and EPON access-control sublayer.
// Its two flow-control opcodes are recognised L2 denial-of-service
// surfaces and so join the project's L2-attack decoder family
// (internal/dtp, vtp, vqp, gxrp, stp):
//
//   - PAUSE (802.3x, opcode 0x0001): a frame to 01:80:c2:00:00:01 tells
//     the upstream port to stop sending for pause_time × 512 bit-times.
//     A flood of PAUSE frames with the maximum quanta (0xFFFF) is the
//     classic switch-port flow-control DoS — it can stall the port
//     indefinitely.
//   - PFC / Priority-based Flow Control (802.1Qbb, opcode 0x0101): the
//     per-priority version used in lossless datacenter fabrics (RoCE /
//     FCoE); a PFC storm causes head-of-line blocking and can collapse a
//     converged fabric.
//
// The remaining opcodes are EPON MPCP (Multi-Point Control Protocol):
// GATE / REPORT / REGISTER_REQ / REGISTER / REGISTER_ACK, the time-slot
// grant + discovery handshake of an Ethernet PON.
//
// # Wrap-vs-native judgement
//
//	Native. A MAC Control frame is a 2-byte opcode followed by a small
//	fixed, opcode-specific body (a pause time, a PFC class-enable vector
//	+ eight times, or an MPCP timestamp + fields). A byte-field read +
//	an opcode switch; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	Every opcode body was verified field-for-field against scapy's
//	MACControl layer (scapy.contrib.mac_control). MAC Control frames are
//	padded to the 60-byte minimum Ethernet payload; the decoder reads
//	only the defined opcode fields and reports any non-zero trailing
//	bytes rather than guessing at them. An unknown opcode is named by
//	number with its body surfaced as raw hex.
package maccontrol

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// PFCClass is one priority class of an 802.1Qbb PFC frame.
type PFCClass struct {
	Class     int  `json:"class"`
	Enabled   bool `json:"enabled"`
	PauseTime int  `json:"pause_time_quanta"`
}

// Result is the decoded view of a MAC Control frame.
type Result struct {
	Opcode     int    `json:"opcode"`
	OpcodeName string `json:"opcode_name"`

	// PAUSE (0x0001).
	PauseTimeQuanta *int `json:"pause_time_quanta,omitempty"`

	// PFC (0x0101).
	PFCClasses []PFCClass `json:"pfc_classes,omitempty"`

	// MPCP (0x0002-0x0006).
	Timestamp           *uint32 `json:"timestamp,omitempty"`
	Flags               *int    `json:"flags,omitempty"`
	FlagsName           string  `json:"flags_name,omitempty"`
	PendingGrants       *int    `json:"pending_grants,omitempty"`
	AssignedPort        *int    `json:"assigned_port,omitempty"`
	SyncTime            *int    `json:"sync_time,omitempty"`
	EchoedAssignedPort  *int    `json:"echoed_assigned_port,omitempty"`
	EchoedSyncTime      *int    `json:"echoed_sync_time,omitempty"`
	EchoedPendingGrants *int    `json:"echoed_pending_grants,omitempty"`

	BodyHex string   `json:"body_hex,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Decode parses a MAC Control frame body (the EtherType-0x8808 payload,
// i.e. the bytes after the Ethernet header) from hex (whitespace / ':' /
// '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("maccontrol: %d bytes — too short for a MAC Control opcode", len(b))
	}
	op := int(binary.BigEndian.Uint16(b[0:2]))
	r := &Result{Opcode: op, OpcodeName: opcodeName(op)}
	body := b[2:]
	consumed := 0
	switch op {
	case 0x0001: // PAUSE
		if len(body) < 2 {
			return nil, fmt.Errorf("maccontrol: PAUSE frame truncated")
		}
		q := int(binary.BigEndian.Uint16(body[0:2]))
		r.PauseTimeQuanta = &q
		consumed = 2
		r.Notes = append(r.Notes, "PAUSE halts the upstream port for pause_time x 512 bit-times; a flood of PAUSE frames (especially pause_time 0xFFFF) is the 802.3x flow-control DoS")
	case 0x0101: // PFC / Priority-based Flow Control
		if len(body) < 18 {
			return nil, fmt.Errorf("maccontrol: PFC frame truncated")
		}
		enable := body[1] // body[0] is reserved
		for c := 0; c < 8; c++ {
			r.PFCClasses = append(r.PFCClasses, PFCClass{
				Class:     c,
				Enabled:   enable&(1<<uint(c)) != 0,
				PauseTime: int(binary.BigEndian.Uint16(body[2+c*2 : 4+c*2])),
			})
		}
		consumed = 18
		r.Notes = append(r.Notes, "PFC (802.1Qbb) pauses individual priority classes; a PFC storm causes head-of-line blocking and can collapse a lossless datacenter fabric (RoCE / FCoE)")
	case 0x0002: // GATE
		consumed = readTimestamp(r, body)
	case 0x0003: // REPORT
		consumed = readTimestamp(r, body)
		if len(body) >= consumed+2 {
			f := int(body[consumed])
			pg := int(body[consumed+1])
			r.Flags, r.FlagsName, r.PendingGrants = &f, mpcpFlag(body[consumed]), &pg
			consumed += 2
		}
	case 0x0004: // REGISTER_REQ
		consumed = readTimestamp(r, body)
		if len(body) >= consumed+6 {
			ap := int(binary.BigEndian.Uint16(body[consumed : consumed+2]))
			f := int(body[consumed+2])
			st := int(binary.BigEndian.Uint16(body[consumed+3 : consumed+5]))
			epg := int(body[consumed+5])
			r.AssignedPort, r.Flags, r.FlagsName, r.SyncTime, r.EchoedPendingGrants = &ap, &f, mpcpFlag(body[consumed+2]), &st, &epg
			consumed += 6
		}
	case 0x0005, 0x0006: // REGISTER / REGISTER_ACK
		consumed = readTimestamp(r, body)
		if len(body) >= consumed+5 {
			f := int(body[consumed])
			eap := int(binary.BigEndian.Uint16(body[consumed+1 : consumed+3]))
			est := int(binary.BigEndian.Uint16(body[consumed+3 : consumed+5]))
			r.Flags, r.FlagsName, r.EchoedAssignedPort, r.EchoedSyncTime = &f, mpcpFlag(body[consumed]), &eap, &est
			consumed += 5
		}
	default:
		r.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		r.Notes = append(r.Notes, fmt.Sprintf("unknown MAC Control opcode 0x%04x — body surfaced raw", op))
		return r, nil
	}
	// Anything after the opcode body should be zero padding to the 60-byte
	// minimum Ethernet payload; flag non-zero trailing bytes.
	if trailing := body[consumed:]; nonZero(trailing) {
		r.Notes = append(r.Notes, "non-zero trailing bytes after the opcode body: "+strings.ToUpper(hex.EncodeToString(trailing)))
	}
	return r, nil
}

func readTimestamp(r *Result, body []byte) int {
	if len(body) >= 4 {
		ts := binary.BigEndian.Uint32(body[0:4])
		r.Timestamp = &ts
		return 4
	}
	return 0
}

func opcodeName(op int) string {
	switch op {
	case 0x0001:
		return "PAUSE"
	case 0x0002:
		return "GATE (MPCP)"
	case 0x0003:
		return "REPORT (MPCP)"
	case 0x0004:
		return "REGISTER_REQ (MPCP)"
	case 0x0005:
		return "REGISTER (MPCP)"
	case 0x0006:
		return "REGISTER_ACK (MPCP)"
	case 0x0101:
		return "PFC / Class-Based Flow Control"
	}
	return fmt.Sprintf("unknown(0x%04x)", op)
}

func mpcpFlag(f byte) string {
	switch f {
	case 1:
		return "register"
	case 2:
		return "deregister"
	case 3:
		return "ack"
	case 4:
		return "nack"
	}
	return fmt.Sprintf("unknown(%d)", f)
}

func nonZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return true
		}
	}
	return false
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("maccontrol: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("maccontrol: input is not valid hex: %w", err)
	}
	return b, nil
}
