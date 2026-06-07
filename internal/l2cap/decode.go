// SPDX-License-Identifier: AGPL-3.0-or-later

// Package l2cap decodes Bluetooth L2CAP (Logical Link Control and Adaptation
// Protocol) — the channel-multiplexing layer that rides inside HCI ACL data
// and carries the higher Bluetooth protocols. It is the bridge between the
// project's bt_hci_decode (the HCI transport below) and its BLE / GATT tooling
// (above): an L2CAP frame's Channel ID (CID) selects the protocol — the
// **signaling** channel (connection / configuration / the LE connection-
// parameter-update and credit-based-connection requests), **ATT** (the
// Attribute Protocol behind GATT), **SMP** (the Security Manager — BLE
// pairing), or a dynamic channel. Decoding an L2CAP frame from a btsnoop /
// HCI-ACL capture reveals which Bluetooth sub-protocol is in flight and, for
// the signaling / ATT / SMP channels, the specific operation (a GATT read /
// write / notification, a pairing request, a connection-parameter update) —
// the recon headline for Bluetooth-stack analysis.
//
// # Wrap-vs-native judgement
//
//	Native. An L2CAP frame is a 2-byte little-endian length + a 2-byte CID,
//	then a per-channel payload (signaling C-frames are code + id + length +
//	data; ATT and SMP PDUs begin with a 1-byte opcode). A byte read + a CID
//	dispatch + opcode tables; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The basic-header layout, the fixed CIDs, the L2CAP signaling codes, the
//	ATT opcodes and the SMP codes follow the Bluetooth Core specification. The
//	channel is dispatched by CID; the signaling code / ATT opcode / SMP code
//	is named from the spec tables; everything past the named opcode (the
//	per-operation parameters) is surfaced as raw hex (the parameter layouts
//	are operation-specific). An unknown signaling code / ATT opcode / SMP code
//	is reported by value, and a frame shorter than the 4-byte basic header is
//	reported, not guessed.
package l2cap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an L2CAP frame.
type Result struct {
	Length  int    `json:"length"`
	CID     string `json:"cid"`
	CIDName string `json:"cid_name"`
	Channel string `json:"channel"` // "signaling" | "att" | "smp" | "dynamic" | "other"

	// Signaling channel
	SignalingCode string `json:"signaling_code,omitempty"`
	SignalingID   *int   `json:"signaling_identifier,omitempty"`

	// ATT / SMP
	OpcodeHex string `json:"opcode_hex,omitempty"`
	Operation string `json:"operation,omitempty"`

	PayloadHex string   `json:"payload_hex,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// Decode parses an L2CAP frame (the L2CAP basic header + payload, i.e. the
// content of an HCI ACL data packet) from hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("l2cap: %d bytes — too short for the 4-byte basic header (length + CID)", len(b))
	}
	length := int(binary.LittleEndian.Uint16(b[0:2]))
	cid := binary.LittleEndian.Uint16(b[2:4])
	r := &Result{
		Length:  length,
		CID:     fmt.Sprintf("0x%04X", cid),
		CIDName: cidName(cid),
	}
	payload := b[4:]

	switch cid {
	case 0x0001, 0x0005: // Signaling (BR/EDR) / LE Signaling
		r.Channel = "signaling"
		if len(payload) >= 4 {
			r.SignalingCode = signalingCode(payload[0])
			id := int(payload[1])
			r.SignalingID = &id
			if len(payload) > 4 {
				r.PayloadHex = hexUpper(payload[4:])
			}
		} else if len(payload) > 0 {
			r.PayloadHex = hexUpper(payload)
		}
	case 0x0004: // ATT (GATT)
		r.Channel = "att"
		if len(payload) >= 1 {
			r.OpcodeHex = fmt.Sprintf("0x%02X", payload[0])
			r.Operation = attOpcode(payload[0])
			if len(payload) > 1 {
				r.PayloadHex = hexUpper(payload[1:])
			}
		}
	case 0x0006, 0x0007: // SMP (Security Manager — pairing)
		r.Channel = "smp"
		if len(payload) >= 1 {
			r.OpcodeHex = fmt.Sprintf("0x%02X", payload[0])
			r.Operation = smpCode(payload[0])
			if len(payload) > 1 {
				r.PayloadHex = hexUpper(payload[1:])
			}
		}
	default:
		if cid >= 0x0040 {
			r.Channel = "dynamic"
		} else {
			r.Channel = "other"
		}
		if len(payload) > 0 {
			r.PayloadHex = hexUpper(payload)
		}
	}

	r.Notes = append(r.Notes, "L2CAP — the CID selects the Bluetooth sub-protocol (signaling / ATT-GATT / SMP-pairing / dynamic); the per-operation parameters are surfaced raw")
	return r, nil
}

func cidName(cid uint16) string {
	switch cid {
	case 0x0001:
		return "L2CAP Signaling (BR/EDR)"
	case 0x0002:
		return "Connectionless"
	case 0x0003:
		return "AMP Manager"
	case 0x0004:
		return "ATT (Attribute Protocol / GATT)"
	case 0x0005:
		return "LE Signaling"
	case 0x0006:
		return "SMP (Security Manager / pairing)"
	case 0x0007:
		return "BR/EDR Security Manager"
	}
	if cid >= 0x0040 {
		return "dynamically-allocated channel"
	}
	return "reserved / fixed"
}

func signalingCode(c byte) string {
	names := map[byte]string{
		0x01: "Command Reject", 0x02: "Connection Request", 0x03: "Connection Response",
		0x04: "Configuration Request", 0x05: "Configuration Response", 0x06: "Disconnection Request",
		0x07: "Disconnection Response", 0x08: "Echo Request", 0x09: "Echo Response",
		0x0A: "Information Request", 0x0B: "Information Response",
		0x12: "Connection Parameter Update Request", 0x13: "Connection Parameter Update Response",
		0x14: "LE Credit Based Connection Request", 0x15: "LE Credit Based Connection Response",
		0x16: "Flow Control Credit Indication", 0x17: "Credit Based Connection Request",
		0x18: "Credit Based Connection Response", 0x19: "Credit Based Reconfigure Request",
		0x1A: "Credit Based Reconfigure Response",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("signaling code 0x%02X", c)
}

func attOpcode(c byte) string {
	names := map[byte]string{
		0x01: "Error Response", 0x02: "Exchange MTU Request", 0x03: "Exchange MTU Response",
		0x04: "Find Information Request", 0x05: "Find Information Response",
		0x06: "Find By Type Value Request", 0x07: "Find By Type Value Response",
		0x08: "Read By Type Request", 0x09: "Read By Type Response",
		0x0A: "Read Request", 0x0B: "Read Response", 0x0C: "Read Blob Request",
		0x0D: "Read Blob Response", 0x0E: "Read Multiple Request", 0x0F: "Read Multiple Response",
		0x10: "Read By Group Type Request", 0x11: "Read By Group Type Response",
		0x12: "Write Request", 0x13: "Write Response", 0x16: "Prepare Write Request",
		0x17: "Prepare Write Response", 0x18: "Execute Write Request", 0x19: "Execute Write Response",
		0x1B: "Handle Value Notification", 0x1D: "Handle Value Indication",
		0x1E: "Handle Value Confirmation", 0x52: "Write Command", 0xD2: "Signed Write Command",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("ATT opcode 0x%02X", c)
}

func smpCode(c byte) string {
	names := map[byte]string{
		0x01: "Pairing Request", 0x02: "Pairing Response", 0x03: "Pairing Confirm",
		0x04: "Pairing Random", 0x05: "Pairing Failed", 0x06: "Encryption Information",
		0x07: "Central Identification", 0x08: "Identity Information",
		0x09: "Identity Address Information", 0x0A: "Signing Information",
		0x0B: "Security Request", 0x0C: "Pairing Public Key", 0x0D: "Pairing DHKey Check",
		0x0E: "Pairing Keypress Notification",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("SMP code 0x%02X", c)
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("l2cap: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("l2cap: input is not valid hex: %w", err)
	}
	return b, nil
}
