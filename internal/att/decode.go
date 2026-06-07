// SPDX-License-Identifier: AGPL-3.0-or-later

// Package att decodes the Bluetooth Attribute Protocol (ATT, Core spec Vol 3
// Part F) — the request/response protocol behind GATT, carried on L2CAP CID
// 0x0004. ATT is the application layer of BLE: it is how a client reads and
// writes a server's attributes (characteristics), discovers its services, and
// receives notifications. Decoding ATT traffic from a btsnoop / HCI-ACL
// capture is the recon headline for what a BLE app actually does on a device:
// which attribute **handles** it reads and writes, the **service / characteristic
// discovery** (Read By Group Type / Read By Type / Find Information) that maps
// the GATT database, and the **notifications / indications** a device pushes.
// It is the final layer of the project's Bluetooth-stack decode chain
// (bt_hci_decode → bt_l2cap_decode → here) and pairs with the UUID naming in
// bluetooth_gatt_uuid_lookup.
//
// # Wrap-vs-native judgement
//
//	Native. An ATT PDU is a 1-byte opcode then per-opcode fixed fields —
//	little-endian 16-bit handles, a 16-bit MTU, 2-or-16-byte UUIDs, and value
//	blobs. A byte read + an opcode dispatch + handle/UUID reads; stdlib only,
//	no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The ATT opcodes, the error codes and the per-opcode field layouts follow
//	the Bluetooth Core specification (Vol 3 Part F) — deterministic and
//	byte-checkable. The common opcodes (Error/Exchange MTU/Find Information/
//	Read By Type/Read/Read By Group Type/Write/Notification/Indication) are
//	field-decoded; the attribute VALUE blobs are surfaced as raw hex (their
//	contents are characteristic-specific), and the length-prefixed
//	attribute-data lists (discovery responses) are surfaced raw with their
//	per-record length noted. An opcode outside the decoded set is named (or
//	reported by value) with its body raw.
package att

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an ATT PDU.
type Result struct {
	Opcode    int    `json:"opcode"`
	OpcodeHex string `json:"opcode_hex"`
	Operation string `json:"operation"`

	Handle      string `json:"handle,omitempty"`
	StartHandle string `json:"start_handle,omitempty"`
	EndHandle   string `json:"end_handle,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	MTU         *int   `json:"mtu,omitempty"`
	ValueHex    string `json:"value_hex,omitempty"`

	// Error Response
	RequestOpcode string `json:"request_opcode,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`

	// Discovery responses (length-prefixed attribute-data lists)
	RecordLength *int `json:"record_length,omitempty"`

	PayloadHex string   `json:"payload_hex,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// Decode parses an ATT PDU (the L2CAP CID-0x0004 payload, starting at the ATT
// opcode) from hex (whitespace / ':' / '-' / '_' separators and a '0x' prefix
// tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("att: empty input")
	}
	op := b[0]
	r := &Result{Opcode: int(op), OpcodeHex: fmt.Sprintf("0x%02X", op), Operation: opcodeName(op)}
	p := b[1:]

	switch op {
	case 0x01: // Error Response: req opcode(1) handle(2) error(1)
		if len(p) >= 4 {
			r.RequestOpcode = fmt.Sprintf("0x%02X (%s)", p[0], opcodeName(p[0]))
			r.Handle = handle(p[1:3])
			r.ErrorCode = errorName(p[3])
		}
	case 0x02, 0x03: // Exchange MTU Request / Response: MTU(2)
		if len(p) >= 2 {
			mtu := int(binary.LittleEndian.Uint16(p[0:2]))
			r.MTU = &mtu
		}
	case 0x04: // Find Information Request: start(2) end(2)
		if len(p) >= 4 {
			r.StartHandle = handle(p[0:2])
			r.EndHandle = handle(p[2:4])
		}
	case 0x08, 0x10: // Read By Type / Read By Group Type Request: start(2) end(2) UUID(2/16)
		if len(p) >= 4 {
			r.StartHandle = handle(p[0:2])
			r.EndHandle = handle(p[2:4])
			if len(p) > 4 {
				r.UUID = uuid(p[4:])
			}
		}
	case 0x05, 0x09, 0x11: // Find Info / Read By Type / Read By Group Type Response: format/length(1) + list
		if len(p) >= 1 {
			n := int(p[0])
			r.RecordLength = &n
			if len(p) > 1 {
				r.PayloadHex = hexUpper(p[1:])
			}
			r.Notes = append(r.Notes, "discovery response: a list of fixed-length attribute records (handle + value/UUID) — surfaced raw with the per-record length")
		}
	case 0x0A, 0x0C: // Read Request / Read Blob Request: handle(2)
		if len(p) >= 2 {
			r.Handle = handle(p[0:2])
		}
	case 0x0B, 0x0D: // Read Response / Read Blob Response: value
		if len(p) > 0 {
			r.ValueHex = hexUpper(p)
		}
	case 0x12, 0x52, 0x16, 0xD2: // Write Request / Command / Prepare Write / Signed Write: handle(2) value
		if len(p) >= 2 {
			r.Handle = handle(p[0:2])
			if len(p) > 2 {
				r.ValueHex = hexUpper(p[2:])
			}
		}
	case 0x1B, 0x1D: // Handle Value Notification / Indication: handle(2) value
		if len(p) >= 2 {
			r.Handle = handle(p[0:2])
			if len(p) > 2 {
				r.ValueHex = hexUpper(p[2:])
			}
		}
	default:
		if len(p) > 0 {
			r.PayloadHex = hexUpper(p)
		}
	}

	r.Notes = append(r.Notes, "Bluetooth ATT (the protocol behind GATT) — the opcode + handle name the GATT operation; attribute values are surfaced raw (characteristic-specific); pair 16-bit UUIDs with bluetooth_gatt_uuid_lookup")
	return r, nil
}

func opcodeName(c byte) string {
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

func errorName(c byte) string {
	names := map[byte]string{
		0x01: "Invalid Handle", 0x02: "Read Not Permitted", 0x03: "Write Not Permitted",
		0x04: "Invalid PDU", 0x05: "Insufficient Authentication", 0x06: "Request Not Supported",
		0x07: "Invalid Offset", 0x08: "Insufficient Authorization", 0x09: "Prepare Queue Full",
		0x0A: "Attribute Not Found", 0x0B: "Attribute Not Long",
		0x0C: "Insufficient Encryption Key Size", 0x0D: "Invalid Attribute Value Length",
		0x0E: "Unlikely Error", 0x0F: "Insufficient Encryption", 0x10: "Unsupported Group Type",
		0x11: "Insufficient Resources", 0x12: "Database Out Of Sync", 0x13: "Value Not Allowed",
	}
	if n, ok := names[c]; ok {
		return fmt.Sprintf("0x%02X (%s)", c, n)
	}
	return fmt.Sprintf("0x%02X", c)
}

func handle(b []byte) string {
	return fmt.Sprintf("0x%04X", binary.LittleEndian.Uint16(b))
}

// uuid renders an ATT UUID: 2 bytes (16-bit SIG UUID, little-endian) or 16
// bytes (128-bit, little-endian on the wire).
func uuid(b []byte) string {
	switch len(b) {
	case 2:
		return fmt.Sprintf("0x%04X (16-bit)", binary.LittleEndian.Uint16(b))
	case 16:
		// Render 128-bit UUID MSB-first (reverse the little-endian wire order).
		r := make([]byte, 16)
		for i := range b {
			r[i] = b[15-i]
		}
		s := hexUpper(r)
		return fmt.Sprintf("%s-%s-%s-%s-%s (128-bit)", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
	}
	return hexUpper(b) + " (non-standard length)"
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("att: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("att: input is not valid hex: %w", err)
	}
	return b, nil
}
