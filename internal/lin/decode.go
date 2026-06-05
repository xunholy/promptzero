// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lin decodes a LIN (Local Interconnect Network) bus frame — the
// low-cost single-wire automotive sub-bus that hangs off CAN for body
// electronics: door / mirror / seat modules, climate flaps, wiper and
// rain/light sensors, switch panels. It is a real automotive
// reverse-engineering / pentest surface (cheap to tap, often unauthenticated)
// and is distinct from the CAN family the other automotive decoders cover.
//
// # Wrap-vs-native judgement
//
//	Native. A LIN frame is a fully-public fixed structure (LIN 2.x /
//	ISO 17987): an optional 0x55 sync byte, a Protected Identifier
//	(PID = 6-bit frame ID + 2 parity bits), 1-8 data bytes, and a
//	checksum. The PID parity is two XOR equations over the ID bits;
//	the checksum is the inverted carry-folded sum of the data (classic)
//	or of the PID + data (enhanced). All deterministic byte/bit math —
//	reimplemented from the standard, no new dependency, no shell-out.
//
// # What this covers
//
//   - The Protected Identifier: the 6-bit frame ID, the parity bits,
//     and a recompute of the parity (reported valid / invalid), plus a
//     frame-class note (signal frame / master-request or slave-response
//     diagnostic / user-defined / reserved).
//   - The data bytes (length inferred as frame_length − PID − checksum).
//   - The checksum: both the classic (data-only, LIN 1.x + diagnostics)
//     and the enhanced (PID + data, LIN 2.x) forms are computed and the
//     frame's checksum is reported as classic / enhanced / invalid.
//
// # Deliberately deferred
//
//	The signal (DBC/LDF) interpretation of the data bytes needs the
//	vehicle's LIN Description File and is not attempted — the raw data
//	is surfaced. The break field and bit-timing are physical-layer and
//	upstream of the captured bytes.
package lin

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded LIN frame.
type Result struct {
	SyncByte      bool     `json:"sync_byte_present"`
	PID           string   `json:"pid"`
	FrameID       int      `json:"frame_id"`
	FrameIDHex    string   `json:"frame_id_hex"`
	ParityValid   bool     `json:"parity_valid"`
	ExpectedPID   string   `json:"expected_pid"`
	FrameClass    string   `json:"frame_class"`
	DataLength    int      `json:"data_length"`
	DataHex       string   `json:"data_hex,omitempty"`
	Checksum      string   `json:"checksum"`
	ChecksumType  string   `json:"checksum_type"`
	ChecksumValid bool     `json:"checksum_valid"`
	Notes         []string `json:"notes,omitempty"`
}

// Decode parses a LIN frame from hex: an optional 0x55 sync byte, the
// PID, the data bytes, and the trailing checksum.
func Decode(hexStr string) (*Result, error) {
	b, err := hex.DecodeString(stripSep(hexStr))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	r := &Result{}
	// An optional leading 0x55 sync byte (some captures keep it).
	if len(b) >= 1 && b[0] == 0x55 {
		// Only treat it as sync when more bytes follow (a bare 0x55 is a PID).
		if len(b) >= 4 {
			r.SyncByte = true
			b = b[1:]
		}
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("frame too short (need at least PID + checksum)")
	}
	if len(b) > 10 {
		return nil, fmt.Errorf("frame too long (%d bytes; LIN is PID + 1-8 data + checksum)", len(b))
	}

	pid := b[0]
	id := int(pid & 0x3F)
	r.PID = fmt.Sprintf("0x%02X", pid)
	r.FrameID = id
	r.FrameIDHex = fmt.Sprintf("0x%02X", id)
	expected := pidParity(byte(id))
	r.ExpectedPID = fmt.Sprintf("0x%02X", expected)
	r.ParityValid = expected == pid
	r.FrameClass = frameClass(id)
	if !r.ParityValid {
		r.Notes = append(r.Notes, "PID parity check FAILED — the parity bits do not match the frame ID")
	}

	data := b[1 : len(b)-1]
	r.DataLength = len(data)
	if len(data) > 0 {
		r.DataHex = strings.ToUpper(hex.EncodeToString(data))
	}

	cksum := b[len(b)-1]
	r.Checksum = fmt.Sprintf("0x%02X", cksum)
	classic := linChecksum(data)
	enhanced := linChecksum(append([]byte{pid}, data...))
	diagnostic := id == 0x3C || id == 0x3D
	switch {
	case cksum == enhanced && !diagnostic:
		r.ChecksumType, r.ChecksumValid = "enhanced (PID + data)", true
	case cksum == classic:
		r.ChecksumType, r.ChecksumValid = "classic (data only)", true
		if !diagnostic {
			r.Notes = append(r.Notes, "classic checksum — a LIN 1.x or diagnostic-style frame")
		}
	case cksum == enhanced: // matches enhanced on a diagnostic ID
		r.ChecksumType, r.ChecksumValid = "enhanced (PID + data)", true
		r.Notes = append(r.Notes, "diagnostic frame (ID 0x3C/0x3D) normally uses the classic checksum")
	default:
		r.ChecksumType, r.ChecksumValid = "invalid", false
		r.Notes = append(r.Notes, fmt.Sprintf(
			"checksum check FAILED — frame 0x%02X, expected classic 0x%02X or enhanced 0x%02X",
			cksum, classic, enhanced))
	}
	return r, nil
}

// pidParity computes the Protected Identifier for a 6-bit frame ID:
// P0 = ID0^ID1^ID2^ID4, P1 = !(ID1^ID3^ID4^ID5) (LIN 2.x / ISO 17987).
func pidParity(id byte) byte {
	bit := func(n byte) byte { return (id >> n) & 1 }
	p0 := bit(0) ^ bit(1) ^ bit(2) ^ bit(4)
	p1 := (bit(1) ^ bit(3) ^ bit(4) ^ bit(5)) ^ 1
	return (id & 0x3F) | (p0 << 6) | (p1 << 7)
}

// linChecksum is the LIN inverted carry-folded 8-bit sum: each byte is
// added with the carry folded back into the LSB, then the result is
// bit-inverted (LIN 2.x §2.3.1.5).
func linChecksum(data []byte) byte {
	var sum int
	for _, b := range data {
		sum += int(b)
		if sum > 0xFF {
			sum = (sum & 0xFF) + 1
		}
	}
	return ^byte(sum)
}

func frameClass(id int) string {
	switch {
	case id >= 0x00 && id <= 0x3B:
		return "signal-carrying frame"
	case id == 0x3C:
		return "master request (diagnostic)"
	case id == 0x3D:
		return "slave response (diagnostic)"
	case id == 0x3E:
		return "user-defined frame"
	default: // 0x3F
		return "reserved frame"
	}
}

func stripSep(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r', ',':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
