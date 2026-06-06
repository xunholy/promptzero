// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ir decodes raw infrared remote-control timing captures into the
// protocol + address/command — the IR analogue of the Sub-GHz protocol
// decoders, and the complement to the file-level ir_decode_file (which only
// reads a .ir file's already-parsed entries).
//
// # Wrap-vs-native judgement
//
// Native. Consumer-IR protocols are public, fully-deterministic
// pulse-distance encodings documented for decades (NEC by NEC/Renesas,
// reproduced in LIRC, the Flipper IR stack, and Arduino-IRremote). Decoding
// is a leader-match plus a per-bit mark/space classifier over the captured
// microsecond timings the operator already has (ir_receive raw, a Flipper
// RAW .ir entry, or a logic-analyser capture) — no IR hardware at decode
// time.
//
// # Verifiable / no confidently-wrong output
//
// NEC carries a built-in checksum: the 8-bit address is followed by its
// bitwise inverse and the 8-bit command by its inverse. A standard NEC frame
// is reported only when BOTH inversions hold; when only the command
// inversion holds it is reported as NEC-extended (16-bit address, no address
// inversion); when neither holds the raw 4 bytes are surfaced with a note
// rather than a guessed address/command. The leader and every bit are
// tolerance-matched, so a non-NEC pulse train is rejected, not mis-decoded.
//
// # Covered / deferred
//
// The NEC family (standard, extended, and the repeat code), Sony SIRC
// (12 / 15 / 20-bit), Samsung, and Philips RC5 / RC5X (14-bit Manchester) are
// covered — the most common consumer-IR protocols across the three encoding
// families (pulse-distance, pulse-width, and bi-phase). NEC is gated by its
// address/command inverse-byte checksum; the checksum-less protocols are gated
// structurally instead — SIRC by its 2400µs leader + exact 12/15/20-bit count,
// and RC5 by an exact 28-half-bit Manchester reconstruction with a valid S1
// start bit (a polarity-inverted or non-RC5 train fails the bit-pair or S1
// gate and is rejected, not mis-decoded). RC6 (a more complex Manchester
// variant with a double-width toggle) and the Pronto/`ir_build` parsed formats
// are deliberately not decoded here yet.
package ir

import (
	"fmt"
	"strconv"
	"strings"
)

// NEC nominal timings in microseconds.
const (
	necLeaderMark  = 9000
	necLeaderSpace = 4500
	necRepeatSpace = 2250
	necBitMark     = 560
	necZeroSpace   = 560
	necOneSpace    = 1690
	tolerancePct   = 30 // IR timings vary widely; ±30% is the usual bound
)

// Result is the decoded view of a raw IR capture.
type Result struct {
	Protocol      string   `json:"protocol"`
	Address       int      `json:"address"`
	AddressHex    string   `json:"address_hex"`
	Command       int      `json:"command"`
	CommandHex    string   `json:"command_hex"`
	Bits          int      `json:"bits"`
	ChecksumValid bool     `json:"checksum_valid"`
	RawBytesHex   string   `json:"raw_bytes_hex,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

// DecodeRaw parses a space-separated list of microsecond timings (the
// alternating mark/space durations from a raw IR capture) and decodes the
// NEC-family frame it carries.
func DecodeRaw(timings string) (*Result, error) {
	t, err := parseTimings(timings)
	if err != nil {
		return nil, err
	}
	if len(t) < 2 {
		return nil, fmt.Errorf("ir: need at least a leader mark + space; got %d timing(s)", len(t))
	}
	switch {
	case within(t[0], necLeaderMark):
		return decodeNEC(t)
	case within(t[0], samsungLeaderMark):
		return decodeSamsung(t)
	case within(t[0], rc5HalfBit) || within(t[0], rc5FullBit):
		// RC5 has no leader: it begins directly with the Manchester bit
		// stream, so its first mark is a 889µs (or merged 1778µs) half-bit.
		// Checked before SIRC: an RC5X frame opens with a merged 1778µs mark
		// that falls inside SIRC's wide leader window, but SIRC's 2400µs
		// leader is outside RC5's 1778±30% window, so this ordering is
		// unambiguous.
		return decodeRC5(t)
	case within(t[0], sircLeaderMark):
		return decodeSIRC(t)
	default:
		return nil, fmt.Errorf("ir: leader mark %dµs matches no supported protocol (NEC ~9000µs, Samsung ~4500µs, Sony SIRC ~2400µs, Philips RC5 ~889µs)", t[0])
	}
}

// decodeNEC decodes a NEC-family frame from its parsed timings (the 9000µs
// leader mark is at t[0]).
func decodeNEC(t []int) (*Result, error) {
	// Repeat code: 9000 mark + 2250 space (+ a 560 mark).
	if within(t[1], necRepeatSpace) {
		return &Result{Protocol: "NEC-repeat", Notes: []string{"NEC repeat code (button held) — carries no address/command"}}, nil
	}
	if !within(t[1], necLeaderSpace) {
		return nil, fmt.Errorf("ir: leader space %dµs is not NEC (~4500µs)", t[1])
	}

	b, err := readPDC32(t)
	if err != nil {
		return nil, err
	}
	out := &Result{
		Bits:        32,
		RawBytesHex: fmt.Sprintf("%02X%02X%02X%02X", b[0], b[1], b[2], b[3]),
	}
	addrOK := b[1] == b[0]^0xFF
	cmdOK := b[3] == b[2]^0xFF
	switch {
	case addrOK && cmdOK:
		out.Protocol = "NEC"
		out.Address = int(b[0])
		out.Command = int(b[2])
		out.ChecksumValid = true
	case cmdOK:
		out.Protocol = "NEC-extended"
		out.Address = int(b[0]) | int(b[1])<<8
		out.Command = int(b[2])
		out.ChecksumValid = true
		out.Notes = append(out.Notes, "16-bit address (no address inversion); command inversion validates")
	default:
		out.Protocol = "NEC-like (checksum failed)"
		out.Address = int(b[0])
		out.Command = int(b[2])
		out.Notes = append(out.Notes, "neither address nor command inversion holds — a misread frame or a non-NEC pulse-distance protocol; address/command shown unverified")
	}
	out.AddressHex = fmt.Sprintf("0x%X", out.Address)
	out.CommandHex = fmt.Sprintf("0x%02X", out.Command)
	return out, nil
}

// readPDC32 reads 32 pulse-distance bits from t[2:] (skipping the leader at
// t[0..1]) and packs them LSB-first into 4 bytes. Each bit is a ~560µs mark
// followed by a ~560µs (0) or ~1690µs (1) space — the encoding shared by NEC
// and Samsung.
func readPDC32(t []int) ([4]byte, error) {
	var b [4]byte
	bits := 0
	for i := 2; bits < 32; i += 2 {
		if i+1 >= len(t) {
			return b, fmt.Errorf("ir: frame truncated at bit %d (need 32)", bits)
		}
		if !within(t[i], necBitMark) {
			return b, fmt.Errorf("ir: bit %d mark %dµs not ~560µs", bits, t[i])
		}
		switch {
		case within(t[i+1], necOneSpace):
			b[bits/8] |= 1 << uint(bits%8) // LSB-first
		case within(t[i+1], necZeroSpace):
			// zero bit — nothing to set
		default:
			return b, fmt.Errorf("ir: bit %d space %dµs is neither ~560µs (0) nor ~1690µs (1)", bits, t[i+1])
		}
		bits++
	}
	return b, nil
}

func within(v, nominal int) bool {
	d := nominal * tolerancePct / 100
	return v >= nominal-d && v <= nominal+d
}

func parseTimings(s string) ([]int, error) {
	fields := strings.FieldsFunc(strings.TrimSpace(s), func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(fields) == 0 {
		return nil, fmt.Errorf("ir: empty timing list")
	}
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("ir: %q is not an integer microsecond value", f)
		}
		if n < 0 {
			n = -n // some captures sign-encode mark/space; magnitude is the duration
		}
		out = append(out, n)
	}
	return out, nil
}
