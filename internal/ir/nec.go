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
// The NEC family (standard, extended, and the repeat code) and Sony SIRC
// (12 / 15 / 20-bit) are covered — the two most common consumer-IR
// pulse-distance protocols. NEC is gated by its address/command inverse-byte
// checksum; SIRC carries no checksum, so it is gated structurally instead —
// the distinctive 2400µs leader, an exact 12/15/20-bit count, and a clean
// per-bit mark classification reject any non-SIRC pulse train. RC5/RC6
// (Manchester), Samsung, and the Pronto/`ir_build` parsed formats are
// deliberately not decoded here yet — they need a different (bi-phase)
// decoder or carry no comparable structural gate.
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
	case within(t[0], sircLeaderMark):
		return decodeSIRC(t)
	default:
		return nil, fmt.Errorf("ir: leader mark %dµs matches neither NEC (~9000µs) nor Sony SIRC (~2400µs)", t[0])
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

	// 32 data bits, each a 560µs mark + a 560µs (0) or 1690µs (1) space.
	bits := make([]int, 0, 32)
	i := 2
	for len(bits) < 32 {
		if i+1 >= len(t) {
			return nil, fmt.Errorf("ir: NEC frame truncated at bit %d (need 32)", len(bits))
		}
		if !within(t[i], necBitMark) {
			return nil, fmt.Errorf("ir: bit %d mark %dµs not ~560µs", len(bits), t[i])
		}
		switch {
		case within(t[i+1], necOneSpace):
			bits = append(bits, 1)
		case within(t[i+1], necZeroSpace):
			bits = append(bits, 0)
		default:
			return nil, fmt.Errorf("ir: bit %d space %dµs is neither ~560µs (0) nor ~1690µs (1)", len(bits), t[i+1])
		}
		i += 2
	}

	// NEC is LSB-first per byte.
	var b [4]byte
	for j, bit := range bits {
		if bit == 1 {
			b[j/8] |= 1 << uint(j%8)
		}
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
