// em4100_frame_decode.go — host-side EM4100 64-bit wire-frame DECODER Spec,
// the parity-validating inverse of EncodeEM4100Frame (em4100_encode).
//
// Wrap-vs-native: native — em4100_encode builds the 64-bit frame an EM4100
// tag transmits (9-bit header + 10 rows of [4 data + even row parity] + 4
// even column parities + stop bit). Nothing recovered the 5-byte customer ID
// from a raw captured frame while *checking* those parities. This does: it
// validates the header, every row parity, every column parity, and the stop
// bit, so a corrupted or non-EM4100 bitstream is flagged/rejected rather than
// silently mis-read. Verified by round-trip against EncodeEM4100Frame — the
// encoder is ground truth, so no external reference vector is needed. Offline
// transform over an operator-supplied bitstream; no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(em4100FrameDecodeSpec)
}

// EM4100Frame is the decoded view of a raw 64-bit EM4100 wire frame.
type EM4100Frame struct {
	IDHex          string     `json:"id_hex"`
	HeaderValid    bool       `json:"header_valid"`
	RowParityOK    bool       `json:"row_parity_ok"`
	ColumnParityOK bool       `json:"column_parity_ok"`
	StopBitValid   bool       `json:"stop_bit_valid"`
	Valid          bool       `json:"valid"`
	Card           EM4100Card `json:"card"`
	Notes          []string   `json:"notes,omitempty"`
}

// DecodeEM4100Frame parses a 64-bit EM4100 wire frame (a 64-character '0'/'1'
// string) into the 5-byte customer ID, validating the 9-bit header, the 10
// even row parities, the 4 even column parities, and the stop bit. A missing
// header is treated as "not an EM4100 frame" (hard error); parity / stop-bit
// failures recover the ID but mark the frame invalid with a note, so a
// corrupted read is never asserted as a clean ID.
func DecodeEM4100Frame(bits string) (*EM4100Frame, error) {
	if len(bits) != 64 {
		return nil, fmt.Errorf("em4100: frame must be 64 bits; got %d", len(bits))
	}
	for i := 0; i < len(bits); i++ {
		if bits[i] != '0' && bits[i] != '1' {
			return nil, fmt.Errorf("em4100: frame bit %d is %q, not '0'/'1'", i, bits[i])
		}
	}
	// 9-bit header must be all ones — this is the sync; absence means the
	// bitstream is not an EM4100 frame.
	if bits[0:9] != "111111111" {
		return nil, fmt.Errorf("em4100: 9-bit header is not all ones (%q) — not an EM4100 frame", bits[0:9])
	}

	out := &EM4100Frame{HeaderValid: true, RowParityOK: true, ColumnParityOK: true}

	nibbles := make([]byte, 10)
	var colData [4]int // running column parity over data bits (col 0 = MSB)
	for row := 0; row < 10; row++ {
		base := 9 + row*5
		var nib byte
		ones := 0
		for c := 0; c < 4; c++ {
			v := int(bits[base+c] - '0')
			nib = nib<<1 | byte(v) // MSB first
			ones += v
			colData[c] ^= v
		}
		nibbles[row] = nib
		rowParity := int(bits[base+4] - '0')
		if rowParity != ones&1 {
			out.RowParityOK = false
		}
	}
	// 4 column parity bits at [59:63].
	for c := 0; c < 4; c++ {
		if int(bits[59+c]-'0') != colData[c]&1 {
			out.ColumnParityOK = false
		}
	}
	out.StopBitValid = bits[63] == '0'

	// Reassemble 5 bytes from the 10 nibbles (MSB nibble first).
	id := make([]byte, 5)
	for i := 0; i < 5; i++ {
		id[i] = nibbles[2*i]<<4 | nibbles[2*i+1]
	}
	idHex := fmt.Sprintf("%02X%02X%02X%02X%02X", id[0], id[1], id[2], id[3], id[4])
	out.IDHex = idHex
	out.Card, _ = DecodeEM4100(idHex)

	out.Valid = out.HeaderValid && out.RowParityOK && out.ColumnParityOK && out.StopBitValid
	if !out.RowParityOK {
		out.Notes = append(out.Notes, "one or more even row-parity bits failed — frame corrupted; ID shown unverified")
	}
	if !out.ColumnParityOK {
		out.Notes = append(out.Notes, "one or more even column-parity bits failed — frame corrupted; ID shown unverified")
	}
	if !out.StopBitValid {
		out.Notes = append(out.Notes, "stop bit is not 0 — frame misaligned or corrupted")
	}
	return out, nil
}

var em4100FrameDecodeSpec = Spec{
	Name: "em4100_frame_decode",
	Description: "Decode a raw 64-bit EM4100 wire frame (the on-the-wire bits from rfid_raw_read, a " +
		"Proxmark `lf em 410x` raw bitstream, or a logic-analyser capture) back into the 5-byte (40-bit) " +
		"customer ID — the parity-validating inverse of em4100_encode. Validates the 9-bit header (all " +
		"ones), all 10 even row-parity bits, all 4 even column-parity bits, and the 0 stop bit, so a " +
		"corrupted or non-EM4100 bitstream is flagged or rejected rather than silently mis-read: a " +
		"missing header is a hard error, and a parity/stop-bit failure recovers the ID but marks the " +
		"frame invalid with a note (never asserting a clean ID from a bad read).\n\n" +
		"Input is the 64-character '0'/'1' frame (as em4100_encode emits) — ':' / '-' / whitespace " +
		"separators tolerated. Output is the recovered ID (with the em4100_decode card forms), the " +
		"per-check parity flags, and an overall valid flag. Offline transform — reads bits, transmits " +
		"nothing, so it is Low risk. Wrap-vs-native: native — fixed frame layout + parity maths, " +
		"round-trip-verified against em4100_encode.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bits":{"type":"string","description":"64-character '0'/'1' EM4100 wire frame. ':' / '-' / whitespace separators tolerated."}
		},
		"required":["bits"]
	}`),
	Required:  []string{"bits"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   em4100FrameDecodeHandler,
}

func em4100FrameDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	bits := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\t", "", "\n", "", "\r", "").Replace(str(p, "bits"))
	if bits == "" {
		return "", fmt.Errorf("em4100_frame_decode: 'bits' is required")
	}
	res, err := DecodeEM4100Frame(bits)
	if err != nil {
		return "", fmt.Errorf("em4100_frame_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
