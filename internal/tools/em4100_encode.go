// em4100_encode.go — host-side EM4100 64-bit wire-frame encoder Spec.
// Companion to em4100_decode (which parses the 40-bit customer ID); this
// builds the on-the-wire 64-bit frame the tag actually stores/transmits, for
// raw cloning / cross-tool (Proxmark lf em 410x) / analysis workflows.
//
// Wrap-vs-native: native — the EM4100 frame layout (9-bit header + 10 rows
// of 4 data + even row parity + 4 even column parities + stop bit) is a
// public, fixed, deterministic structure (Proxmark / rtl_433 / EM4100
// datasheet). Pure bit + parity maths, no hardware. The Flipper firmware
// does this encoding internally for `rfid write EM4100`; we expose it for
// the raw / non-Flipper paths.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(em4100EncodeSpec)
}

// EncodeEM4100Frame builds the 64-bit EM4100 wire frame for a 5-byte (40-bit)
// customer ID: 9 leading header ones, then 10 rows of [4 data bits + 1 even
// row-parity bit] (one row per nibble, MSB nibble first), then 4 even
// column-parity bits (one per data-bit column across all 10 rows), then a
// trailing 0 stop bit. Returns the 64-character '0'/'1' string.
func EncodeEM4100Frame(id []byte) (string, error) {
	if len(id) != 5 {
		return "", fmt.Errorf("em4100: ID must be 5 bytes (40 bits); got %d", len(id))
	}
	// Ten 4-bit nibbles, MSB nibble of each byte first.
	nibbles := make([]byte, 10)
	for i, b := range id {
		nibbles[2*i] = b >> 4
		nibbles[2*i+1] = b & 0x0f
	}

	var sb strings.Builder
	sb.Grow(64)
	sb.WriteString("111111111") // 9-bit header

	colParity := [4]int{}
	for _, n := range nibbles {
		ones := 0
		for bit := 3; bit >= 0; bit-- {
			v := int(n>>uint(bit)) & 1
			if v == 1 {
				sb.WriteByte('1')
				ones++
			} else {
				sb.WriteByte('0')
			}
			colParity[3-bit] ^= v // column index 0 = MSB
		}
		sb.WriteByte('0' + byte(ones&1)) // even row parity
	}
	for c := 0; c < 4; c++ {
		sb.WriteByte('0' + byte(colParity[c]&1)) // even column parity
	}
	sb.WriteByte('0') // stop bit

	return sb.String(), nil
}

var em4100EncodeSpec = Spec{
	Name: "em4100_encode",
	Description: "Build the 64-bit EM4100 on-the-wire frame from a 5-byte (40-bit) customer ID — the " +
		"bits an EM4100 tag actually stores/transmits, for raw cloning, cross-tool work (e.g. " +
		"Proxmark `lf em 410x clone`), and analysis. Lays out the 9-bit header (all ones), 10 rows of " +
		"[4 data bits + 1 even row-parity bit] (one row per ID nibble, MSB first), 4 even " +
		"column-parity bits, and a 0 stop bit, per the EM4100 datasheet. Companion to em4100_decode " +
		"(which parses the ID forms). Generation only — it writes nothing and transmits nothing; the " +
		"Flipper firmware does this encoding internally for `rfid write EM4100`, so this is for the " +
		"raw / non-Flipper paths. Output is the 64-bit '0'/'1' frame plus the ID echoed back.\n\n" +
		"Wrap-vs-native: native — public fixed frame layout, pure bit + parity maths, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"10 hex characters (the 5-byte EM4100 customer ID). ':' / '-' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   em4100EncodeHandler,
}

func em4100EncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	normalised := normaliseEM4100Hex(str(p, "hex"))
	if len(normalised) != 10 {
		return "", fmt.Errorf("em4100_encode: want 10 hex characters (5 bytes); got %d", len(normalised))
	}
	id, err := hex.DecodeString(normalised)
	if err != nil {
		return "", fmt.Errorf("em4100_encode: invalid hex: %w", err)
	}
	frame, err := EncodeEM4100Frame(id)
	if err != nil {
		return "", fmt.Errorf("em4100_encode: %w", err)
	}
	card, _ := DecodeEM4100(normalised)
	out, _ := json.MarshalIndent(struct {
		ID    string     `json:"id_hex"`
		Bits  string     `json:"frame_bits"`
		Frame int        `json:"frame_bits_len"`
		Card  EM4100Card `json:"card"`
	}{ID: strings.ToUpper(normalised), Bits: frame, Frame: len(frame), Card: card}, "", "  ")
	return string(out), nil
}
