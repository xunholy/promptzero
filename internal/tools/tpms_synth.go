// tpms_synth.go — host-side TPMS frame synthesizer Spec, the inverse of
// subghz_tpms_decode, delegating to internal/tpms.Synth.
//
// Wrap-vs-native: native — TPMS framing is a public deterministic transform
// (rtl_433-derived Manchester + CRC-8 families); generation is pure bit +
// CRC maths. The output is round-trip-verified against subghz_tpms_decode.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tpms"
)

func init() { //nolint:gochecknoinits
	Register(tpmsSynthSpec)
}

var tpmsSynthSpec = Spec{
	Name: "subghz_tpms_synth",
	Description: "Synthesize a TPMS Sub-GHz frame (pre-demodulated Manchester bit-stream) from a " +
		"32-bit sensor ID + payload bytes + CRC-8 polynomial — the offline inverse of " +
		"subghz_tpms_decode. Lays out [sensor ID:4][payload…][CRC-8], seals it with the chosen " +
		"polynomial, and Manchester line-codes the result; round-trip-verified against " +
		"subghz_tpms_decode (which recovers the same sensor ID + payload and confirms the CRC). " +
		"It is the bit-generator behind a TPMS-spoof payload — generation only, it transmits " +
		"nothing (pair the bits with a Sub-GHz TX stage), so it carries the same Low risk as the " +
		"decoder.\n\n" +
		"Inputs:\n" +
		" - `sensor_id`: 32-bit sensor ID as hex (up to 8 hex chars) or a decimal integer.\n" +
		" - `payload` (optional): the data bytes after the ID, before the CRC, as hex — left " +
		"verbatim; per-model pressure/temperature scaling is NOT imposed (mirrors the decoder's " +
		"refusal to guess unverifiable layouts). Max 12 bytes.\n" +
		" - `crc_poly` (optional): CRC-8 polynomial 0x07 (default), 0x2F, or 0x13.\n" +
		" - `ge_thomas` (optional): false = IEEE 802.3 Manchester (default), true = G.E. Thomas.\n\n" +
		"Output is the '0'/'1' bit-stream plus the frame decoded back from it for confirmation. " +
		"Companion to subghz_tpms_decode (gap-analysis §3 rank 6, the decode + _synth pairing). " +
		"Wrap-vs-native: native — public framing, pure bit + CRC maths, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"sensor_id":{"type":"string","description":"32-bit sensor ID: hex (e.g. 1A2B3C4D, up to 8 hex chars) or a decimal integer string."},
			"payload":{"type":"string","description":"Optional data bytes after the ID, before the CRC, as hex (separators tolerated). Max 12 bytes."},
			"crc_poly":{"type":"string","description":"CRC-8 polynomial: 0x07 (default), 0x2F, or 0x13."},
			"ge_thomas":{"type":"boolean","description":"true = G.E. Thomas Manchester; false = IEEE 802.3 (default)."}
		},
		"required":["sensor_id"]
	}`),
	Required:  []string{"sensor_id"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   tpmsSynthHandler,
}

func tpmsSynthHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	idStr := strings.TrimSpace(str(p, "sensor_id"))
	if idStr == "" {
		return "", fmt.Errorf("subghz_tpms_synth: 'sensor_id' is required")
	}
	id, err := parseSensorID(idStr)
	if err != nil {
		return "", fmt.Errorf("subghz_tpms_synth: %w", err)
	}

	in := tpms.SynthInput{SensorID: id}
	if pl := strings.TrimSpace(str(p, "payload")); pl != "" {
		clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(pl)
		b, err := hex.DecodeString(clean)
		if err != nil {
			return "", fmt.Errorf("subghz_tpms_synth: payload is not valid hex: %w", err)
		}
		in.Payload = b
	}
	if poly := strings.TrimSpace(str(p, "crc_poly")); poly != "" {
		v, err := parseHexByte(poly)
		if err != nil {
			return "", fmt.Errorf("subghz_tpms_synth: crc_poly %q invalid: %w", poly, err)
		}
		in.CRCPoly = v
	}
	if g, ok := p["ge_thomas"].(bool); ok {
		in.GEThomas = g
	}

	bits, err := tpms.Synth(in)
	if err != nil {
		return "", fmt.Errorf("subghz_tpms_synth: %w", err)
	}
	frame, _ := tpms.Decode(bits)
	out, _ := json.MarshalIndent(struct {
		Bits  string       `json:"bits"`
		Frame *tpms.Result `json:"decoded_back"`
	}{Bits: bits, Frame: frame}, "", "  ")
	return string(out), nil
}

// parseSensorID accepts a hex (with optional 0x) or decimal 32-bit ID.
func parseSensorID(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	lower := strings.ToLower(s)
	hexish := strings.HasPrefix(lower, "0x")
	if hexish {
		lower = lower[2:]
	}
	// Treat as hex if it has 0x, or contains a-f, or is the common 8-hex form.
	if hexish || strings.ContainsAny(lower, "abcdef") || len(lower) == 8 {
		var v uint64
		for _, c := range lower {
			d := hexDigit(c)
			if d < 0 {
				return 0, fmt.Errorf("invalid hex sensor_id %q", s)
			}
			v = v<<4 | uint64(d)
			if v > 0xFFFFFFFF {
				return 0, fmt.Errorf("sensor_id %q exceeds 32 bits", s)
			}
		}
		return uint32(v), nil
	}
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid decimal sensor_id %q", s)
		}
		v = v*10 + uint64(c-'0')
		if v > 0xFFFFFFFF {
			return 0, fmt.Errorf("sensor_id %q exceeds 32 bits", s)
		}
	}
	return uint32(v), nil
}

func parseHexByte(s string) (byte, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if s == "" || len(s) > 2 {
		return 0, fmt.Errorf("want a 1-2 digit hex byte")
	}
	var v int
	for _, c := range s {
		d := hexDigit(c)
		if d < 0 {
			return 0, fmt.Errorf("not hex")
		}
		v = v<<4 | d
	}
	return byte(v), nil
}

func hexDigit(c rune) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return -1
	}
}
