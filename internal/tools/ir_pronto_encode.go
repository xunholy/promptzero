// ir_pronto_encode.go — host-side raw-IR-timing → Pronto HEX (CCF) encoder Spec,
// the inverse of ir_pronto_decode, delegating to internal/ir.EncodePronto.
//
// Wrap-vs-native: native — the timings → Pronto conversion is the documented
// Pronto arithmetic inverted (frequency word from the carrier, each burst =
// round(µs / carrier period)); stdlib only. Round-trips with ir_pronto_decode.
// Offline transform, no hardware, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ir"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(irProntoEncodeSpec)
}

var irProntoEncodeSpec = Spec{
	Name: "ir_pronto_encode",
	Description: "Encode a raw infrared timing capture into a **Pronto HEX (CCF)** code — the inverse of " +
		"`ir_pronto_decode`, and the IR companion to the project's other inverse generators (`em4100_encode`, " +
		"`rfid_pacs_encode`, `subghz_weather_synth`, `dcf77_synth`). Converts a sequence of microsecond " +
		"mark/space durations (from `ir_receive raw`, a Flipper RAW .ir entry, or a logic-analyser trace) plus a " +
		"carrier frequency into a raw-oscillated (format 0x0000) Pronto code — the universal textual IR format " +
		"used by remote databases and learning remotes (Philips Pronto, **Logitech Harmony**, JP1, " +
		"RemoteCentral, IrScrutinizer), so a captured signal can be shared or imported.\n\n" +
		"No confidently-wrong output: the conversion is the documented Pronto/CCF arithmetic inverted — the " +
		"frequency word = round(1000000 / (carrier_hz × 0.241246)) (38000 Hz → 0x006D, the canonical anchor) and " +
		"each burst = round(µs / carrier-period). It **round-trips** with `ir_pronto_decode` (decoding the " +
		"emitted code reproduces the input timings within carrier-period rounding). An odd number of timings (not " +
		"whole mark/space pairs), a non-numeric timing, a non-positive carrier, or a timing that overflows the " +
		"Pronto burst range is rejected. No network, no device, transmits nothing, so it is Low risk. Inputs: " +
		"**timings** (space/comma-separated integer microseconds, alternating mark/space) and optional " +
		"**carrier_hz** (default 38000).\n\n" +
		"Source: docs/catalog/gap-analysis.md (Pronto format; the inverse of the v0.614 ir_pronto_decode). " +
		"Wrap-vs-native: native — documented arithmetic, round-trip-verified, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"timings":{"type":"string","description":"Raw IR timings: space/comma-separated integer microsecond values, alternating mark, space, mark, space… (an even count)."},
			"carrier_hz":{"type":"integer","description":"Carrier frequency in Hz (default 38000, the common consumer-IR carrier)."}
		},
		"required":["timings"]
	}`),
	Required:  []string{"timings"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   irProntoEncodeHandler,
}

func irProntoEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	timings := str(p, "timings")
	if strings.TrimSpace(timings) == "" {
		return "", fmt.Errorf("ir_pronto_encode: 'timings' is required")
	}
	carrier := 38000
	if v, ok := p["carrier_hz"]; ok {
		if f, ok := v.(float64); ok && f != 0 {
			carrier = int(f)
		}
	}
	code, err := ir.EncodePronto(timings, carrier)
	if err != nil {
		return "", fmt.Errorf("ir_pronto_encode: %w", err)
	}
	out := map[string]any{"pronto_hex": code, "carrier_hz": carrier}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
