// dcf77.go — host-side DCF77 time-signal decoder Spec,
// delegating to the internal/dcf77 package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dcf77"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dcf77DecodeSpec)
}

var dcf77DecodeSpec = Spec{
	Name: "dcf77_decode",
	Description: "Decode a 60-bit DCF77 time-signal frame — the long-wave (77.5 kHz) radio " +
		"broadcast from Mainflingen, Germany that carries current Central European time + " +
		"date. Per PTB DCF77 specification. Decodes:\n\n" +
		"- **Header** (bits 0-19): start-of-minute marker, encrypted weather data, " +
		"antenna-switch + DST-change announcements, CET vs CEST timezone, leap-second " +
		"announcement, start-of-time marker.\n" +
		"- **Time** (bits 20-35): minute (BCD weights 1,2,4,8,10,20,40) + even parity, " +
		"hour (BCD weights 1,2,4,8,10,20) + even parity.\n" +
		"- **Date** (bits 36-58): day of month (BCD 1..31), day of week (ISO 1=Monday " +
		"through 7=Sunday with English name lookup), month (BCD 1..12), year (BCD 0..99 — " +
		"caller chooses the century), date parity.\n\n" +
		"Surfaces formatted time ('HH:MM') + date ('YYYY-MM-DD' using 20YY century " +
		"assumption) for quick reads. Reports per-field parity validity + a single " +
		"AllParityValid convenience flag for frame integrity.\n\n" +
		"Pure offline parser — operators paste a 60-bit DCF77 bit-stream captured by their " +
		"SDR (rtl_sdr → gnuradio DCF77 block) or consumer radio-clock test pin and decode " +
		"the time without running a fresh capture. Accepts ':' / '-' / '_' / whitespace " +
		"separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Sub-GHz time-signal decode space). " +
		"Wrap-vs-native: native — the DCF77 frame format is fully public (PTB DCF77 spec, " +
		"ETSI EN 300 220-1), the walker is bit-level decoding over a 60-bit frame.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bits":{"type":"string","description":"60-bit DCF77 frame as a string of '0' and '1' characters. ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["bits"]
	}`),
	Required:  []string{"bits"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dcf77DecodeHandler,
}

func dcf77DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "bits")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("dcf77_decode: 'bits' is required")
	}
	res, err := dcf77.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("dcf77_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
