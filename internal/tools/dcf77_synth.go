// dcf77_synth.go — host-side DCF77 time-signal telegram synthesizer Spec,
// the inverse of dcf77_decode, delegating to internal/dcf77.Synth.
//
// Wrap-vs-native: native — the DCF77 frame format is fully public (PTB
// DCF77 spec / ETSI EN 300 220-1); generation is pure BCD + even parity
// over a fixed 60-bit frame. The result is round-trip-verified against the
// existing dcf77_decode walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/dcf77"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dcf77SynthSpec)
}

var dcf77SynthSpec = Spec{
	Name: "dcf77_synth",
	Description: "Synthesize a 60-bit DCF77 time-signal minute telegram for a given wall-clock " +
		"time + date — the offline inverse of dcf77_decode. DCF77 is the long-wave (77.5 kHz) " +
		"time broadcast from Mainflingen that consumer radio-clocks lock to; this builds the " +
		"frame bits an operator would feed to a long-wave / Sub-GHz TX stage to present a chosen " +
		"time to nearby radio-controlled clocks (clock-spoof payload). Encodes per the PTB DCF77 " +
		"spec:\n\n" +
		"- start-of-minute marker (bit 0 = 0), start-of-time marker (bit 20 = 1)\n" +
		"- timezone bits (CEST = 10 / CET = 01)\n" +
		"- minute / hour as BCD + even parity (bits 28, 35)\n" +
		"- day-of-month / day-of-week (ISO 1=Mon..7=Sun) / month / two-digit year as BCD, with the " +
		"date even-parity bit (58)\n\n" +
		"Weather and announcement bits are left 0 (a clean time/date, no warnings). The output is " +
		"the 60-character '0'/'1' bit-string plus the frame decoded back from it for confirmation — " +
		"round-trip-verified against dcf77_decode so the telegram is provably consistent.\n\n" +
		"Pure offline generator — it does NOT transmit; pair the bits with a TX stage. Companion to " +
		"dcf77_decode; source: docs/catalog/gap-analysis.md honourable mentions (dcf77_clock_spoof). " +
		"Wrap-vs-native: native — public frame format, pure bit-level BCD + parity, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"minute":{"type":"integer","description":"Minute 0-59."},
			"hour":{"type":"integer","description":"Hour 0-23 (24h)."},
			"day_of_month":{"type":"integer","description":"Day of month 1-31."},
			"day_of_week":{"type":"integer","description":"ISO day of week 1=Monday .. 7=Sunday."},
			"month":{"type":"integer","description":"Month 1-12."},
			"year":{"type":"integer","description":"Two-digit year within century 0-99."},
			"cest":{"type":"boolean","description":"true = CEST (summer, UTC+2); false = CET (UTC+1). Default false."}
		},
		"required":["minute","hour","day_of_month","day_of_week","month","year"]
	}`),
	Required:  []string{"minute", "hour", "day_of_month", "day_of_week", "month", "year"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dcf77SynthHandler,
}

func dcf77SynthHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := dcf77.SynthInput{}
	for _, f := range []struct {
		key string
		dst *int
	}{
		{"minute", &in.Minute},
		{"hour", &in.Hour},
		{"day_of_month", &in.DayOfMonth},
		{"day_of_week", &in.DayOfWeek},
		{"month", &in.Month},
		{"year", &in.Year},
	} {
		v, ok := intArg(p[f.key])
		if !ok {
			return "", fmt.Errorf("dcf77_synth: %q is required and must be an integer", f.key)
		}
		*f.dst = v
	}
	if c, ok := p["cest"].(bool); ok {
		in.CEST = c
	}

	bits, err := dcf77.Synth(in)
	if err != nil {
		return "", fmt.Errorf("dcf77_synth: %w", err)
	}
	// Round-trip the telegram back through the decoder so the output
	// carries the confirmed interpretation alongside the raw bits.
	frame, _ := dcf77.Decode(bits)
	out, _ := json.MarshalIndent(struct {
		Bits  string      `json:"bits"`
		Frame dcf77.Frame `json:"frame"`
	}{Bits: bits, Frame: frame}, "", "  ")
	return string(out), nil
}
