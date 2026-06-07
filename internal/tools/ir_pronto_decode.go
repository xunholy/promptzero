// ir_pronto_decode.go — host-side Pronto HEX (CCF) IR-code decoder Spec,
// delegating to internal/ir.DecodePronto.
//
// Wrap-vs-native: native — the Pronto -> carrier/timings conversion is fixed,
// documented arithmetic (carrier period = freqWord x 0.241246µs, each burst =
// cycles x period); a word parse + arithmetic + a chain into the existing raw-IR
// protocol decoder, stdlib only. Offline transform, no hardware.

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
	Register(irProntoDecodeSpec)
}

var irProntoDecodeSpec = Spec{
	Name: "ir_pronto_decode",
	Description: "Decode a **Pronto HEX (CCF)** infrared code — the universal textual IR-code format used by " +
		"remote databases and learning remotes (Philips Pronto, **Logitech Harmony**, JP1, RemoteCentral, " +
		"IrScrutinizer). A Pronto code is a list of 16-bit hex words: a format word, a frequency word, the intro " +
		"and repeat burst-pair counts, then the burst values (each in carrier cycles). This converts the code " +
		"into its **carrier frequency** and the **intro / repeat timing sequences in microseconds**, and — for " +
		"the common raw-oscillated format — runs the converted intro timings through the protocol decoder to " +
		"**name the protocol** (NEC / Kaseikyo / Samsung32 / Sony SIRC / RC5). It is the Pronto-format companion " +
		"to `ir_raw_decode` (which takes raw µs timings).\n\n" +
		"No confidently-wrong output: the format-word meanings, the 0.241246µs Pronto clock unit and the " +
		"burst-pair layout are the long-documented Pronto/CCF spec (the frequency word 0x006D → 38029 Hz is the " +
		"canonical anchor). Only the raw formats (0x0000 oscillated / 0x0100 unmodulated) carry burst pairs and " +
		"are converted; a predefined-code format word is reported by value with a note, not mis-converted. The " +
		"chained protocol decode is best-effort — when the intro timings match a known protocol it is named, " +
		"otherwise the carrier + raw timings are surfaced (no guess). A word count inconsistent with the declared " +
		"burst-pair counts, a non-4-hex-digit word, or a zero frequency is rejected. No network, no device, " +
		"transmits nothing, so it is Low risk. The input is the Pronto HEX code; ':' / '-' separators, a '0x' " +
		"prefix and whitespace are tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (the Pronto format the IR decoder previously did not parse). " +
		"Wrap-vs-native: native — a word parse + documented arithmetic + a chain into ir_raw_decode, stdlib " +
		"only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The Pronto HEX (CCF) IR code — space-separated 4-hex-digit words, e.g. '0000 006D 0022 0000 0156 00AB ...'. ':' '-' separators, a '0x' prefix and whitespace tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   irProntoDecodeHandler,
}

func irProntoDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("ir_pronto_decode: 'hex' is required")
	}
	res, err := ir.DecodePronto(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("ir_pronto_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
