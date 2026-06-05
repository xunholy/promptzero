// bcbp_decode.go — host-side IATA Bar Coded Boarding Pass (Resolution
// 792) decoder Spec, delegating to internal/bcbp.
//
// Wrap-vs-native: native — BCBP is a fixed public layout (header + per-leg
// fixed-width mandatory fields + a hex-length-delimited conditional
// section); substring slicing driven by the declared sizes. A travel-OSINT
// companion to mrz_decode. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bcbp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bcbpDecodeSpec)
}

var bcbpDecodeSpec = Spec{
	Name: "bcbp_decode",
	Description: "Decode an **IATA Bar Coded Boarding Pass** (Resolution 792) — the text encoded in the PDF417 / " +
		"Aztec / QR barcode on a boarding pass. Boarding passes are routinely photographed, posted to social " +
		"media and discarded intact, and the barcode leaks the **passenger name**, the **booking reference " +
		"(PNR)** — which with the surname is often enough to open the full reservation on the airline's site " +
		"— the **itinerary**, **seat**, **check-in sequence** and frequent-flyer data. Decoding it is a core " +
		"travel-OSINT / privacy-exposure check (companion to `mrz_decode`).\n\n" +
		"Decodes the **mandatory fields**: format code, number of legs, passenger name, e-ticket indicator, " +
		"and per flight leg the PNR, from/to airports, operating carrier, flight number, flight day-of-year, " +
		"compartment class, seat, check-in sequence and passenger status. Multi-leg passes are supported.\n\n" +
		"No confidently-wrong output: the mandatory fields are fixed-width (verified against the canonical " +
		"IATA Resolution 792 example), and because every leg's conditional section is length-prefixed, leg " +
		"boundaries are found from the declared sizes — a multi-leg pass cannot be mis-sliced. The variable " +
		"**conditional (airline-use) section is surfaced raw** rather than decoded field-by-field (its layout " +
		"is version-dependent and airline-extensible, so guessing it would risk a wrong decode). The flight " +
		"date is a day-of-year (1-366) with **no year encoded**, so it is surfaced as the raw day count and " +
		"not resolved to a calendar date.\n\n" +
		"Offline transform — reads the barcode text, transmits nothing, so it is Low risk. Source: " +
		"docs/catalog/gap-analysis.md (travel-OSINT boarding-pass decode — companion to mrz_decode). " +
		"Wrap-vs-native: native — fixed-width slicing driven by the self-describing length markers, stdlib " +
		"only, no new go.mod dep. Verified against the canonical IATA 792 example boarding pass.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bcbp":{"type":"string","description":"The decoded text string from a boarding-pass PDF417/Aztec/QR barcode (starts with 'M' or 'S')."}
		},
		"required":["bcbp"]
	}`),
	Required:  []string{"bcbp"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bcbpDecodeHandler,
}

func bcbpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "bcbp")) == "" {
		return "", fmt.Errorf("bcbp_decode: 'bcbp' is required")
	}
	res, err := bcbp.Decode(str(p, "bcbp"))
	if err != nil {
		return "", fmt.Errorf("bcbp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
