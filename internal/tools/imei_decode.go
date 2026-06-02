// imei_decode.go — host-side GSM device-identity (IMEI / IMEISV) decoder and
// Luhn validator Spec, delegating to internal/imei.
//
// Wrap-vs-native: native — the IMEI structure (TAC + serial + Luhn check
// digit, 3GPP TS 23.003) and the Luhn algorithm are public fixed specs over a
// digit string. It is the offline complement to the cellular tooling: an IMEI
// is disclosed in a GSM/LTE Identity Response (the message an IMSI-catcher
// forces, visible in a gsmtap capture), so an identity read off the air can be
// validated and broken down here. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/imei"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(imeiDecodeSpec)
}

var imeiDecodeSpec = Spec{
	Name: "imei_decode",
	Description: "Decode and validate a GSM device identity — the 15-digit IMEI (with its Luhn check " +
		"digit) or the 16-digit IMEISV (software-version variant). The offline complement to the " +
		"cellular tooling: an IMEI is disclosed in a GSM/LTE Identity Response — the message an " +
		"IMSI-catcher forces to deanonymise a handset, visible in a gsmtap capture — so an identity read " +
		"off the air can be validated and broken down here.\n\n" +
		"For an IMEI, the Luhn check digit is recomputed from the first 14 digits and compared (the " +
		"verification anchor) — a mismatch is reported as luhn_valid=false with a note (a mistyped digit " +
		"also fails it), not asserted as a definitively fake device. Returns the Type Allocation Code " +
		"(TAC, digits 1-8) with its leading Reporting Body Identifier, the 6-digit serial, and the check " +
		"digit (IMEI) or 2-digit software version (IMEISV, which is not Luhn-checked). The TAC is " +
		"surfaced raw — the TAC-to-manufacturer/model registry (the GSMA database) is proprietary, so a " +
		"device make/model is deliberately NOT guessed (no confidently-wrong output).\n\n" +
		"Offline transform — reads a digit string, transmits nothing, so it is Low risk. " +
		"' ' / '-' / '/' separators tolerated. Wrap-vs-native: native — Luhn + structural split over a " +
		"digit string, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"imei":{"type":"string","description":"15-digit IMEI or 16-digit IMEISV. ' ' / '-' / '/' separators tolerated."}
		},
		"required":["imei"]
	}`),
	Required:  []string{"imei"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   imeiDecodeHandler,
}

func imeiDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "imei")) == "" {
		return "", fmt.Errorf("imei_decode: 'imei' is required")
	}
	res, err := imei.Decode(str(p, "imei"))
	if err != nil {
		return "", fmt.Errorf("imei_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
