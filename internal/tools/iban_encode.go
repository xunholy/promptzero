// iban_encode.go — host-side IBAN builder Spec, the inverse of
// iban_decode, delegating to internal/iban.Encode.
//
// Wrap-vs-native: native — an IBAN's check digits are a deterministic
// ISO 7064 MOD-97-10 function of the country code + BBAN; computing them
// is integer arithmetic, stdlib only, no new go.mod dep. Output is
// round-trip-verified against iban_decode. Generation only — emits a
// string, transmits nothing, so it is Low risk like the decoder.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/iban"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ibanEncodeSpec)
}

var ibanEncodeSpec = Spec{
	Name: "iban_encode",
	Description: "Build a valid **IBAN** from a country code and a BBAN by computing the **ISO 7064 MOD-97-10 " +
		"check digits** — the offline inverse of `iban_decode`. For staging test vectors, fuzzing-corpus " +
		"entries, or repairing the check digits of an IBAN whose body is known.\n\n" +
		"Inputs:\n" +
		"- **country_code** — the 2-letter ISO 3166-1 country code (e.g. `GB`).\n" +
		"- **bban** — the country-specific Basic Bank Account Number body (the part after the check digits).\n\n" +
		"' ' / '-' / ':' separators and lower case are tolerated. The output is the assembled IBAN run back " +
		"through the decoder for confirmation, so `mod97_valid` is true by construction — the result is " +
		"round-trip-verified against `iban_decode`, not merely asserted. Generation only: it performs no I/O " +
		"and transmits nothing, so it is Low risk like the decoder. Companion to `iban_decode`. Wrap-vs-native: " +
		"native — MOD-97-10 arithmetic, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"country_code":{"type":"string","description":"2-letter ISO 3166-1 country code (e.g. GB). Lower case tolerated."},
			"bban":{"type":"string","description":"Basic Bank Account Number body (country-specific). ' ' / '-' / ':' separators tolerated."}
		},
		"required":["country_code","bban"]
	}`),
	Required:  []string{"country_code", "bban"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ibanEncodeHandler,
}

func ibanEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	cc := strings.TrimSpace(str(p, "country_code"))
	bban := strings.TrimSpace(str(p, "bban"))
	if cc == "" || bban == "" {
		return "", fmt.Errorf("iban_encode: 'country_code' and 'bban' are required")
	}
	res, err := iban.Encode(cc, bban)
	if err != nil {
		return "", fmt.Errorf("iban_encode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
