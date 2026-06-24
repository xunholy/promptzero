// iban_decode.go — host-side IBAN (International Bank Account Number)
// decoder Spec, delegating to internal/iban.
//
// Wrap-vs-native: native — an IBAN is a fixed character-field layout
// (ISO 13616: 2-letter country code + 2 check digits + country-specific
// BBAN) guarded by an ISO 7064 MOD-97-10 checksum; validating it is
// integer arithmetic, stdlib only, no new go.mod dep. The financial-
// account leg of the data-decoder family with track2 (payment card),
// iccid (SIM), imei (device). Offline read, no hardware.

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
	Register(ibanDecodeSpec)
}

var ibanDecodeSpec = Spec{
	Name: "iban_decode",
	Description: "Decode and validate an **IBAN** — an International Bank Account Number (ISO 13616). Turns up " +
		"in leaked spreadsheets, invoice-fraud / BEC lures, and clipboard-hijacker payloads; decoding one off a " +
		"paste tells you the issuing country and whether the number is internally consistent.\n\n" +
		"Breaks the IBAN into:\n" +
		"- **Country code** — the leading ISO 3166-1 alpha-2 letters (surfaced raw, not mapped to a country " +
		"name — that would need a table the IBAN itself does not carry).\n" +
		"- **Check digits** — positions 3-4.\n" +
		"- **BBAN** — the Basic Bank Account Number (surfaced whole; see below).\n" +
		"- **MOD-97-10 result** — recomputed and compared (`mod97_valid`).\n\n" +
		"The **ISO 7064 MOD-97-10 checksum is the verification anchor**: a mismatch is reported as " +
		"`mod97_valid=false` with the expected check digits in a note (a mistyped IBAN, or one whose check " +
		"digits were stripped), never asserted as a definitively fraudulent account. The **BBAN is not split** " +
		"into bank / branch / account — that split is country-specific with no single public rule, so it is " +
		"surfaced combined rather than guessed (the same reason `iccid_decode` surfaces issuer+account " +
		"combined). The per-country length is not enforced — MOD-97-10 already catches truncation and " +
		"transposition. No confidently-wrong output.\n\n" +
		"Offline transform — reads a string, transmits nothing, so it is Low risk. ' ' / '-' / ':' separators " +
		"and lower case are tolerated. Wrap-vs-native: native — MOD-97-10 arithmetic, stdlib only, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"iban":{"type":"string","description":"International Bank Account Number (ISO 13616). ' ' / '-' / ':' separators and lower case tolerated."}
		},
		"required":["iban"]
	}`),
	Required:  []string{"iban"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ibanDecodeHandler,
}

func ibanDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "iban")) == "" {
		return "", fmt.Errorf("iban_decode: 'iban' is required")
	}
	res, err := iban.Decode(str(p, "iban"))
	if err != nil {
		return "", fmt.Errorf("iban_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
