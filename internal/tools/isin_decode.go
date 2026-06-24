// isin_decode.go — host-side ISIN (International Securities
// Identification Number) decoder Spec, delegating to internal/isin.
//
// Wrap-vs-native: native — an ISIN is a fixed character-field layout
// (ISO 6166: 2-letter prefix + 9-char NSIN + 1 Luhn check digit);
// validating it is integer arithmetic over the letter-expanded body,
// stdlib only, no new go.mod dep. The securities leg of the financial-
// data decoder family with iban_decode (account) and lei_decode
// (entity). Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/isin"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(isinDecodeSpec)
}

var isinDecodeSpec = Spec{
	Name: "isin_decode",
	Description: "Decode and validate an **ISIN** — an International Securities Identification Number (ISO 6166), " +
		"the 12-character code that identifies a tradable security (stock, bond, fund). The **securities leg of " +
		"the financial-data decoder family** with `iban_decode` (the account) and `lei_decode` (the entity). " +
		"Shows up in brokerage statements, trade confirmations, market-data dumps, and investment-fraud lures.\n\n" +
		"Breaks the ISIN into:\n" +
		"- **Prefix** — the leading 2 letters (an ISO 3166-1 country code, or a special code such as `XS` for " +
		"internationally-cleared issues; surfaced raw, not mapped to a country name).\n" +
		"- **NSIN** — the 9-character National Securities Identifying Number (surfaced whole; see below).\n" +
		"- **Check digit** — position 12.\n" +
		"- **Luhn result** — recomputed and compared (`luhn_valid`).\n\n" +
		"The **ISO 6166 modulus-10 (Luhn) check digit is the verification anchor**: a mismatch is reported as " +
		"`luhn_valid=false` with the expected check digit in a note (a mistyped ISIN), never asserted as a " +
		"definitively fake security. The NSIN is **not split** into its national scheme (CUSIP / SEDOL / WKN) — " +
		"that split is prefix-specific with no single public rule. No confidently-wrong output.\n\n" +
		"Offline transform — reads a string, transmits nothing, so it is Low risk. ' ' / '-' / ':' separators " +
		"and lower case are tolerated. Wrap-vs-native: native — Luhn arithmetic, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"isin":{"type":"string","description":"International Securities Identification Number (ISO 6166), 12 characters. ' ' / '-' / ':' separators and lower case tolerated."}
		},
		"required":["isin"]
	}`),
	Required:  []string{"isin"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   isinDecodeHandler,
}

func isinDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "isin")) == "" {
		return "", fmt.Errorf("isin_decode: 'isin' is required")
	}
	res, err := isin.Decode(str(p, "isin"))
	if err != nil {
		return "", fmt.Errorf("isin_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
