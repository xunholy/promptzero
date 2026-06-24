// lei_decode.go — host-side LEI (Legal Entity Identifier) decoder Spec,
// delegating to internal/lei.
//
// Wrap-vs-native: native — an LEI is a fixed character-field layout
// (ISO 17442: 4-char GLEIF LOU prefix + 14-char entity part + 2 check
// digits) guarded by the same ISO 7064 MOD-97-10 checksum as an IBAN;
// validating it is integer arithmetic, stdlib only, no new go.mod dep.
// The entity-side companion to iban_decode (the account). Offline read,
// no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/lei"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(leiDecodeSpec)
}

var leiDecodeSpec = Spec{
	Name: "lei_decode",
	Description: "Decode and validate an **LEI** — a Legal Entity Identifier (ISO 17442), the 20-character code " +
		"that identifies a legally distinct entity in financial transactions. The **entity-side companion to " +
		"`iban_decode`** (the account): an LEI shows up in regulatory filings (MiFID II, EMIR), SWIFT " +
		"messaging, and invoice-fraud / BEC lures alongside the IBAN it is meant to corroborate.\n\n" +
		"Breaks the LEI into:\n" +
		"- **LOU prefix** — the leading 4 characters identifying the GLEIF Local Operating Unit that issued it.\n" +
		"- **Entity ID** — the 14-character entity-specific part (surfaced whole; see below).\n" +
		"- **Check digits** — positions 19-20.\n" +
		"- **MOD-97-10 result** — recomputed and compared (`mod97_valid`).\n\n" +
		"The **ISO 7064 MOD-97-10 checksum is the verification anchor**: a mismatch is reported as " +
		"`mod97_valid=false` with the expected check digits in a note (a mistyped LEI), never asserted as a " +
		"definitively fake entity. The entity-specific part is **not split** — the original ISO 17442 \"00\" " +
		"reserved characters at positions 5-6 are not present in every registered LEI, so splitting on that " +
		"convention would be confidently wrong. No confidently-wrong output.\n\n" +
		"Offline transform — reads a string, transmits nothing, so it is Low risk. ' ' / '-' / ':' separators " +
		"and lower case are tolerated. Wrap-vs-native: native — MOD-97-10 arithmetic, stdlib only, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"lei":{"type":"string","description":"Legal Entity Identifier (ISO 17442), 20 characters. ' ' / '-' / ':' separators and lower case tolerated."}
		},
		"required":["lei"]
	}`),
	Required:  []string{"lei"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   leiDecodeHandler,
}

func leiDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "lei")) == "" {
		return "", fmt.Errorf("lei_decode: 'lei' is required")
	}
	res, err := lei.Decode(str(p, "lei"))
	if err != nil {
		return "", fmt.Errorf("lei_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
