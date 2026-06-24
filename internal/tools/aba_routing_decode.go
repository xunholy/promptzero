// aba_routing_decode.go — host-side ABA routing-number decoder Spec,
// delegating to internal/aba.
//
// Wrap-vs-native: native — an RTN is a fixed digit-field layout (4-digit
// Federal Reserve routing symbol + 4-digit institution id + 1 check
// digit) guarded by a weighted modulus-10 checksum; validating it is
// integer arithmetic, stdlib only, no new go.mod dep. The US-domestic
// counterpart to iban_decode (the international account). Offline read,
// no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/aba"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(abaRoutingDecodeSpec)
}

var abaRoutingDecodeSpec = Spec{
	Name: "aba_routing_decode",
	Description: "Decode and validate an **ABA routing number** (RTN) — the 9-digit code that identifies a US " +
		"bank or credit union in ACH and wire transfers. The **US-domestic counterpart to `iban_decode`** " +
		"(the international account): an RTN shows up in ACH-fraud / business-email-compromise lures, leaked " +
		"direct-deposit forms, and check (MICR-line) images.\n\n" +
		"Breaks the RTN into:\n" +
		"- **Federal Reserve routing symbol** — digits 1-4.\n" +
		"- **ABA institution identifier** — digits 5-8 (surfaced raw; the bank name lives only in the " +
		"proprietary ABA registry, not embedded).\n" +
		"- **Check digit** — digit 9.\n" +
		"- **Type + Federal Reserve district** — derived from the leading two digits by the published RTN " +
		"numbering ranges (Government / Primary FRB / Thrift / Electronic-ACH / Traveler's cheque); a prefix " +
		"outside those ranges leaves the district undetermined rather than guessing.\n" +
		"- **Checksum result** — recomputed and compared (`checksum_valid`).\n\n" +
		"The **weighted modulus-10 checksum is the verification anchor**: a mismatch is reported as " +
		"`checksum_valid=false` with a note (a mistyped or transposed RTN), never asserted as a definitively " +
		"fake bank. No confidently-wrong output.\n\n" +
		"Offline transform — reads a string, transmits nothing, so it is Low risk. ' ' / '-' / ':' separators " +
		"are tolerated. Wrap-vs-native: native — modulus-10 arithmetic, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"routing_number":{"type":"string","description":"9-digit ABA routing transit number. ' ' / '-' / ':' separators tolerated."}
		},
		"required":["routing_number"]
	}`),
	Required:  []string{"routing_number"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   abaRoutingDecodeHandler,
}

func abaRoutingDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "routing_number")) == "" {
		return "", fmt.Errorf("aba_routing_decode: 'routing_number' is required")
	}
	res, err := aba.Decode(str(p, "routing_number"))
	if err != nil {
		return "", fmt.Errorf("aba_routing_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
