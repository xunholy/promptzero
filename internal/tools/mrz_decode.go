// mrz_decode.go — host-side Machine Readable Zone (passport / ID / visa)
// decoder Spec, delegating to internal/mrz.
//
// Wrap-vs-native: native — the MRZ formats (TD1/TD2/TD3, ICAO Doc 9303)
// are fixed-width field layouts with a public 7-3-1 weighted check-digit
// scheme; substring slicing + a checksum loop. Directly relevant to the
// NFC tooling: the MRZ is the BAC key-derivation input for reading an
// e-passport / e-ID chip. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mrz"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mrzDecodeSpec)
}

var mrzDecodeSpec = Spec{
	Name: "mrz_decode",
	Description: "Decode the **Machine Readable Zone** of a passport, ID card or visa — the `<`-padded OCR-B " +
		"lines at the bottom of an ICAO 9303 travel document. **Directly relevant to the NFC tooling:** the " +
		"MRZ is the input to the **Basic Access Control (BAC)** key derivation that unlocks an e-passport / " +
		"e-ID **NFC chip** (the document number, date of birth and date of expiry — each with its check " +
		"digit — are hashed into the BAC seed), so an MRZ read off the printed document is what lets a reader " +
		"talk to the chip. Also a core OSINT / border-forensics artefact.\n\n" +
		"Auto-detects the format and breaks out the fields:\n" +
		"- **TD3** (passport, 2×44), **TD1** (ID card, 3×30), **TD2** (2×36).\n" +
		"- document type, issuing country, surname + given names, document number, nationality, date of " +
		"birth, sex, date of expiry, and the optional/personal-number field.\n\n" +
		"**Each check digit is the verification anchor** — the document number, date of birth, date of " +
		"expiry, the optional field and the composite are independently recomputed with the ICAO 7-3-1 " +
		"weighted-modulo-10 algorithm and compared; per-field and overall validity (`valid`) are surfaced, " +
		"with a note naming any field that fails. A valid check digit is NOT asserted to prove the document " +
		"is genuine (an MRZ can be transcribed wrong or altered). Dates are surfaced as raw YYMMDD plus an " +
		"ISO rendering with the **century left unresolved** — the MRZ does not encode it, so 19xx vs 20xx is " +
		"not guessed (no confidently-wrong output).\n\n" +
		"Offline transform — reads the MRZ text, transmits nothing, so it is Low risk. Pass the lines " +
		"newline-separated, or as one concatenated string of the known length. Source: " +
		"docs/catalog/gap-analysis.md (travel-document MRZ decode — the BAC-key input for e-passport NFC). " +
		"Wrap-vs-native: native — fixed-width slicing + the public check-digit algorithm, stdlib only, no " +
		"new go.mod dep. Verified field-for-field + check-digit-for-check-digit against the `mrz` reference " +
		"library for TD1/TD2/TD3.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"mrz":{"type":"string","description":"The MRZ lines (TD1 3×30, TD2 2×36, or TD3 2×44), newline-separated or concatenated. '<' is the filler character."}
		},
		"required":["mrz"]
	}`),
	Required:  []string{"mrz"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mrzDecodeHandler,
}

func mrzDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "mrz")) == "" {
		return "", fmt.Errorf("mrz_decode: 'mrz' is required")
	}
	res, err := mrz.Decode(str(p, "mrz"))
	if err != nil {
		return "", fmt.Errorf("mrz_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
