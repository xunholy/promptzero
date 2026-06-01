// ndef_encode.go — host-side NDEF message builder Spec, the inverse of
// ndef_decode, delegating to internal/ndef.Encode.
//
// Wrap-vs-native: native — the NDEF record layout + URI Identifier Code
// table are public (NFC Forum NDEF + RTD specs); encoding is pure byte
// assembly. Output is round-trip-verified against ndef_decode.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ndef"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ndefEncodeSpec)
}

var ndefEncodeSpec = Spec{
	Name: "ndef_encode",
	Description: "Build the raw bytes of an NDEF message from a list of records — the offline inverse " +
		"of ndef_decode. Produces the exact byte blob written to an NFC tag's NDEF area (e.g. a URI " +
		"that auto-opens on tap, or a text record), for tag-writing / cloning / spoofing workflows. " +
		"Generation only — it writes nothing to a tag and transmits nothing (pair with an NFC write " +
		"stage), so it is Low risk like the decoder.\n\n" +
		"Supported well-known record types (the highest-runners for tag writing):\n" +
		" - **uri** — NFC Forum URI record (type \"U\"); the longest-matching prefix (http://www., " +
		"https://, tel:, mailto:, …) is abbreviated to its 1-byte Identifier Code automatically.\n" +
		" - **text** — Text record (type \"T\"); UTF-8 body + language code (default \"en\").\n\n" +
		"The first record gets the Message-Begin flag, the last gets Message-End, and short-record " +
		"length encoding is used for payloads < 256 bytes. Output is the message bytes (hex) plus the " +
		"message decoded back from them for confirmation — round-trip-verified against ndef_decode.\n\n" +
		"Deferred: Smart Poster / MIME / External / chunked records (URI + Text cover the bulk of " +
		"tag-writing). Companion to ndef_decode. Wrap-vs-native: native — public layout + prefix " +
		"table, pure byte assembly, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"records":{
				"type":"array",
				"description":"Ordered NDEF records to build.",
				"items":{
					"type":"object",
					"properties":{
						"kind":{"type":"string","description":"uri or text."},
						"uri":{"type":"string","description":"For kind=uri: the full URI (e.g. https://example.com)."},
						"text":{"type":"string","description":"For kind=text: the UTF-8 body."},
						"lang":{"type":"string","description":"For kind=text: ISO language code (default en)."}
					},
					"required":["kind"]
				}
			}
		},
		"required":["records"]
	}`),
	Required:  []string{"records"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ndefEncodeHandler,
}

func ndefEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawRecs, ok := p["records"].([]any)
	if !ok || len(rawRecs) == 0 {
		return "", fmt.Errorf("ndef_encode: 'records' must be a non-empty array")
	}
	recs := make([]ndef.EncodeRecord, 0, len(rawRecs))
	for i, rr := range rawRecs {
		m, ok := rr.(map[string]any)
		if !ok {
			return "", fmt.Errorf("ndef_encode: records[%d] is not an object", i)
		}
		recs = append(recs, ndef.EncodeRecord{
			Kind: strOf(m["kind"]),
			URI:  strOf(m["uri"]),
			Text: strOf(m["text"]),
			Lang: strOf(m["lang"]),
		})
	}

	b, err := ndef.Encode(recs)
	if err != nil {
		return "", fmt.Errorf("ndef_encode: %w", err)
	}
	back, _ := ndef.DecodeBytes(b)
	out, _ := json.MarshalIndent(struct {
		Hex     string       `json:"hex"`
		Decoded ndef.Message `json:"decoded_back"`
	}{Hex: strings.ToUpper(hex.EncodeToString(b)), Decoded: back}, "", "  ")
	return string(out), nil
}

// strOf coerces an any to a string, tolerating nil/non-string as "".
func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
