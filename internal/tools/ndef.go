// ndef.go — host-side NFC Data Exchange Format dissector Spec,
// delegating to the internal/ndef package for the walker proper.
//
// Wrap-vs-native judgement: NDEF is a fully open NFC Forum
// specification. The walker is a recursive descent over record
// headers + payloads with a well-known type catalog (URI prefix
// table, Text language code, Smart Poster nesting). Wrapping a
// FAP for this would add an SD-card install step + a
// firmware-fork dependency for a pure parser. Native delivers
// offline analysis — operators paste the NDEF bytes pulled out
// of any NFC dump and decode every record without the tag
// present.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ndef"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ndefDecodeSpec)
}

var ndefDecodeSpec = Spec{
	Name: "ndef_decode",
	Description: "Decode an NFC Data Exchange Format (NDEF) message into structured records. " +
		"Walks every record in the message; for each record decodes the header flags (MB / ME / " +
		"CF / SR / IL), Type Name Format (TNF), Type, ID, and payload. Well-known types get full " +
		"field decode:\n\n" +
		"- **URI** record (`U`): expands the 36-entry NFC Forum prefix table (`http://www.`, " +
		"`tel:`, `mailto:`, `urn:`, etc.) and surfaces the full URI string.\n" +
		"- **Text** record (`T`): decodes the status byte (UTF-8 vs UTF-16 + language-code " +
		"length), surfaces the ISO 639-1/2 language code and the decoded text.\n" +
		"- **Smart Poster** record (`Sp`): recursively decodes the nested NDEF message so " +
		"operators see the URI / Text / Action records inside.\n\n" +
		"MIME-type records (TNF=2) get the MIME type + payload size surfaced; Absolute URI " +
		"(TNF=3) records surface the URI; External-type records (TNF=4) surface the vendor:name " +
		"string + payload size. Empty / Unknown / Unchanged records pass through with raw hex.\n\n" +
		"Pure offline parser — no Flipper required. Accepts ':' / '-' / '_' / whitespace " +
		"separators. The walker handles short-record (SR=1, 1-byte payload length) and long-" +
		"record (SR=0, 4-byte big-endian payload length) headers, and the optional ID-length " +
		"field (IL=1).\n\n" +
		"Source: docs/catalog/gap-analysis.md (NFC decode space). Wrap-vs-native: native — NDEF " +
		"is a fully open spec at nfc-forum.org, the walker is a recursive descent with a small " +
		"well-known-type table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded NDEF message. ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ndefDecodeHandler,
}

func ndefDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ndef_decode: 'hex' is required")
	}
	msg, err := ndef.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ndef_decode: %w", err)
	}
	out, _ := json.MarshalIndent(msg, "", "  ")
	return string(out), nil
}
