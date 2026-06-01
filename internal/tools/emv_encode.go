// emv_encode.go — host-side EMV BER-TLV builder Spec, the inverse of
// nfc_emv_decode, delegating to internal/emv.Encode.
//
// Wrap-vs-native: native — EMV BER-TLV is a public, deterministic structure
// (ISO/IEC 8825-1 + EMV Book 3); encoding is pure tag/length/value byte
// assembly. Output is round-trip-verified against nfc_emv_decode.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/emv"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(emvEncodeSpec)
}

var emvEncodeSpec = Spec{
	Name: "nfc_emv_encode",
	Description: "Build an EMV BER-TLV byte blob from a tag/value tree — the offline inverse of " +
		"nfc_emv_decode. Emits each tag's bytes, the definite length (minimal short/long form), and " +
		"the value; constructed tags (e.g. 70, 77, A5 — P/C bit set) are rebuilt from their nested " +
		"children. For staging the TLVs an operator sends to a contactless card (PDOL/GPO/command " +
		"data) or constructs as a response in smartcard/NFC testing. Generation only — it performs no " +
		"card I/O and transmits nothing, so it is Low risk like the decoder.\n\n" +
		"Each record is `{tag, value, children}`:\n" +
		" - `tag`: BER tag as hex (e.g. \"5A\", \"9F02\", \"70\").\n" +
		" - `value`: primitive value as hex (ignored for constructed tags).\n" +
		" - `children`: nested records for a constructed tag.\n\n" +
		"Output is the message hex plus the blob decoded back from it for confirmation — round-trip-" +
		"verified against nfc_emv_decode. Companion to nfc_emv_decode. Wrap-vs-native: native — public " +
		"BER-TLV layout, pure byte assembly, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"records":{
				"type":"array",
				"description":"Top-level BER-TLV records (recursive via children).",
				"items":{
					"type":"object",
					"properties":{
						"tag":{"type":"string","description":"BER tag as hex, e.g. 5A / 9F02 / 70."},
						"value":{"type":"string","description":"Primitive value as hex (ignored for constructed tags)."},
						"children":{"type":"array","description":"Nested records for a constructed tag.","items":{"type":"object"}}
					},
					"required":["tag"]
				}
			}
		},
		"required":["records"]
	}`),
	Required:  []string{"records"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvEncodeHandler,
}

func emvEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawRecs, ok := p["records"].([]any)
	if !ok || len(rawRecs) == 0 {
		return "", fmt.Errorf("nfc_emv_encode: 'records' must be a non-empty array")
	}
	tlvs, err := tlvsFromAny(rawRecs)
	if err != nil {
		return "", fmt.Errorf("nfc_emv_encode: %w", err)
	}
	b, err := emv.Encode(tlvs)
	if err != nil {
		return "", fmt.Errorf("nfc_emv_encode: %w", err)
	}
	back, _ := emv.ParseBytes(b)
	out, _ := json.MarshalIndent(struct {
		Hex     string    `json:"hex"`
		Decoded []emv.TLV `json:"decoded_back"`
	}{Hex: strings.ToUpper(hex.EncodeToString(b)), Decoded: back}, "", "  ")
	return string(out), nil
}

// tlvsFromAny converts the tool's JSON record array into []emv.TLV,
// recursing into children for constructed tags.
func tlvsFromAny(raw []any) ([]emv.TLV, error) {
	out := make([]emv.TLV, 0, len(raw))
	for i, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("records[%d] is not an object", i)
		}
		tagStr := strings.TrimSpace(strOf(m["tag"]))
		if tagStr == "" {
			return nil, fmt.Errorf("records[%d]: 'tag' is required", i)
		}
		tag, terr := parseUint32("0x" + strings.TrimPrefix(strings.ToLower(tagStr), "0x"))
		if terr != nil || tag == 0 {
			return nil, fmt.Errorf("records[%d]: invalid tag %q", i, tagStr)
		}
		tlv := emv.TLV{Tag: tag}
		if kids, ok := m["children"].([]any); ok && len(kids) > 0 {
			tlv.Constructed = true
			ch, err := tlvsFromAny(kids)
			if err != nil {
				return nil, err
			}
			tlv.Children = ch
		} else if vStr := strings.TrimSpace(strOf(m["value"])); vStr != "" {
			clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(vStr)
			vb, err := hex.DecodeString(clean)
			if err != nil {
				return nil, fmt.Errorf("records[%d]: value not valid hex: %w", i, err)
			}
			tlv.Value = vb
		}
		out = append(out, tlv)
	}
	return out, nil
}
