// emv_dol.go — host-side EMV Data Object List decoder Spec, delegating to
// internal/emv.DecodeDOL.
//
// Wrap-vs-native: native — a DOL (PDOL/CDOL1/CDOL2/DDOL/TDOL) is a
// concatenation of (tag, length) pairs with NO values, so nfc_emv_decode's
// BER-TLV walker can't parse it (nothing to walk) and leaves the value raw.
// This decodes the list structurally, reusing the same tag-name table.
// Offline transform over operator-supplied bytes; no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/emv"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(emvDOLDecodeSpec)
}

var emvDOLDecodeSpec = Spec{
	Name: "nfc_emv_dol_decode",
	Description: "Decode an EMV Data Object List — PDOL (tag 9F38), CDOL1/CDOL2 (8C/8D), DDOL (9F49), " +
		"or TDOL (97) — into the list of (tag, length) data objects the card asks the terminal to " +
		"supply. A DOL is a concatenation of BER (tag, length) pairs with NO value bytes, so " +
		"nfc_emv_decode's BER-TLV walker can't parse it (there are no values to walk) and leaves the " +
		"value raw; this cracks it.\n\n" +
		"Each entry resolves the requested tag's name from the same curated EMV tag table, and the " +
		"lengths are summed into total_length — the size of the concatenated command data the terminal " +
		"must build (e.g. the GET PROCESSING OPTIONS data assembled from a PDOL). The parse is purely " +
		"structural (tag + length header bytes), so there is nothing to mis-decode — no confidently-wrong " +
		"output.\n\n" +
		"Pass the DOL value hex directly (e.g. tag 9F38's value_hex from nfc_emv_decode); a full EMV " +
		"BER-TLV blob is also accepted, and the first DOL tag (PDOL/CDOL1/CDOL2/DDOL/TDOL) found at any " +
		"depth is extracted automatically. Accepts ':' / '-' / '_' / whitespace separators. Offline " +
		"transform — reads bytes, transmits nothing, so it is Low risk. Wrap-vs-native: native — " +
		"structural (tag,length) walk reusing the EMV tag table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"DOL value hex (a PDOL/CDOL/DDOL/TDOL value), or a full EMV BER-TLV blob containing a DOL tag. Accepts ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvDOLDecodeHandler,
}

func emvDOLDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_emv_dol_decode: 'hex' is required")
	}
	source := "dol"
	// If the input is a full TLV blob carrying a DOL tag, decode that tag's
	// value; otherwise treat the whole input as a raw DOL.
	if v, tagHex, ok := findDOL(raw); ok {
		source = "extracted from " + tagHex
		res, err := emv.DecodeDOL(v)
		if err != nil {
			return "", fmt.Errorf("nfc_emv_dol_decode: %w", err)
		}
		return marshalDOL(source, res)
	}
	res, err := emv.DecodeDOLHex(raw)
	if err != nil {
		return "", fmt.Errorf("nfc_emv_dol_decode: %w", err)
	}
	return marshalDOL(source, res)
}

func marshalDOL(source string, res *emv.DOL) (string, error) {
	out, _ := json.MarshalIndent(map[string]any{
		"source": source,
		"dol":    res,
	}, "", "  ")
	return string(out), nil
}

// findDOL parses the input as a BER-TLV blob and returns the value bytes and
// tag-hex of the first DOL tag found at any depth.
func findDOL(hexBlob string) (value []byte, tagHex string, ok bool) {
	tlvs, err := emv.Parse(hexBlob)
	if err != nil {
		return nil, "", false
	}
	return searchDOL(tlvs)
}

func searchDOL(tlvs []emv.TLV) ([]byte, string, bool) {
	for _, t := range tlvs {
		if emv.IsDOLTag(t.Tag) {
			return t.Value, t.TagHex, true
		}
		if len(t.Children) > 0 {
			if v, th, ok := searchDOL(t.Children); ok {
				return v, th, true
			}
		}
	}
	return nil, "", false
}
