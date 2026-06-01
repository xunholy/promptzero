// emv_track2.go — host-side EMV Track 2 Equivalent Data decoder Spec,
// delegating to internal/emv.DecodeTrack2.
//
// Wrap-vs-native: native — nfc_emv_decode's BER-TLV walker surfaces tag 57's
// raw value bytes but leaves the nibble-packed track structure intact. This
// cracks that structure (PAN / expiry / service code / discretionary data)
// and validates the PAN against its Luhn check digit — the verification
// anchor that keeps a misframed blob from being asserted as a real card
// number. Pure offline transform over operator-supplied bytes; no hardware.

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
	Register(emvTrack2DecodeSpec)
}

var emvTrack2DecodeSpec = Spec{
	Name: "nfc_emv_track2_decode",
	Description: "Decode EMV tag 57 (Track 2 Equivalent Data) / ISO 7813 track 2 into its fields — the " +
		"PAN, expiry (MM/YY), 3-digit service code (with its decoded meaning), and discretionary data. " +
		"nfc_emv_decode's BER-TLV walker surfaces tag 57's raw value bytes but leaves the nibble-packed " +
		"track structure (<PAN> 'D' <YYMM> <service code> <discretionary> 'F'-pad) intact; this cracks " +
		"it.\n\n" +
		"The PAN's trailing Luhn check digit is validated and reported as luhn_valid: a frame that fails " +
		"Luhn is surfaced with a note rather than asserted as a real card number, so a misframed blob is " +
		"never confidently mis-decoded. The PAN is also returned masked (BIN + last 4) for PCI-aware " +
		"reporting. Pass the Track-2 value hex directly (the value_hex of tag 57 from nfc_emv_decode); a " +
		"full BER-TLV blob is also accepted and tag 57 is extracted from it automatically.\n\n" +
		"Offline transform — reads operator-supplied bytes and decodes them, no hardware, transmits " +
		"nothing, so it is Low risk. Wrap-vs-native: native — nibble unpacking + Luhn over a byte slice.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Track 2 Equivalent Data value hex (tag 57's value), or a full EMV BER-TLV blob containing tag 57. Accepts ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvTrack2DecodeHandler,
}

func emvTrack2DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_emv_track2_decode: 'hex' is required")
	}
	source := "track2"
	res, err := emv.DecodeTrack2Hex(raw)
	if err != nil {
		// Fall back to treating the input as a full TLV blob and pulling tag 57.
		if v, ok := findTag57(raw); ok {
			source = "tag57-extracted"
			res, err = emv.DecodeTrack2(v)
		}
	}
	if err != nil {
		return "", fmt.Errorf("nfc_emv_track2_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"source": source,
		"track2": res,
	}, "", "  ")
	return string(out), nil
}

// findTag57 parses the input as a BER-TLV blob and returns the value bytes of
// the first tag 0x57 (Track 2 Equivalent Data) found at any depth.
func findTag57(hexBlob string) ([]byte, bool) {
	tlvs, err := emv.Parse(hexBlob)
	if err != nil {
		return nil, false
	}
	return searchTag(tlvs, 0x57)
}

func searchTag(tlvs []emv.TLV, tag uint32) ([]byte, bool) {
	for _, t := range tlvs {
		if t.Tag == tag {
			return t.Value, true
		}
		if len(t.Children) > 0 {
			if v, ok := searchTag(t.Children, tag); ok {
				return v, true
			}
		}
	}
	return nil, false
}
