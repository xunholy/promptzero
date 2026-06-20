// emv_aip.go — host-side EMV Application Interchange Profile (tag 82) decoder
// Spec, delegating to internal/emv.DecodeAIP.
//
// Wrap-vs-native: native — the AIP is a fixed 2-byte EMV Book 3 Annex C1
// bitfield in which the card advertises its authentication capabilities
// (SDA/DDA/CDA, cardholder verification, issuer authentication). nfc_emv_decode's
// BER-TLV walker surfaces tag 82's value raw; this cracks it into the named
// capability bits and the single most security-relevant takeaway — which (if
// any) offline data-authentication method the card supports. The bit names come
// from the published EMV table with raw bytes always surfaced. Offline read, no
// hardware.

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
	Register(emvAIPDecodeSpec)
}

var emvAIPDecodeSpec = Spec{
	Name: "nfc_emv_aip_decode",
	Description: "Decode an EMV Application Interchange Profile (tag 82) — the 2-byte bitfield in which a " +
		"payment card advertises which authentication and verification capabilities it supports. This is " +
		"the single most security-relevant field on an EMV card dump: it tells you the card's offline " +
		"data-authentication method (SDA / DDA / CDA), whether cardholder verification and issuer " +
		"authentication are supported, and whether terminal risk management is requested. " +
		"nfc_emv_decode's BER-TLV walker surfaces tag 82's value raw; this cracks it.\n\n" +
		"Byte 1's seven defined bits are decoded per EMV Book 3, Annex C1: SDA (0x40), DDA (0x20), " +
		"cardholder verification (0x10), terminal risk management (0x08), issuer authentication (0x04), " +
		"on-device cardholder verification (0x02, EMV 4.3+) and CDA (0x01). The offline_data_authentication " +
		"headline picks the strongest method present (CDA > DDA > SDA), flagging SDA-only cards as " +
		"replayable/clone-prone and no-offline-auth cards as online-only. Byte 1 bit 8 and the whole of " +
		"byte 2 are RFU in the contact profile (contactless kernels repurpose byte 2) and are surfaced " +
		"raw with a note rather than guessed — no confidently-wrong output. Gated structurally: exactly " +
		"2 bytes.\n\n" +
		"Pass the AIP value hex directly (tag 82's value_hex from nfc_emv_decode); a full EMV BER-TLV " +
		"blob is also accepted and tag 82 is extracted automatically. Offline transform — reads bytes, " +
		"transmits nothing, so it is Low risk. Wrap-vs-native: native — fixed-layout bit decode + a " +
		"bounded EMV name table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"AIP value hex (tag 82's 2-byte value, e.g. \"7C00\"), or a full EMV BER-TLV blob containing tag 82. Accepts ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvAIPDecodeHandler,
}

func emvAIPDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_emv_aip_decode: 'hex' is required")
	}
	source := "aip"
	res, err := emv.DecodeAIPHex(raw)
	if err != nil {
		// Fall back to treating the input as a full TLV blob and pulling tag 82.
		if tlvs, perr := emv.Parse(raw); perr == nil {
			if v, ok := searchTag(tlvs, 0x82); ok {
				source = "tag82-extracted"
				res, err = emv.DecodeAIP(v)
			}
		}
	}
	if err != nil {
		return "", fmt.Errorf("nfc_emv_aip_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"source": source,
		"aip":    res,
	}, "", "  ")
	return string(out), nil
}
