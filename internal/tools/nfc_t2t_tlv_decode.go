// nfc_t2t_tlv_decode.go — host-side NFC Type 2 Tag TLV-area dissector Spec,
// delegating to internal/t2t.
//
// Wrap-vs-native: native — fixed TLV framing over the data area, reusing the
// internal/ndef walker for the NDEF Message TLV value. The TLV type values and
// 1-or-3-byte length encoding are from the NFC Forum Type 2 Tag Operation
// Specification (cross-checked vs the Nordic nrfxlib T2T docs). Offline read of
// operator-supplied bytes — no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/t2t"
)

func init() { //nolint:gochecknoinits
	Register(nfcT2TTLVDecodeSpec)
}

var nfcT2TTLVDecodeSpec = Spec{
	Name: "nfc_t2t_tlv_decode",
	Description: "Walk the TLV blocks in an NFC **Type 2 Tag data area** (the user memory from page 4 onward) " +
		"and decode the NDEF message in place. This bridges a raw tag-memory dump to `ndef_decode`: a Type 2 " +
		"Tag (NTAG / MIFARE Ultralight) stores its NDEF message inside a TLV structure, and this locates it " +
		"among the Lock Control / Memory Control / NDEF / Proprietary / Terminator blocks. The data-area " +
		"complement to `nfc_t2t` (which decodes the page 0-3 header: UID / BCC / lock bytes / Capability " +
		"Container).\n\n" +
		"Field: **hex** — the Type 2 Tag data area (TLV blocks; ':' / '-' / '_' / whitespace ignored). For a " +
		"full dump, strip the first 16 bytes (pages 0-3) and pass the rest, or use `nfc_t2t` for the header. " +
		"Each block is reported with its type, offset, length, and raw value; the **NDEF Message TLV** (0x03) " +
		"value is decoded via the NDEF walker (URI / Text / Smart Poster / handover / MIME records). The " +
		"length field's 1-or-3-byte form (the 0xFF big-endian escape) is handled, and the Terminator TLV " +
		"(0xFE) ends the walk.\n\n" +
		"Offline, deterministic, transmits nothing -> Low risk. No confidently-wrong output: a TLV whose " +
		"declared length runs past the buffer is reported as truncated (not silently trusted); the Lock / " +
		"Memory Control reserved-area descriptors are surfaced raw rather than guessed. Wrap-vs-native: " +
		"native — TLV framing over the shared NDEF walker (NFC Forum Type 2 Tag Operation Specification).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"NFC Type 2 Tag data area (TLV blocks, page 4 onward), hex. ':' / '-' / '_' / whitespace tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nfcT2TTLVDecodeHandler,
}

func nfcT2TTLVDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_t2t_tlv_decode: 'hex' is required")
	}
	res, err := t2t.DecodeTLVHex(raw)
	if err != nil {
		return "", fmt.Errorf("nfc_t2t_tlv_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
