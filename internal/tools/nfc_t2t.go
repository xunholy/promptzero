// nfc_t2t.go — host-side NFC Forum Type 2 Tag structure dissector Spec,
// delegating to the internal/t2t package.
//
// Wrap-vs-native: native — the Type 2 Tag page layout (NTAG21x / MIFARE
// Ultralight) is a public NFC Forum standard; a fixed-offset read with a
// hand-computable BCC XOR checksum, no hardware. Distinct from mifare
// (Classic) and ndef (the message inside the user pages) — this is the
// tag-structure layer.

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
	Register(nfcT2TDecodeSpec)
}

var nfcT2TDecodeSpec = Spec{
	Name: "nfc_t2t_decode",
	Description: "Decode the NFC Forum Type 2 Tag structure from a memory dump — the page layout shared " +
		"by NXP NTAG213/215/216 and MIFARE Ultralight, by far the most common NFC tags (transit, " +
		"access fobs, amiibo, marketing). Distinct from nfc/mifare (MIFARE Classic) and from " +
		"ndef_decode (the NDEF message inside the user pages): this is the tag-structure layer.\n\n" +
		"Surfaces, from the first 4 pages (16 bytes):\n" +
		" - the **7-byte UID** and its two **BCC** check bytes, each VALIDATED — BCC0 = 0x88 XOR " +
		"UID0..2 (page 0 byte 3), BCC1 = UID3..6 (page 2 byte 0). A mismatch is flagged (a misread " +
		"dump or a non-7-byte-UID tag), so the UID is never silently trusted.\n" +
		" - the **static lock bytes** decoded to the list of locked pages (3-15) plus the " +
		"block-locking bits — i.e. which pages are write-protected.\n" +
		" - the **Capability Container** (page 3): NDEF magic (0xE1), version, NDEF memory size " +
		"(CC2 x 8 bytes), and the read/write access conditions.\n\n" +
		"When the dump size exactly matches an NTAG213/215/216 (45/135/231 pages), the configuration " +
		"pages are also decoded into the password-protection posture — AUTH0 (first page requiring " +
		"authentication), the protected range, read+write vs write-only protection, the failed-auth " +
		"lockout (AUTHLIM), and whether the config is permanently locked (CFGLCK) — the key NFC " +
		"security property. Their location is derived structurally (config is always the last four " +
		"pages of an NTAG21x), so no per-variant page table is guessed; Ultralight EV1 is not covered. " +
		"Pass the dump page-aligned (4 bytes/page); ':' / '-' / '_' " +
		"/ whitespace and a 0x prefix tolerated. Pure offline parser — no card. Companion to " +
		"ndef_decode / nfc_mfu_rdbl. Wrap-vs-native: native — public NFC Forum Type 2 layout, a " +
		"fixed-offset read + BCC checksum, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Type 2 Tag memory dump as hex, page-aligned (4 bytes/page), at least the first 4 pages (16 bytes). Separators / 0x tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nfcT2TDecodeHandler,
}

func nfcT2TDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_t2t_decode: 'hex' is required")
	}
	res, err := t2t.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("nfc_t2t_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
