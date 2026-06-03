// ntag_config_decode.go — host-side NTAG21x configuration-page dissector Spec,
// delegating to internal/ntag.
//
// Wrap-vs-native: native — fixed bit-field extraction from the config pages, no
// dependency. The page layout and every field meaning are taken verbatim from
// the NXP NTAG213/215/216 data sheet (rev 3.2 §8.5.7), verified against the
// document. Offline read of operator-supplied bytes — no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ntag"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ntagConfigDecodeSpec)
}

var ntagConfigDecodeSpec = Spec{
	Name: "ntag_config_decode",
	Description: "Decode the **NTAG21x (NTAG213/215/216) configuration pages** — the registers that control " +
		"an NFC Type-2 tag's password protection, lock state, NFC counter, and UID/counter ASCII-mirror " +
		"feature. Given a tag dump, this answers the first questions about a tag: is it password-protected, " +
		"read+write or write-only, is the configuration permanently locked (CFGLCK), how many failed " +
		"password attempts are allowed (AUTHLIM), and is the NFC read counter enabled. The protection-state " +
		"complement to `ndef_decode` / `nfc_t2t` (which decode the tag's data, not its access registers).\n\n" +
		"Field: **hex** — the two configuration pages CFG0 + CFG1 (8 bytes), optionally followed by the PWD " +
		"and PACK pages (16 bytes); ':' / '-' / whitespace ignored. The config pages live at different " +
		"addresses per variant (29h NTAG213, 83h NTAG215, E3h NTAG216) but the layout is identical. Decodes " +
		"AUTH0 (first protected page), the ACCESS byte (PROT read+write vs write-only, CFGLCK, NFC_CNT_EN, " +
		"NFC_CNT_PWD_PROT, AUTHLIM), and the MIRROR byte (MIRROR_CONF UID/counter mirror, MIRROR_BYTE/PAGE, " +
		"strong-modulation mode).\n\n" +
		"Offline, deterministic, transmits nothing -> Low risk. No confidently-wrong output: an undocumented " +
		"MIRROR_CONF value is surfaced as reserved, and AUTH0=0xFF (protection disabled) is noted rather than " +
		"asserted against an unknown memory size. Verified against the NXP NTAG213/215/216 data sheet " +
		"(rev 3.2 §8.5.7). Wrap-vs-native: native — fixed bit-field extraction.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"NTAG21x config pages, hex: 8 bytes (CFG0+CFG1) or 16 bytes (+PWD+PACK). ':' / '-' / whitespace tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ntagConfigDecodeHandler,
}

func ntagConfigDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ntag_config_decode: 'hex' is required")
	}
	res, err := ntag.DecodeHex(raw)
	if err != nil {
		return "", fmt.Errorf("ntag_config_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
