// iso14443a.go — host-side ISO 14443A tag-type identifier Spec,
// delegating to the internal/iso14443a package for the lookup +
// bitfield walker proper.
//
// Wrap-vs-native judgement: the ATQA / SAK encoding and the
// per-vendor tag-type table are public — NXP application notes
// AN10833 / AN10927 + ISO/IEC 14443-3/-4. Wrapping a FAP for
// this would add an SD-card install step + a firmware-fork
// dependency for a pure lookup. Native delivers offline
// analysis — operators paste a Flipper / Proxmark "nfc read"
// output and identify the card type without re-presenting the
// card.
//
// Pairs with the Bruce / Proxmark / Flipper "nfc read"
// transports (which return raw ATQA / SAK / UID) and with the
// existing mifare_classic_decode_block (which decodes content
// once the type is known).

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/iso14443a"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(nfcISO14443AIdentifySpec)
}

var nfcISO14443AIdentifySpec = Spec{
	Name: "nfc_iso14443a_identify",
	Description: "Identify an ISO/IEC 14443-3 Type A NFC card from its anti-collision " +
		"response (ATQA + SAK + UID, plus optional ATS). Looks up the (ATQA, SAK) " +
		"combination against the documented tag-type table — Mifare Classic 1K / 4K / Mini, " +
		"Mifare Ultralight / NTAG family, Mifare DESFire EV1/EV2/EV3, JCOP, SmartMX with " +
		"Mifare emulation, Mifare Plus, Infineon variants. Decodes the ATQA bitfield " +
		"(UID size hint, bit-frame anti-collision, proprietary high-byte bits), the SAK " +
		"bitfield (cascade bit, ISO 14443-4 vs 14443-3-only compliance), and classifies the " +
		"UID (4 / 7 / 10 bytes, manufacturer name from the first byte or after a 0x88 " +
		"cascade tag).\n\n" +
		"When the operator supplies the optional ATS (Answer To Select), the decoder parses " +
		"TL + T0 (TA1 / TB1 / TC1 presence flags + FSCI → FSC frame size), surfaces the " +
		"interface bytes as hex, and renders historical bytes as both hex and printable-" +
		"ASCII preview.\n\n" +
		"Pure offline parser — no Flipper required. Pairs with the Bruce / Proxmark / " +
		"Flipper `nfc read` transports and with `mifare_classic_decode_block` (decodes " +
		"content once the type is known). Accepts ':' / '-' / '_' / whitespace separators in " +
		"all fields; auto-detects reversed-endian ATQA when the operator's tool displays " +
		"wire-byte order.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NFC decode space). Wrap-vs-native: native — " +
		"NXP AN10833 Table 6 + AN10927 + ISO/IEC 14443 are fully public, the walker is a " +
		"lookup table + bitfield decoder.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"atqa":{"type":"string","description":"2-byte ATQA hex (e.g. '0004' for Mifare Classic 1K). ':' / '-' / '_' / whitespace separators tolerated. Auto-detects reversed-endian display."},
			"sak":{"type":"string","description":"1-byte SAK hex (e.g. '08' for Classic 1K)."},
			"uid":{"type":"string","description":"4 / 7 / 10-byte UID hex. Cascade tag 0x88 detected."},
			"ats":{"type":"string","description":"Optional Answer To Select hex. Parsed when present."}
		},
		"required":["atqa","sak","uid"]
	}`),
	Required:  []string{"atqa", "sak", "uid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nfcISO14443AIdentifyHandler,
}

func nfcISO14443AIdentifyHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	atqa := strings.TrimSpace(str(p, "atqa"))
	sak := strings.TrimSpace(str(p, "sak"))
	uid := strings.TrimSpace(str(p, "uid"))
	ats := strings.TrimSpace(str(p, "ats"))
	if atqa == "" || sak == "" || uid == "" {
		return "", fmt.Errorf("nfc_iso14443a_identify: 'atqa', 'sak', and 'uid' are required")
	}
	res, err := iso14443a.Identify(atqa, sak, uid, ats)
	if err != nil {
		return "", fmt.Errorf("nfc_iso14443a_identify: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
