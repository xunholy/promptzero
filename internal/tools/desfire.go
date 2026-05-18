// desfire.go — host-side DESFire AID dissector Spec,
// delegating to the internal/desfire package for the lookup +
// bitfield walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/desfire"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(nfcDesfireAIDDecodeSpec)
}

var nfcDesfireAIDDecodeSpec = Spec{
	Name: "nfc_desfire_aid_decode",
	Description: "Decode a 3-byte Mifare DESFire Application Identifier (AID) — the value " +
		"returned by the DESFire GetApplicationIDs command that identifies each application " +
		"stored on the card. Per NXP DESFire reference + ISO/IEC 7816-5 + NXP AN10833 (MAD " +
		"format). Decodes:\n\n" +
		"- **Special values**: empty (0x000000 — card master, no application), MIFARE Classic " +
		"emulation (0xF40000 — DESFire pretending to be a Classic), wildcard (0xFFFFFF).\n" +
		"- **MAD-formatted AID detection** (high nibble 0xF): the MIFARE Application Directory " +
		"format. Splits into 12-bit function code (category) + 12-bit vendor sub-ID.\n" +
		"- **Function code category** lookup for MAD AIDs: MIFARE Classic emulation (0xF40), " +
		"Transit applications (0xF48), Banking (0xF44), Retail / loyalty (0xFA4), Access " +
		"control (0xFCA), Vending (0xFC4), Parking (0xFCC), Membership (0xFE0), Health (0xFE4), " +
		"Education (0xFE8), Time recording (0xFD2), Vendor-specific (0xF80-0xF8F).\n" +
		"- **Well-known AID name** catalog: full-AID matches for MIFARE Classic emulation, " +
		"OV-chipkaart (Dutch transit), HID iCLASS-SE NDEF, ePassport entries, Adam Opel Card " +
		"loyalty.\n\n" +
		"Pure offline parser — operators paste a DESFire AID from a Flipper / Proxmark / " +
		"pcsc_scan 'list applications' output and identify the application without re-presenting " +
		"the card. Pairs with the existing NFC decoders (nfc_iso14443a_identify for the " +
		"card-type identification, mifare_classic_decode for the Classic emulation path, " +
		"nfc_emv_decode for EMV BER-TLV inside DESFire applications). Accepts '0x' prefix and " +
		"':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (DESFire decode space). Wrap-vs-native: native — " +
		"DESFire AID format is a public NXP spec, the walker is a 3-byte lookup with a " +
		"per-function-code category table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"3-byte DESFire AID hex (6 chars; e.g. 'F40000' for MIFARE Classic emulation). Accepts '0x' prefix and ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nfcDesfireAIDDecodeHandler,
}

func nfcDesfireAIDDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_desfire_aid_decode: 'hex' is required")
	}
	res, err := desfire.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("nfc_desfire_aid_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
