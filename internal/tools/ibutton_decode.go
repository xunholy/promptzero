// ibutton_decode.go — host-side Dallas 1-Wire ROM ID dissector
// Spec, delegating to the internal/ibutton package for the
// family-table walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ibutton"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ibuttonDecodeSpec)
}

var ibuttonDecodeSpec = Spec{
	Name: "ibutton_decode",
	Description: "Decode a Dallas 1-Wire ROM ID (a.k.a. iButton key) into a structured view — the " +
		"complement to ibutton_read / ibutton_emulate / ibutton_write, which all need physical " +
		"hardware contact with the key. Per Maxim Application Notes AN001 + AN-27 + AN1796. Decodes:\n\n" +
		"- **64-bit ROM ID layout**: 8-bit family code + 48-bit serial + 8-bit CRC.\n" +
		"- **Family-code → device-type lookup**: ~45 documented Maxim/Dallas devices including " +
		"DS1990A / DS2401 / DS2411 (the canonical 'unique ID' iButton — family 0x01), DS18B20 " +
		"temperature sensors (family 0x28), DS2431 / DS1972 1Kb EEPROM (family 0x2D), DS2438 " +
		"smart battery monitor (family 0x26), DS2408 8-channel switch (family 0x29), DS1820 / " +
		"DS18S20 (family 0x10), DS1971 / DS2430A 256-bit EEPROM (family 0x14), DS2433 4Kb EEPROM " +
		"(family 0x23), DS1922 Thermochron (family 0x41), DS2413 dual-channel PIO switch (family " +
		"0x3A), and the rest of the published 1-Wire device line.\n" +
		"- **Dallas CRC-8 validation**: polynomial 0x31 (reflected as 0x8C), init 0x00, no final " +
		"XOR. Surfaces both the captured CRC byte and the computed expected value so operators " +
		"can diff a misread frame.\n\n" +
		"Pure offline parser — operators paste the hex bytes printed by ibutton_read (or any " +
		"Flipper iButton dump) and inspect the family / serial / CRC fields without re-touching " +
		"the key. Pairs with ibutton_read for live captures and ibutton_emulate / ibutton_write " +
		"for replay; this Spec extends the iButton tool family with the missing host-side " +
		"forensic decode step.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.\n\n" +
		"Scope: Dallas DS-family ROM IDs only (8-byte fixed width). Cyfral and Metakom " +
		"Russian-intercom-key variants use different bit-widths and Manchester encodings — they " +
		"will land as separate Specs (ibutton_cyfral_decode / ibutton_metakom_decode) in future " +
		"iterations.\n\n" +
		"Source: docs/catalog/gap-analysis.md (LF baseline gap — iButton is the contact-based " +
		"complement to the wireless LF rfid_pacs_decode line). Wrap-vs-native: native — the " +
		"1-Wire ROM-ID layout is public, the CRC is a 4-line bit walker, and the family table " +
		"is a static lookup with no hardware dependency.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Dallas 1-Wire ROM ID (8 bytes; 16 hex chars). ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ibuttonDecodeHandler,
}

func ibuttonDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ibutton_decode: 'hex' is required")
	}
	res, err := ibutton.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ibutton_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
