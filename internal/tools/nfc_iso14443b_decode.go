// nfc_iso14443b_decode.go — host-side ISO/IEC 14443 Type B ATQB decoder Spec,
// delegating to internal/iso14443b.
//
// Wrap-vs-native: native — decodes the 12-byte Type B ATQB (the answer to
// REQB/WUPB) into PUPI, application data, and the protocol-info parameters. Type
// B is the air interface behind most ePassports (ICAO 9303), several national
// eID cards, and some transit/payment cards — the second proximity standard
// alongside Type A (nfc_iso14443a_identify). The 0x50 leading byte is the hard
// anchor. Offline read of an operator-supplied dump; no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/iso14443b"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(iso14443bDecodeSpec)
}

var iso14443bDecodeSpec = Spec{
	Name: "nfc_iso14443b_decode",
	Description: "Decode an ISO/IEC 14443 Type B ATQB — the PICC's answer to REQB/WUPB. Type B is the air " +
		"interface behind most ePassports (ICAO 9303), several national eID cards, and some transit/payment " +
		"cards; this identifies a Type B card and its protocol parameters, the Type B complement to " +
		"nfc_iso14443a_identify.\n\n" +
		"Field: **atqb** (the 12-byte ATQB, hex — a trailing 2-byte CRC_B is tolerated; ':' / '-' / spaces " +
		"ignored). The 0x50 leading byte is validated (a non-0x50 ATQB is flagged, not mis-decoded); the " +
		"PUPI and card-specific application data are surfaced raw; and the protocol info is decoded into " +
		"max frame size (FSCI), ISO 14443-4 support, frame waiting time (FWI→FWT), the bit-rate capability, " +
		"and NAD/CID support — all documented ISO 14443-3/-4 fields.\n\n" +
		"Offline read of operator-supplied bytes — no hardware, transmits nothing, so it is Low risk. " +
		"Wrap-vs-native: native — fixed ISO 14443-3 byte parsing.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"atqb":{"type":"string","description":"The 12-byte ATQB, hex (leading 0x50…). A trailing CRC_B is tolerated; ':' / '-' / whitespace ignored."}
		},
		"required":["atqb"]
	}`),
	Required:  []string{"atqb"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   iso14443bDecodeHandler,
}

func iso14443bDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	atqb := str(p, "atqb")
	if strings.TrimSpace(atqb) == "" {
		return "", fmt.Errorf("nfc_iso14443b_decode: 'atqb' is required")
	}
	res, err := iso14443b.DecodeATQB(atqb)
	if err != nil {
		return "", fmt.Errorf("nfc_iso14443b_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
