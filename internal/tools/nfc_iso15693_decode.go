// nfc_iso15693_decode.go — host-side ISO/IEC 15693 vicinity-card identity
// decoder Spec, delegating to internal/iso15693.
//
// Wrap-vs-native: native — decodes the 8-byte ISO 15693 UID (the second major
// HF NFC standard alongside ISO 14443) into prefix / IC-manufacturer / serial,
// plus an optional AFI application-family byte. The 0xE0 UID prefix is the hard
// anchor and the manufacturer is looked up in the ISO 7816-6 table shared with
// internal/iso14443a. Offline read of an operator-supplied dump; no hardware.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/iso15693"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(iso15693DecodeSpec)
}

var iso15693DecodeSpec = Spec{
	Name: "nfc_iso15693_decode",
	Description: "Decode an ISO/IEC 15693 vicinity-card (HF 13.56 MHz) identity — the UID and, optionally, " +
		"the AFI byte. ISO 15693 is the second major HF NFC standard alongside ISO 14443 (the project's " +
		"nfc_iso14443a_identify), seen on library / access-control / medical / laundry / industrial tags " +
		"(NXP ICODE, TI Tag-it, ST LRI). The card-recon complement that identifies what kind of 15693 tag a " +
		"dump came from.\n\n" +
		"Fields: **uid** (8-byte UID, MSB-first hex — ':' / '-' / '_' / spaces tolerated) and optional " +
		"**afi** (the Application Family Identifier byte, hex). The UID is split into the 0xE0 prefix " +
		"(validated — a UID that doesn't start 0xE0 is flagged as non-standard, not mis-decoded), the IC " +
		"manufacturer (from the ISO 7816-6 registry; unknown codes surfaced raw, never guessed), and the " +
		"6-byte IC serial. The AFI's high nibble is expanded to its documented application family.\n\n" +
		"Offline read of operator-supplied bytes — no hardware, transmits nothing, so it is Low risk. " +
		"Wrap-vs-native: native — fixed ISO 15693-3 byte parsing + the shared manufacturer table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid":{"type":"string","description":"The 8-byte ISO 15693 UID, MSB-first hex (e.g. E004…). ':' / '-' / '_' / whitespace tolerated."},
			"afi":{"type":"string","description":"Optional Application Family Identifier byte (hex)."}
		},
		"required":["uid"]
	}`),
	Required:  []string{"uid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   iso15693DecodeHandler,
}

func iso15693DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	uid := str(p, "uid")
	if strings.TrimSpace(uid) == "" {
		return "", fmt.Errorf("nfc_iso15693_decode: 'uid' is required")
	}
	res, err := iso15693.DecodeUID(uid)
	if err != nil {
		return "", fmt.Errorf("nfc_iso15693_decode: %w", err)
	}
	if a := strings.TrimSpace(str(p, "afi")); a != "" {
		ab, err := hex.DecodeString(strings.NewReplacer("0x", "", "0X", "", " ", "").Replace(a))
		if err != nil || len(ab) != 1 {
			return "", fmt.Errorf("nfc_iso15693_decode: 'afi' must be one hex byte")
		}
		res.AFI = iso15693.DecodeAFI(ab[0])
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
