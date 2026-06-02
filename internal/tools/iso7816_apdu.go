// iso7816_apdu_decode.go — host-side ISO 7816-4 APDU decoder Spec (command
// structure + response status word), delegating to internal/iso7816.
//
// Wrap-vs-native: native — the APDU framing (CLA/INS/P1/P2 + the length cases)
// and the SW1SW2 status-word table are public, fixed ISO 7816-4 structures.
// It is the offline analysis complement to nfc_apdu (which sends an APDU to a
// card): decoding the response status word — success / PIN retries remaining /
// security status not satisfied / file not found — is core smart-card
// interaction analysis. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/iso7816"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(iso7816APDUDecodeSpec)
}

var iso7816APDUDecodeSpec = Spec{
	Name: "iso7816_apdu_decode",
	Description: "Decode an ISO 7816-4 APDU — the command/response unit of every contact and " +
		"contactless smart-card exchange (EMV, SIM/USIM, DESFire, JavaCard applets). The offline " +
		"analysis complement to nfc_apdu (which sends one): paste a captured APDU and read it back.\n\n" +
		"**response** (default): the data field followed by the SW1 SW2 status word (always the last two " +
		"bytes). The status word is the headline — 9000 success, 61XX 'more data, GET RESPONSE', 6CXX " +
		"'wrong Le, X available', 63CX 'verification failed, X PIN/key retries remaining', 6982 'security " +
		"status not satisfied', 6983 'authentication method blocked', 6A82 'file/application not found', " +
		"6D00 'INS not supported', 6E00 'CLA not supported', and the rest of the ISO 7816-4 table. The " +
		"parameterised families (61/6C/63CX) are computed, and a status word outside the table is " +
		"surfaced raw with its warning/error class rather than guessed. The DESFire wrapping-mode family " +
		"is decoded too — SW1 0x91 + SW2 = the NXP DESFire status (9100 OPERATION_OK, 91AF " +
		"ADDITIONAL_FRAME, 91AE AUTHENTICATION_ERROR, 919D PERMISSION_DENIED, 91A0 APPLICATION_NOT_FOUND, " +
		"91F0 FILE_NOT_FOUND, …), since most DESFire exchanges are ISO 7816 wrapped.\n\n" +
		"**command**: the CLA INS P1 P2 header plus the ISO 7816-4 length case (1 / 2S / 3S / 4S and the " +
		"extended 2E / 3E / 4E), with Lc, the data field, and Le. The INS is named for an interindustry " +
		"CLA (SELECT, READ BINARY/RECORD, GET RESPONSE/DATA, VERIFY, …). For CLA 0x90 — the DESFire ISO " +
		"wrapper — the INS is named as the DESFire command (SELECT_APPLICATION, AUTHENTICATE_AES, " +
		"READ_DATA, GET_VERSION, CHANGE_KEY, …); any other proprietary CLA (high bit set) withholds the " +
		"INS name since it is application-specific. Inconsistent length encodings are " +
		"rejected, not mis-parsed.\n\n" +
		"Offline transform — reads hex, transmits nothing, so it is Low risk. Accepts ':' / '-' / '_' / " +
		"whitespace separators. Wrap-vs-native: native — fixed ISO 7816-4 framing + status-word table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"APDU bytes as hex. Separators tolerated."},
			"kind":{"type":"string","description":"\"response\" (default — decodes the trailing SW1 SW2) or \"command\" (decodes CLA/INS/P1/P2 + length case).","enum":["response","command"]}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   iso7816APDUDecodeHandler,
}

func iso7816APDUDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(str(p, "hex")))
	clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
	if clean == "" {
		return "", fmt.Errorf("iso7816_apdu_decode: 'hex' is required")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("iso7816_apdu_decode: invalid hex: %w", err)
	}

	kind := strings.ToLower(strings.TrimSpace(str(p, "kind")))
	if kind == "" {
		kind = "response"
	}
	switch kind {
	case "response":
		res, err := iso7816.DecodeResponseAPDU(b)
		if err != nil {
			return "", fmt.Errorf("iso7816_apdu_decode: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{"kind": "response", "response": res}, "", "  ")
		return string(out), nil
	case "command":
		res, err := iso7816.DecodeCommandAPDU(b)
		if err != nil {
			return "", fmt.Errorf("iso7816_apdu_decode: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{"kind": "command", "command": res}, "", "  ")
		return string(out), nil
	default:
		return "", fmt.Errorf("iso7816_apdu_decode: kind %q must be \"response\" or \"command\"", kind)
	}
}
