// obd2_dtc.go — host-side OBD-II Diagnostic Trouble Code decoder Spec,
// delegating to the internal/obd2 package.
//
// Wrap-vs-native: native — the SAE J2012 DTC encoding (2 bytes → P/C/B/U +
// 4 digits) is a public, deterministic bit-unpack. The j1850 decoder names
// the Mode-03/07/0A service but never unpacks the trouble-code values; this
// does. Companion to obd2_pid_decode (live data) — together they cover both
// halves of OBD-II diagnostics.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/obd2"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(obd2DTCDecodeSpec)
}

var obd2DTCDecodeSpec = Spec{
	Name: "obd2_dtc_decode",
	Description: "Decode an OBD-II Diagnostic Trouble Code response (Mode 03 stored / Mode 07 pending " +
		"/ Mode 0A permanent) into the canonical SAE J2012 codes — P0143, P0420, U0123, etc. Each " +
		"trouble code is 2 bytes: the top two bits of the first byte select the category letter " +
		"(P powertrain / C chassis / B body / U network), the next two bits are the first digit, the " +
		"first byte's low nibble is the second digit, and the second byte's nibbles are the third and " +
		"fourth digits.\n\n" +
		"The j1850 / canbus decoders name the Mode-03/07/0A service but leave the trouble-code values " +
		"as raw bytes; this unpacks them. Input is the response payload — the service byte (0x43 / " +
		"0x47 / 0x4A) followed by the DTC bytes, or the bare 2-byte-per-code stream. All-zero pairs " +
		"(0x0000) are empty slots and are skipped; an odd trailing byte is noted and ignored. Each " +
		"code is also flagged generic (SAE/ISO-controlled, first digit 0) vs manufacturer-specific " +
		"(first digit 1).\n\n" +
		"The code itself is fully deterministic; human fault DESCRIPTIONS are deliberately not " +
		"emitted — only the generic SAE set is standardised and the manufacturer-specific ranges " +
		"vary, so a guessed description would risk the confidently-wrong output this project avoids. " +
		"':' / '-' / '_' / whitespace and a 0x prefix tolerated. Pure offline transform — no vehicle " +
		"or adapter. Companion to obd2_pid_decode. Wrap-vs-native: native — public J2012 bit-unpack, " +
		"no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"OBD-II DTC response: service byte (0x43/0x47/0x4A) + DTC bytes, or the bare 2-byte-per-code stream, e.g. '43 0143 0420'. Separators / 0x tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   obd2DTCDecodeHandler,
}

func obd2DTCDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("obd2_dtc_decode: 'hex' is required")
	}
	res, err := obd2.DecodeDTCResponse(raw)
	if err != nil {
		return "", fmt.Errorf("obd2_dtc_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
