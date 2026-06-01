// kwp_decode.go — host-side KWP2000 (ISO 14230) diagnostic-message decoder
// Spec, delegating to the internal/kwp package.
//
// Wrap-vs-native: native — KWP2000 shares UDS's +0x40 / 0x7F framing but
// has a DISTINCT service-ID table (local-identifier + communication-control
// services that UDS lacks), so uds_decode would mislabel KWP traffic. This
// is the correct ISO 14230 table. Companion to uds_decode / isotp_decode /
// obd2_*; the j1850 decoder lists KWP2000 as out of scope.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/kwp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(kwpDecodeSpec)
}

var kwpDecodeSpec = Spec{
	Name: "kwp_decode",
	Description: "Decode a KWP2000 (Keyword Protocol 2000, ISO 14230-3) diagnostic message — UDS's " +
		"predecessor, still spoken by many pre-CAN / early-CAN ECUs and ELM327 adapters. KWP shares " +
		"UDS's application framing (positive response = request SID + 0x40; negative response = " +
		"0x7F <SID> <NRC>) but has a DISTINCT service-ID table, so decoding KWP traffic with uds_decode " +
		"mislabels it — use this for KWP buses.\n\n" +
		"Classifies the message and names everything actionable:\n" +
		" - **direction**: request / positive_response / negative_response.\n" +
		" - **service**: the named KWP service, including the KWP-specific ones UDS lacks — " +
		"ReadDataByLocalIdentifier (0x21), InputOutputControlByLocalIdentifier (0x30), " +
		"StartRoutineByLocalIdentifier (0x31), WriteDataByLocalIdentifier (0x3B), StartCommunication " +
		"(0x81), StopCommunication (0x82).\n" +
		" - **nrc / nrc_name** for a negative response — securityAccessDenied, invalidKey, " +
		"requestOutOfRange, requestCorrectlyReceived-ResponsePending (0x78), etc.\n" +
		" - **param_byte + param_label** — the byte after the SID, labelled by service " +
		"(local_identifier, diagnostic_session_type, access_mode, …); its value enum is not guessed " +
		"(KWP identifiers are largely manufacturer-defined), so the raw byte + remaining payload are " +
		"surfaced for interpretation.\n\n" +
		"Input is the reassembled KWP application PDU as hex (no ISO-TP framing) — e.g. `7F 21 31` = " +
		"ReadDataByLocalIdentifier → requestOutOfRange. Only ISO-14230-assigned service IDs / NRCs are " +
		"named; unknown values are surfaced raw, never guessed. ':' / '-' / '_' / whitespace and a 0x " +
		"prefix tolerated. Pure offline parser — no bus or adapter. Wrap-vs-native: native — public " +
		"ISO 14230 tables, a static lookup, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Reassembled KWP2000 application PDU as hex (no ISO-TP framing), e.g. '7F 21 31' or '21 01'. Separators / 0x tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   kwpDecodeHandler,
}

func kwpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("kwp_decode: 'hex' is required")
	}
	res, err := kwp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("kwp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
