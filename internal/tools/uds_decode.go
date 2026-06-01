// uds_decode.go — host-side UDS (ISO 14229) diagnostic-message decoder
// Spec, delegating to the internal/uds package.
//
// Wrap-vs-native: native — the UDS service-ID table, the +0x40 positive-
// response convention, the 0x7F negative-response framing, and the NRC
// table are a public ISO standard (ISO 14229-1). The j1850 decoder covers
// only legacy OBD-II modes 1-9 and notes UDS as out of scope; this fills
// that gap. Complements obd2_pid_decode / obd2_dtc_decode and the canbus_*
// transport tools.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/uds"
)

func init() { //nolint:gochecknoinits
	Register(udsDecodeSpec)
}

var udsDecodeSpec = Spec{
	Name: "uds_decode",
	Description: "Decode a UDS (Unified Diagnostic Services, ISO 14229-1) message — the protocol " +
		"behind modern ECU diagnostics and attacks (session control, security access, routine " +
		"control, memory read/write, firmware transfer). Classifies the message and names everything " +
		"actionable:\n\n" +
		" - **direction**: request, positive_response (response SID = request SID + 0x40), or " +
		"negative_response (0x7F <SID> <NRC>).\n" +
		" - **service**: the named UDS service (DiagnosticSessionControl, SecurityAccess, " +
		"ReadDataByIdentifier, RoutineControl, RequestDownload, …).\n" +
		" - **nrc / nrc_name** for a negative response — the decisive field when probing an ECU: " +
		"securityAccessDenied, invalidKey, requestOutOfRange, conditionsNotCorrect, " +
		"requestCorrectlyReceived-ResponsePending (0x78), serviceNotSupportedInActiveSession, etc.\n" +
		" - **sub_function** + suppress_positive_response bit (e.g. session type, reset type, routine " +
		"control type, ControlDTCSetting on/off), with the common enums named.\n" +
		" - **data_identifier** for Read/WriteDataByIdentifier — the 16-bit DID, with the ISO-standard " +
		"ones named (0xF190 VIN, 0xF18C ECU serial, …).\n\n" +
		"Input is the reassembled UDS application PDU (without ISO-TP framing) as hex — e.g. " +
		"`7F 27 35` = SecurityAccess → invalidKey, or `22 F1 90` = ReadDataByIdentifier(VIN). Only " +
		"ISO-14229-assigned service IDs / NRCs / sub-function enums are named; unknown values and " +
		"manufacturer-specific DIDs are surfaced raw, never guessed. ':' / '-' / '_' / whitespace and " +
		"a 0x prefix tolerated. Pure offline parser — no bus or adapter. Wrap-vs-native: native — " +
		"public ISO 14229 tables, a static lookup, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Reassembled UDS application PDU as hex (no ISO-TP framing), e.g. '7F 27 35' or '22 F1 90'. Separators / 0x tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   udsDecodeHandler,
}

func udsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("uds_decode: 'hex' is required")
	}
	res, err := uds.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("uds_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
