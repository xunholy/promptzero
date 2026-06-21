// uds_dtc_status_decode.go — host-side UDS DTC status-byte decoder Spec,
// delegating to internal/uds.DecodeDTCStatus.
//
// Wrap-vs-native: native — the 8-bit DTCStatusMask is a fixed ISO 14229-1
// Annex D.2 bitfield; this cracks it into the named status flags (testFailed /
// pendingDTC / confirmedDTC / warningIndicatorRequested / …) that service 0x19
// returns with every DTC. Offline read, no hardware. Companion to uds_decode
// (the message) and obd2_dtc_decode (the trouble-code form).

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
	Register(udsDTCStatusDecodeSpec)
}

var udsDTCStatusDecodeSpec = Spec{
	Name: "uds_dtc_status_decode",
	Description: "Decode a **UDS DTC status byte** — the 8-bit DTCStatusMask that ISO 14229-1 service 0x19 " +
		"(ReadDTCInformation) returns alongside every Diagnostic Trouble Code. When you read DTCs from an ECU " +
		"the raw response is a list of [3-byte DTC][1-byte status] records; this cracks the status byte, the " +
		"part that says whether each fault is **currently failing, pending, or confirmed (stored)** and whether " +
		"the **MIL / warning indicator** is requested — the information you actually act on. Companion to " +
		"uds_decode (which names the service) and obd2_dtc_decode (which renders the P/C/B/U trouble-code " +
		"form).\n\n" +
		"The eight bits are decoded per ISO 14229-1 Annex D.2: testFailed (0x01), testFailedThisOperationCycle " +
		"(0x02), pendingDTC (0x04), confirmedDTC (0x08), testNotCompletedSinceLastClear (0x10), " +
		"testFailedSinceLastClear (0x20), testNotCompletedThisOperationCycle (0x40) and warningIndicatorRequested " +
		"(0x80). A severity summary picks the headline state (confirmed > pending > currently-failing > clean) " +
		"and notes when the warning indicator is requested. Every value 0x00-0xFF is structurally valid (all " +
		"eight bits are defined), so there is no confidently-wrong output — only a non-1-byte input is " +
		"rejected.\n\n" +
		"Input: **hex** — exactly one byte (the status mask, e.g. \"09\" or \"0x2F\"). Offline transform — reads " +
		"a byte, transmits nothing, so it is Low risk. Wrap-vs-native: native — a fixed bit decode, stdlib " +
		"only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The UDS DTC status byte — exactly 1 byte of hex (e.g. \"09\", \"2F\", \"0x88\"). Separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   udsDTCStatusDecodeHandler,
}

func udsDTCStatusDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("uds_dtc_status_decode: 'hex' is required")
	}
	res, err := uds.DecodeDTCStatusHex(raw)
	if err != nil {
		return "", fmt.Errorf("uds_dtc_status_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{"dtc_status": res}, "", "  ")
	return string(out), nil
}
