// obd2_pid.go — host-side OBD-II / SAE J1979 Mode-01 PID value decoder
// Spec, delegating to the internal/obd2 package.
//
// Wrap-vs-native: native — the J1979 Mode-01 PID formulas are public,
// exact, and transport-independent. The j1850 decoder names the PID but
// stops at the raw payload bytes; this computes the engineering value those
// bytes encode (and applies equally to CAN-bus OBD-II responses).

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
	Register(obd2PIDDecodeSpec)
}

var obd2PIDDecodeSpec = Spec{
	Name: "obd2_pid_decode",
	Description: "Decode an OBD-II / SAE J1979 Mode-01 (\"show current data\") response into its " +
		"engineering value — RPM, vehicle speed, coolant / intake / oil / catalyst temperature, MAF " +
		"air-flow, throttle position, fuel trim, control-module voltage, evaporative-system and " +
		"fuel-rail pressure, ethanol fuel percentage, fuel-injection timing, the time the engine has " +
		"run with the MIL (check-engine lamp) on or since the codes were cleared, and the rest of the " +
		"standard live-data PIDs — via the public per-PID formulas. The j1850 / canbus decoders name the PID and surface " +
		"the raw measurement bytes; this computes the value those bytes encode, and works for any " +
		"transport (CAN / ISO 15765, J1850 VPW/PWM, ISO 9141) since you supply the already-extracted " +
		"Mode-01 payload.\n\n" +
		"Input is the response payload: the service byte (0x41 for a Mode-01 response) + the PID + the " +
		"measurement bytes — e.g. `41 0C 1A F8` decodes to Engine RPM = 1726. A request payload " +
		"(0x01 + PID) is also accepted and just names the PID. The result carries the PID name, the " +
		"computed value + unit, and the formula used (e.g. ((A*256)+B)/4) so the derivation is " +
		"auditable.\n\n" +
		"Only PIDs with a formula in the J1979 table are given a value; an unknown / manufacturer-" +
		"specific PID, or a known PID with too few bytes, is surfaced with its raw hex and a note — " +
		"never a guessed number. ':' / '-' / '_' / whitespace separators and a 0x prefix tolerated. " +
		"Pure offline transform — no vehicle or adapter. Companion to canbus_fd_decode / " +
		"automotive_j1850_decode. Wrap-vs-native: native — public J1979 formulas, a static table, no " +
		"hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"OBD-II Mode-01 response payload: service byte (0x41) + PID + measurement bytes, e.g. '41 0C 1A F8'. A request (0x01 + PID) is also accepted. Separators / 0x tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   obd2PIDDecodeHandler,
}

func obd2PIDDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("obd2_pid_decode: 'hex' is required")
	}
	res, err := obd2.DecodeResponse(raw)
	if err != nil {
		return "", fmt.Errorf("obd2_pid_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
