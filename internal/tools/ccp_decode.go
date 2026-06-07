// ccp_decode.go — host-side CCP (CAN Calibration Protocol) decoder Spec,
// delegating to internal/ccp.
//
// Wrap-vs-native: native — an 8-byte CAN payload: a CRO (command byte +
// counter + params) or a DTO (packet id → CRM / event / DAQ data); a byte
// lookup + a small return-code table, stdlib only. The CAN-native ECU
// calibration/flash decoder (XCP predecessor) — surfaces the operation
// (CONNECT / SEED&KEY / UPLOAD / DNLOAD / PROGRAM) or the slave return code.
// Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ccp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ccpDecodeSpec)
}

var ccpDecodeSpec = Spec{
	Name: "ccp_decode",
	Description: "Decode a **CCP (CAN Calibration Protocol, ASAM)** frame — the **CAN-native predecessor of XCP** " +
		"that an ECU calibration tool uses to read and write an ECU's memory: connect to a station, DAQ " +
		"measurement, **download** calibration data, and **flash** (PROGRAM). It is still in production ECUs " +
		"(especially older GM / European powertrain modules) and is the CAN-bus sibling of `xcp_decode`, " +
		"joining the project's automotive family (`uds_decode`, `kwp_decode`, `obd2_*`, `doip_decode`, " +
		"`isotp_decode`, `canbus_fd_decode`). CCP is a real **automotive-security target**: it exposes direct " +
		"ECU memory **UPLOAD** (read) / **DNLOAD** (write) and a **PROGRAM / CLEAR_MEMORY** flash sequence, " +
		"with the only access control being the optional **GET_SEED / UNLOCK** seed-and-key handshake — so an " +
		"attacker on the CAN bus who speaks CCP can exfiltrate calibration/firmware, tamper with calibration, " +
		"or reflash the ECU.\n\n" +
		"A captured CCP frame identifies the **operation** — a session CONNECT (and the target station " +
		"address), a SEED & KEY auth, a memory UPLOAD, a calibration DNLOAD, a PROGRAM flash — or, on the " +
		"slave side, the Command Return Message (with its return code), an event, or DAQ measurement data. " +
		"Security-relevant commands (auth / memory read / memory write / flash) are flagged.\n\n" +
		"No confidently-wrong output: the command table and the return-code table are code-generated from " +
		"scapy's authoritative CCP layer (`scapy.contrib.automotive.ccp`). Like XCP, CCP is " +
		"**direction-dependent** — a command byte (master → slave) and a DTO packet id (slave → master) share " +
		"the same byte space — so supply the `direction`; without it the command interpretation is used and " +
		"the ambiguity is noted. Only the command byte / packet id, the counter, the return code and (for " +
		"CONNECT) the little-endian station address are decoded; the remaining parameters are surfaced as " +
		"**raw hex** (command-specific, address-granularity-dependent), never reinterpreted here. No network, " +
		"no device, transmits nothing, so it is Low risk. The input is the CCP CAN payload. ':' / '-' / '_' / " +
		"whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (automotive ECU calibration/flash-bus recon; the CAN-native XCP " +
		"sibling). Wrap-vs-native: native — a byte lookup + a small return-code table, stdlib only, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The CCP frame (the CAN payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."},
			"direction":{"type":"string","description":"Frame direction: 'command' (CRO, master→slave, the default) or 'response' (DTO, slave→master). The command byte and the DTO packet id share the same byte space."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ccpDecodeHandler,
}

func ccpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("ccp_decode: 'hex' is required")
	}
	res, err := ccp.Decode(str(p, "hex"), str(p, "direction"))
	if err != nil {
		return "", fmt.Errorf("ccp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
