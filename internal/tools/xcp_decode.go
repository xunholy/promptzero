// xcp_decode.go — host-side ASAM XCP (Universal Measurement and Calibration
// Protocol) decoder Spec, delegating to internal/xcp.
//
// Wrap-vs-native: native — a 1-byte PID (command code master→slave, or
// response/error/event class slave→master) + raw parameters; a byte lookup +
// small sub-code tables, stdlib only. The ECU calibration/flash-bus decoder —
// surfaces the XCP operation (CONNECT / SEED&KEY / UPLOAD / DOWNLOAD / PROGRAM)
// or the slave response/error/event from a captured XCP packet. Offline read,
// no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/xcp"
)

func init() { //nolint:gochecknoinits
	Register(xcpDecodeSpec)
}

var xcpDecodeSpec = Spec{
	Name: "xcp_decode",
	Description: "Decode an **XCP (ASAM MCD-1 Universal Measurement and Calibration Protocol)** packet — the " +
		"master/slave protocol an ECU calibration tool uses to **read and write an ECU's memory**: measurement " +
		"(DAQ / STIM), calibration (download) and **flash programming** (PROGRAM). It runs over CAN " +
		"(XCP-on-CAN), Ethernet, FlexRay and others, and joins the project's automotive family (`uds_decode`, " +
		"`kwp_decode`, `obd2_*`, `isotp_decode`, `canbus_fd_decode`). XCP is a real **automotive-security " +
		"target**: it exposes direct ECU memory **UPLOAD** (read) / **DOWNLOAD** (write) and a **PROGRAM** " +
		"reflash sequence, and access protection is the optional **SEED & KEY** (GET_SEED / UNLOCK) handshake " +
		"that is frequently weak or absent — so an attacker on the bus who speaks XCP can exfiltrate " +
		"calibration/firmware, tamper with calibration values, or reflash the ECU.\n\n" +
		"A captured XCP packet identifies the **operation** in flight — a session CONNECT, a SEED & KEY auth, " +
		"a memory UPLOAD, a calibration DOWNLOAD, a PROGRAM flash sequence — or, on the slave side, the " +
		"positive response (RES), the negative response (ERR + the decoded error code), an event (EV) or a " +
		"service request (SERV). Security-relevant commands (auth, memory read/write, flash) are flagged.\n\n" +
		"No confidently-wrong output: the command-code table (0xC7-0xFF), the error-code table and the " +
		"event-code table are code-generated from scapy's authoritative XCP layer " +
		"(`scapy.contrib.automotive.xcp`). XCP is **direction-dependent** — the same PID (0xFC-0xFF) is a " +
		"command master → slave but a response/event/service class slave → master — so supply the " +
		"`direction`; without it the command interpretation is used and the ambiguity is noted. Only the PID + " +
		"(for ERR/EV) the sub-code are decoded; the command/response parameters are surfaced as **raw hex** " +
		"(their layout is command-specific and address-granularity-dependent), never reinterpreted here. No " +
		"network, no device, transmits nothing, so it is Low risk. The input is the XCP packet starting at the " +
		"PID byte. ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (automotive ECU calibration/flash-bus recon). Wrap-vs-native: " +
		"native — a byte lookup + small sub-code tables, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The XCP packet (CTO/DTO) starting at the PID byte as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."},
			"direction":{"type":"string","description":"Packet direction: 'command' (master→slave, the default) or 'response' (slave→master). The PIDs 0xFC-0xFF are ambiguous between the two."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   xcpDecodeHandler,
}

func xcpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("xcp_decode: 'hex' is required")
	}
	res, err := xcp.Decode(str(p, "hex"), str(p, "direction"))
	if err != nil {
		return "", fmt.Errorf("xcp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
