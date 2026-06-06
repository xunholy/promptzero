// maccontrol_decode.go — host-side IEEE 802.3 MAC Control (flow-control /
// EPON MPCP) decoder Spec, delegating to internal/maccontrol.
//
// Wrap-vs-native: native — a 2-byte opcode + a small fixed opcode body;
// byte-field reads + an opcode switch, stdlib only. Adds the L2-DoS leg
// (802.3x PAUSE flood, 802.1Qbb PFC storm) to the LAN-attack family
// (dtp/vtp/vqp/gxrp/stp). Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/maccontrol"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(macControlDecodeSpec)
}

var macControlDecodeSpec = Spec{
	Name: "maccontrol_decode",
	Description: "Decode **IEEE 802.3 MAC Control** frames (EtherType 0x8808) — the Ethernet flow-control and " +
		"EPON access-control sublayer. Its two flow-control opcodes are recognised **L2 denial-of-service** " +
		"surfaces, so this joins the project's LAN-attack decoder family (`dtp`, `vtp`, `vqp`, `gxrp`, " +
		"`stp`):\n\n" +
		"• **PAUSE** (802.3x, opcode 0x0001) — a frame to 01:80:c2:00:00:01 halts the upstream port for " +
		"pause_time × 512 bit-times; a **flood of PAUSE frames with the maximum quanta (0xFFFF) is the " +
		"classic switch-port flow-control DoS** (it can stall the port indefinitely).\n" +
		"• **PFC / Priority-based Flow Control** (802.1Qbb, opcode 0x0101) — the per-priority version used in " +
		"lossless datacenter fabrics (RoCE / FCoE); a **PFC storm causes head-of-line blocking and can " +
		"collapse a converged fabric**.\n\n" +
		"The remaining opcodes are **EPON MPCP** (Multi-Point Control Protocol): GATE / REPORT / " +
		"REGISTER_REQ / REGISTER / REGISTER_ACK — the time-slot grant + discovery handshake of an Ethernet " +
		"PON. Decodes the PAUSE quanta, the PFC per-class enable + pause times, and the MPCP timestamp / " +
		"flags / port / grant fields.\n\n" +
		"No confidently-wrong output: MAC Control frames are padded to the 60-byte minimum Ethernet payload, " +
		"so the decoder reads only the defined opcode fields and **reports any non-zero trailing bytes** " +
		"rather than guessing; an unknown opcode is named by number with its body surfaced as raw hex. No " +
		"network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace separators " +
		"and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (L2 flow-control DoS — 802.3x PAUSE / 802.1Qbb PFC — recon). " +
		"Wrap-vs-native: native — a byte-field read + an opcode switch, stdlib only, no new go.mod dep. " +
		"Verified field-for-field against scapy's MACControl layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The MAC Control frame body (the EtherType-0x8808 payload, after the Ethernet header) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   macControlDecodeHandler,
}

func macControlDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("maccontrol_decode: 'hex' is required")
	}
	res, err := maccontrol.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("maccontrol_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
