// l2cap_decode.go — host-side Bluetooth L2CAP decoder Spec, delegating to
// internal/l2cap.
//
// Wrap-vs-native: native — a 2-byte LE length + 2-byte CID + per-channel
// payload; a byte read + a CID dispatch + opcode tables, stdlib only. The
// Bluetooth channel-mux decoder bridging bt_hci_decode (below) and the GATT
// tooling (above) — surfaces the CID's sub-protocol (signaling / ATT-GATT /
// SMP-pairing) and the specific operation. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/l2cap"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(l2capDecodeSpec)
}

var l2capDecodeSpec = Spec{
	Name: "bt_l2cap_decode",
	Description: "Decode a **Bluetooth L2CAP** (Logical Link Control and Adaptation Protocol) frame — the " +
		"channel-multiplexing layer that rides inside HCI ACL data and carries the higher Bluetooth " +
		"protocols. It is the **bridge** between `bt_hci_decode` (the HCI transport below) and the project's " +
		"BLE / GATT tooling (above): an L2CAP frame's **Channel ID (CID)** selects the protocol — the " +
		"**signaling** channel (connection / configuration / the LE connection-parameter-update and " +
		"credit-based-connection requests), **ATT** (the Attribute Protocol behind GATT), **SMP** (the " +
		"Security Manager — BLE pairing), or a dynamic channel. Decoding an L2CAP frame from a btsnoop / " +
		"HCI-ACL capture reveals which Bluetooth sub-protocol is in flight and, for the signaling / ATT / SMP " +
		"channels, the specific operation — a GATT read / write / notification, a pairing request, a " +
		"connection-parameter update — the recon headline for Bluetooth-stack analysis.\n\n" +
		"No confidently-wrong output: the basic-header layout, the fixed CIDs, the L2CAP signaling codes, the " +
		"ATT opcodes and the SMP codes follow the Bluetooth Core specification. The channel is dispatched by " +
		"CID; the signaling code / ATT opcode / SMP code is named from the spec tables; everything past the " +
		"named opcode (the per-operation parameters) is surfaced as **raw hex** (the parameter layouts are " +
		"operation-specific). An unknown signaling code / ATT opcode / SMP code is reported by value, and a " +
		"frame shorter than the 4-byte basic header is reported, not guessed. No network, no device, transmits " +
		"nothing, so it is Low risk. The input is the L2CAP frame (the content of an HCI ACL data packet). " +
		"':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Bluetooth-stack L2CAP recon; bridges bt_hci_decode and the GATT " +
		"tooling). Wrap-vs-native: native — a byte read + a CID dispatch + opcode tables, stdlib only, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The Bluetooth L2CAP frame (the L2CAP basic header + payload, i.e. the content of an HCI ACL data packet) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   l2capDecodeHandler,
}

func l2capDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("bt_l2cap_decode: 'hex' is required")
	}
	res, err := l2cap.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("bt_l2cap_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
