// hci_decode.go — host-side Bluetooth HCI (Host Controller Interface) packet
// decoder Spec, delegating to internal/hci.
//
// Wrap-vs-native: native — a 1-byte H4 transport indicator + a small fixed
// header (command opcode OGF/OCF + length, event code + length, ACL handle +
// length); a byte read + bit-field splits + opcode/event tables, stdlib only.
// The Bluetooth-stack transport decoder — surfaces the operation (command /
// event / LE Meta sub-event / ACL) from a btsnoop / hcidump capture. Offline
// read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/hci"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(hciDecodeSpec)
}

var hciDecodeSpec = Spec{
	Name: "bt_hci_decode",
	Description: "Decode a **Bluetooth HCI (Host Controller Interface)** packet — the transport between a Bluetooth " +
		"host stack and its controller, and exactly what a **btsnoop / hcidump** capture contains. Every " +
		"Bluetooth and BLE operation passes through HCI, so decoding an HCI capture is the foundational view of " +
		"what a host (or an attacker's host) is doing: scanning, advertising, connecting, reading a remote's " +
		"features, setting advertising data. It is the transport layer beneath the project's BLE decoders " +
		"(`internal/ble`, `btuuid`, the GATT / advertising tooling), and the offline-decode companion to the " +
		"live `bt_hci_info`.\n\n" +
		"A captured HCI packet identifies the **operation** — a **command** (with its OGF group + opcode, e.g. " +
		"LE Set Scan Enable / LE Create Connection / LE Set Advertising Data / Reset), an **event** (Command " +
		"Complete / Command Status — both naming the embedded command opcode — Disconnection Complete, or an " +
		"**LE Meta** sub-event such as an Advertising Report or Connection Complete), or an **ACL** data " +
		"fragment (with its connection handle + PB/BC flags).\n\n" +
		"No confidently-wrong output: the H4 transport indicators, the OGF groups, the well-known command " +
		"opcodes, the event codes and the LE-Meta sub-event codes follow the Bluetooth Core specification " +
		"(scapy's HCI type field carries non-standard extras, so the spec is the authority). The well-known " +
		"opcodes / events are named; an opcode outside the named set is reported by its **OGF group + OCF** " +
		"(never guessed), and an unknown event by code; the command / event **parameters are surfaced as raw " +
		"hex** (per-command, the table is vast) except the unambiguous Command Complete/Status embedded opcode " +
		"and the LE-Meta sub-event code. No network, no device, transmits nothing, so it is Low risk. The " +
		"input is the HCI (H4) packet — the transport indicator byte then the packet. ':' / '-' / '_' / " +
		"whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Bluetooth-stack / btsnoop HCI recon). Wrap-vs-native: native — " +
		"a byte read + bit-field splits + opcode/event tables, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The Bluetooth HCI (H4) packet — the transport indicator byte (01 Command / 02 ACL / 04 Event / …) then the packet — as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   hciDecodeHandler,
}

func hciDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("bt_hci_decode: 'hex' is required")
	}
	res, err := hci.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("bt_hci_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
