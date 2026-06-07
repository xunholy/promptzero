// att_decode.go — host-side Bluetooth ATT (Attribute Protocol / GATT)
// decoder Spec, delegating to internal/att.
//
// Wrap-vs-native: native — a 1-byte opcode + per-opcode fixed fields (LE
// handles, MTU, 2/16-byte UUIDs, value blobs); a byte read + an opcode
// dispatch, stdlib only. The GATT-traffic decoder completing the BT-stack
// chain — surfaces the attribute handles read/written/notified and the
// service discovery. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/att"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(attDecodeSpec)
}

var attDecodeSpec = Spec{
	Name: "bt_att_decode",
	Description: "Decode a **Bluetooth ATT (Attribute Protocol)** PDU — the request/response protocol behind " +
		"**GATT**, carried on L2CAP CID 0x0004. ATT is the **application layer of BLE**: it is how a client " +
		"reads and writes a server's attributes (characteristics), discovers its services, and receives " +
		"notifications. Decoding ATT traffic from a btsnoop / HCI-ACL capture is the recon headline for what a " +
		"BLE app actually does on a device: which attribute **handles** it reads and writes, the **service / " +
		"characteristic discovery** (Read By Group Type / Read By Type / Find Information) that maps the GATT " +
		"database, and the **notifications / indications** a device pushes. It is the final layer of the " +
		"project's Bluetooth-stack decode chain (`bt_hci_decode` → `bt_l2cap_decode` → this) and pairs with " +
		"the UUID naming in `bluetooth_gatt_uuid_lookup`.\n\n" +
		"Field-decodes the common opcodes: Error Response (the failing request opcode + handle + error code), " +
		"Exchange MTU, Find Information, Read By Type / Read By Group Type requests (start/end handle + UUID — " +
		"16-bit or 128-bit), Read / Read Blob, Write Request / Command / Signed Write (handle + value), and " +
		"Handle Value Notification / Indication (handle + value).\n\n" +
		"No confidently-wrong output: the ATT opcodes, the error codes and the per-opcode field layouts follow " +
		"the Bluetooth Core specification (Vol 3 Part F). The attribute **value** blobs are surfaced as **raw " +
		"hex** (their contents are characteristic-specific), and the length-prefixed attribute-data lists " +
		"(discovery responses) are surfaced raw with their per-record length noted; an opcode outside the " +
		"decoded set is named (or reported by value) with its body raw. No network, no device, transmits " +
		"nothing, so it is Low risk. The input is the ATT PDU (the L2CAP CID-0x0004 payload). ':' / '-' / '_' " +
		"/ whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (BLE GATT-traffic recon; completes bt_hci_decode → " +
		"bt_l2cap_decode → ATT). Wrap-vs-native: native — a byte read + an opcode dispatch + handle/UUID " +
		"reads, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The Bluetooth ATT PDU (the L2CAP CID-0x0004 payload, starting at the ATT opcode) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   attDecodeHandler,
}

func attDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("bt_att_decode: 'hex' is required")
	}
	res, err := att.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("bt_att_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
