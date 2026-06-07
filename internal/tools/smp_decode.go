// smp_decode.go — host-side Bluetooth LE SMP (Security Manager Protocol /
// pairing) decoder Spec, delegating to internal/smp.
//
// Wrap-vs-native: native — a 1-byte SMP code + a fixed body (the Pairing
// Request/Response is six bytes of bit-fields); a byte read + bit-field decode
// + small tables, stdlib only. The BLE-pairing-security decoder completing the
// BT-stack chain — surfaces the pairing posture (MITM / Secure Connections /
// Just Works), IO capability, key sizes and key distribution. Offline read,
// no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/smp"
)

func init() { //nolint:gochecknoinits
	Register(smpDecodeSpec)
}

var smpDecodeSpec = Spec{
	Name: "bt_smp_decode",
	Description: "Decode a **Bluetooth LE SMP (Security Manager Protocol)** PDU — the **pairing**-and-key-" +
		"distribution layer carried on L2CAP CID 0x0006. SMP is where BLE security is established (or fails to " +
		"be): the **Pairing Request / Response** exchange negotiates the pairing **method** and the keys to " +
		"distribute, and the choice of method determines whether the link is protected against a " +
		"man-in-the-middle. A captured SMP exchange is the recon headline for **BLE-pairing security**: it " +
		"reveals each side's **IO capability**, whether **MITM protection** is requested, whether **LE Secure " +
		"Connections** (vs the weaker Legacy pairing) is used, the **max encryption key size**, and which " +
		"long-term / identity / signing keys are distributed — so it answers \"is this pairing **Just Works** " +
		"(no MITM protection, trivially interceptable) or authenticated?\". It completes the project's " +
		"Bluetooth-stack decode chain (`bt_hci_decode` → `bt_l2cap_decode` → this).\n\n" +
		"Decodes the SMP code, and for the Pairing Request/Response/Security Request the IO capability, OOB " +
		"flag, AuthReq (bonding / MITM / Secure Connections / keypress), max key size and the initiator / " +
		"responder key-distribution masks — with a derived **security-posture** note; the Pairing Failed " +
		"reason; and the Identity Address. Key material (LTK / IRK / CSRK / Confirm / Random / public key) is " +
		"surfaced as raw hex.\n\n" +
		"No confidently-wrong output: the SMP codes, IO-capability values, AuthReq bit-fields, " +
		"key-distribution flags and Pairing-Failed reasons follow the Bluetooth Core specification (Vol 3 Part " +
		"H). The posture note is derived only from the unambiguous AuthReq bits (MITM / Secure Connections) on " +
		"the decoded PDU — the exact Legacy method (Just Works vs Passkey vs OOB) also depends on **both** " +
		"sides' IO capabilities, so the note states the single-PDU posture rather than over-claiming the " +
		"method. No network, no device, transmits nothing, so it is Low risk. The input is the SMP PDU (the " +
		"L2CAP CID-0x0006 payload). ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (BLE-pairing security recon; completes bt_hci_decode → " +
		"bt_l2cap_decode → SMP). Wrap-vs-native: native — a byte read + bit-field decode + small tables, " +
		"stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The Bluetooth LE SMP PDU (the L2CAP CID-0x0006 payload, starting at the SMP code byte) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   smpDecodeHandler,
}

func smpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("bt_smp_decode: 'hex' is required")
	}
	res, err := smp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("bt_smp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
