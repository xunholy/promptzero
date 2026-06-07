// usbpd_decode.go — host-side USB Power Delivery (USB-PD) decoder Spec,
// delegating to internal/usbpd.
//
// Wrap-vs-native: native — a 16-bit LE header + 32-bit LE Data Objects; a
// bit-field read + a per-message-type walk, stdlib only. The USB-C power-
// negotiation decoder — surfaces the message type, roles, and the offered
// power (Source/Sink Capabilities PDOs) from a captured PD exchange. Offline
// read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/usbpd"
)

func init() { //nolint:gochecknoinits
	Register(usbPDDecodeSpec)
}

var usbPDDecodeSpec = Spec{
	Name: "usb_pd_decode",
	Description: "Decode a **USB Power Delivery (USB-PD)** message — the protocol spoken over the USB-C CC line to " +
		"negotiate power (and to tunnel alternate modes and vendor-defined messages). USB-PD is an emerging " +
		"**hardware-attack surface**: a malicious charger or a PD-capable cable can advertise bogus power " +
		"capabilities, drive a sink to request out-of-spec voltage, or carry vendor-defined messages that " +
		"trigger device-specific behaviour — so a captured PD exchange (from a CC-line analyzer) is real " +
		"recon. A USB-PD message identifies the **negotiation step** — a **Source/Sink Capabilities** " +
		"advertisement (and the offered voltages/currents), a Request, an Accept/Reject/PS_RDY, a role swap, a " +
		"Vendor-Defined Message — the headline for charger / cable analysis. It joins the project's USB " +
		"analysis stack (`usb_descriptor_decode`, `usb_hid_report_descriptor_decode`, `usbhid`).\n\n" +
		"Decodes the 16-bit header (message type — with the control-vs-data dispatch driven by the data-object " +
		"count, spec revision, power/data roles, message id, extended flag) and, for **Source/Sink " +
		"Capabilities**, each Power Data Object: **Fixed** (voltage + max current + the role flags), " +
		"**Variable** and **Battery** (voltage range + current).\n\n" +
		"No confidently-wrong output: the header bit layout, the control- and data-message type tables, and " +
		"the Fixed / Variable / Battery PDO layouts follow the USB Power Delivery specification — " +
		"deterministic and byte-checkable against spec-built PDOs. Only the standardised fields are decoded; " +
		"an **Augmented PDO (PPS / AVS)** is surfaced by type with its 32-bit value raw, and the **Request " +
		"RDO**, BIST, Vendor-Defined and other data messages' objects are surfaced as **raw hex** (their " +
		"layouts are position-dependent and would be confidently-wrong without the prior Capabilities " +
		"context). No network, no device, transmits nothing, so it is Low risk. The input is the raw on-wire " +
		"PD message bytes (little-endian). ':' / '-' / '_' / whitespace separators and a '0x' prefix " +
		"tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (USB-C power-delivery / malicious-charger recon). " +
		"Wrap-vs-native: native — a bit-field read + a per-message-type walk, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The raw on-wire USB-PD message bytes (16-bit header + 32-bit data objects, little-endian) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   usbPDDecodeHandler,
}

func usbPDDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("usb_pd_decode: 'hex' is required")
	}
	res, err := usbpd.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("usb_pd_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
