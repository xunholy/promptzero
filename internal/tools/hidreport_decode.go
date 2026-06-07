// hidreport_decode.go — host-side USB HID Report Descriptor decoder Spec,
// delegating to internal/hidreport.
//
// Wrap-vs-native: native — a flat item sequence (prefix byte = bTag/bType/bSize
// + LE data); a byte walk + bit-field reads + tag-name tables, stdlib only.
// The HID device-identity decoder — surfaces the declared usage (keyboard /
// mouse / …), collections and report shape, and flags the BadUSB keyboard
// tell. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/hidreport"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(hidReportDecodeSpec)
}

var hidReportDecodeSpec = Spec{
	Name: "usb_hid_report_descriptor_decode",
	Description: "Decode a **USB HID Report Descriptor** — the item-based structure (USB HID 1.11 §6.2.2) a HID " +
		"device returns to declare **what it is**: its usage (keyboard / mouse / gamepad / vendor-defined), " +
		"its collections, and the size/shape of its input, output and feature reports. It is the **deepest " +
		"layer of USB device identity** and the definitive **BadUSB tell**: a device whose report descriptor " +
		"declares a **Generic Desktop / Keyboard** usage with a standard input report is a keyboard — so a " +
		"flash drive or 'charging cable' whose HID report descriptor declares a keyboard is a keystroke " +
		"injector (Rubber Ducky / Bash Bunny / O.MG cable). It completes the project's USB analysis stack: " +
		"`usb_descriptor_decode` (the device / interface / endpoint identity), this (the HID usage the device " +
		"claims), and `usbhid` (the report data the device then sends).\n\n" +
		"Decodes each item — **Main** (Input / Output / Feature with the decoded data-flag bits, Collection " +
		"with its type, End Collection), **Global** (Usage Page with its name, Logical/Physical Min/Max, " +
		"Report Size / ID / Count, Push / Pop), **Local** (Usage with its name, Usage Min/Max, …) and long " +
		"items — and summarises the **declared usages** (e.g. 'Generic Desktop / Keyboard').\n\n" +
		"No confidently-wrong output: the item encoding, the Main / Global / Local tag tables, the Collection " +
		"types and the Input/Output/Feature data-flag bits follow the USB HID 1.11 specification — " +
		"deterministic and byte-checkable against the canonical boot-keyboard report descriptor. Usage-page " +
		"and usage **values** are a vast, vendor-extensible registry, so only the well-known usage pages and " +
		"the Generic-Desktop usages are named; any other usage page / usage is **surfaced by value** (never " +
		"guessed), and a truncated item stops the walk. No network, no device, transmits nothing, so it is " +
		"Low risk. The input is the HID report descriptor (the bytes of the 0x22 descriptor). ':' / '-' / '_' " +
		"/ whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (USB HID device-identity / BadUSB descriptor analysis). " +
		"Wrap-vs-native: native — a byte walk + bit-field reads + tag-name tables, stdlib only, no new go.mod " +
		"dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The USB HID report descriptor (the bytes of the 0x22 descriptor) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   hidReportDecodeHandler,
}

func hidReportDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("usb_hid_report_descriptor_decode: 'hex' is required")
	}
	res, err := hidreport.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("usb_hid_report_descriptor_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
