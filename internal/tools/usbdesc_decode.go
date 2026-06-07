// usbdesc_decode.go — host-side USB descriptor decoder Spec, delegating to
// internal/usbdesc.
//
// Wrap-vs-native: native — fixed, length-prefixed little-endian USB-spec
// descriptor structures walked by bLength; a byte-slice walk + field reads +
// a class-code lookup, stdlib only. The USB device-fingerprinting / BadUSB
// decoder — surfaces VID:PID, device/interface class, endpoints, and flags
// the HID-boot-keyboard (rubber-ducky) and composite-device patterns.
// Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/usbdesc"
)

func init() { //nolint:gochecknoinits
	Register(usbDescDecodeSpec)
}

var usbDescDecodeSpec = Spec{
	Name: "usb_descriptor_decode",
	Description: "Decode **USB descriptors** — the self-describing structures a USB device returns during " +
		"enumeration (the device / configuration / interface / endpoint / HID / string descriptors of USB " +
		"2.0 / 3.x). It is the **device-fingerprinting and BadUSB-analysis** companion to the project's " +
		"`usbhid` (HID report decode) and BadUSB tooling. A captured descriptor blob (from `lsusb -v`, a USB " +
		"sniffer, or the device itself) identifies the device: its **idVendor / idProduct** (the VID:PID " +
		"fingerprint), its device and per-interface **class** (HID / Mass Storage / CDC / …) and its " +
		"endpoints. This is real recon: an unexpected **HID boot-keyboard interface** (class 3 / subclass 1 / " +
		"protocol 1) is the signature of a **BadUSB / rubber-ducky** keystroke injector masquerading as a " +
		"peripheral, and a **composite device** that mixes (say) a keyboard with mass storage is a classic " +
		"malicious-USB pattern — both are flagged.\n\n" +
		"Decodes the **Device** descriptor (USB version, class, VID:PID, device version, configuration count), " +
		"the **Configuration** descriptor (total length, interface count, power attributes, max power), the " +
		"**Interface** descriptor (number, class + subclass/protocol — with the HID boot keyboard/mouse named), " +
		"the **Endpoint** descriptor (address + direction, transfer type, max packet size, interval), the " +
		"**String** descriptor (UTF-16LE text) and the Interface-Association descriptor; a full configuration " +
		"blob is walked descriptor-by-descriptor.\n\n" +
		"No confidently-wrong output: the descriptor layouts and the USB-IF base class codes follow the USB " +
		"specification (and match `lsusb`) — the structures are deterministic and byte-checkable. A " +
		"class-specific (0x24/0x25) or unknown descriptor type is surfaced by type with its body as **raw " +
		"hex** (the class-specific layouts are many and vendor-defined), and a bLength that is zero or " +
		"overruns the buffer stops the walk rather than guessing. No network, no device, transmits nothing, " +
		"so it is Low risk. The input is the descriptor blob (one descriptor or a concatenation). ':' / '-' / " +
		"'_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (USB device fingerprinting / BadUSB descriptor analysis). " +
		"Wrap-vs-native: native — a byte-slice walk + field reads + a class-code lookup, stdlib only, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The USB descriptor blob (one descriptor or a concatenation, e.g. a full configuration descriptor) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   usbDescDecodeHandler,
}

func usbDescDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("usb_descriptor_decode: 'hex' is required")
	}
	res, err := usbdesc.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("usb_descriptor_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
