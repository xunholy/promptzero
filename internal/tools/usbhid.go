// usbhid.go — host-side USB HID Keyboard forensic decoder Spec.
// Wraps the internal/usbhid walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/usbhid"
)

func init() { //nolint:gochecknoinits
	Register(usbHIDClassifySpec)
}

var usbHIDClassifySpec = Spec{
	Name: "usb_badusb_classify",
	Description: "Reconstruct keystrokes + a DuckyScript-style transcript from a stream " +
		"of USB HID Keyboard Boot Protocol reports — the **defensive sibling** of " +
		"the badusb_* family (which generates BadUSB scripts and target profiles). " +
		"This Spec reconstructs keystrokes from a usbmon capture of a suspected " +
		"rogue device, so an incident responder can answer 'what did the attacker " +
		"actually type?' from a pcap alone. Used in insider-threat investigations " +
		"(rogue HID device plugged into a workstation; the corporate USB-" +
		"monitoring stack recorded the URBs but not the rendered text), DEF CON " +
		"Recon Village CTFs (challenges that hand out a usbmon pcap and ask " +
		"'what was typed'), and vendor abuse triage (benign HID device suspected " +
		"of typing without operator intent — compare recorded reports against " +
		"authorised payloads). Decodes:\n\n" +
		"- **Per-report decode** (USB HID 1.11 §B.1 Boot Protocol, 8 bytes): " +
		"byte 0 = modifier bitmap (bit 0 LCtrl / bit 1 LShift / bit 2 LAlt / " +
		"bit 3 LGui / bit 4 RCtrl / bit 5 RShift / bit 6 RAlt / bit 7 RGui); " +
		"byte 1 = Reserved; bytes 2-7 = up to 6 simultaneous keys held as HID " +
		"Usage codes (Usage Page Keyboard/Keypad). 0x00 padding for unused " +
		"slots. 0x01-0x03 are error codes (ErrorRollOver / POSTFail / " +
		"ErrorUndefined).\n" +
		"- **80+ entry HID Usage code name + Shift-variant table** (HID Usage " +
		"Tables 1.5 §10 selected high-runners): 0x04-0x1D a..z (Shift → A..Z); " +
		"0x1E-0x27 1..9 0 (Shift → !@#$%%^&*()); 0x28 Enter / 0x29 Escape / " +
		"0x2A Backspace / 0x2B Tab / 0x2C Space; 0x2D-0x38 punctuation row " +
		"(-/_, =/+, [/{, ]/}, \\/|, ;/:, '/\", `/~, ,/<, ./>, //?); 0x39 " +
		"Caps Lock; 0x3A-0x45 F1..F12; 0x4A-0x4E Home / PageUp / Delete / End " +
		"/ PageDown; 0x4F-0x52 arrow keys (Right / Left / Down / Up); 0x53 " +
		"NumLock + keypad.\n" +
		"- **Key-down event detection** by report-to-report diffing — " +
		"successive reports declare which keys are *currently* held; " +
		"transitions from 'not in previous report' to 'in current report' mark " +
		"a fresh keystroke. Suppresses repeat reports of the same key-held " +
		"state.\n" +
		"- **Reconstructed text** — best-effort string concatenation of every " +
		"printable key-down event (Shift state honoured). Caps Lock toggling " +
		"is tracked across the report stream.\n" +
		"- **DuckyScript-style transcript** — produces a sequence of " +
		"directives that, fed back into a Rubber-Ducky-class encoder, would " +
		"approximate the same keystroke sequence: consecutive printable " +
		"characters → STRING \"<text>\"; standalone non-printable keys → " +
		"DuckyScript keyword (ENTER, TAB, ESC, BACKSPACE, DELETE, UP, DOWN, " +
		"LEFT, RIGHT, F1..F12, HOME, END, PAGEUP, PAGEDOWN, CAPSLOCK); " +
		"modifier + key combinations → DuckyScript modifier keywords (CTRL, " +
		"SHIFT, ALT, GUI, CTRL-SHIFT, CTRL-ALT, ALT-SHIFT, GUI-SHIFT) followed " +
		"by the bare key.\n\n" +
		"Pure offline parser. Two input modes:\n" +
		" - `usbmon`: paste a raw Linux usbmon text capture " +
		"(`cat /sys/kernel/debug/usb/usbmon/<N>u`, or the usbmon lines " +
		"Wireshark shows) and the framing is stripped for you — every 8-byte " +
		"Interrupt-IN keyboard callback is extracted in order and decoded.\n" +
		" - `hex`: paste the already-extracted concatenated 8-byte HID " +
		"Keyboard Boot Protocol reports directly.\n" +
		"Either way you get back the per-report decode, key-down event " +
		"sequence, reconstructed text, and DuckyScript-style transcript.\n\n" +
		"Out of scope (deferred): USBPcap (Windows) framing (use the Linux " +
		"usbmon text mode, or pre-extract to `hex`); USB enumeration descriptors " +
		"(Device / Configuration / Interface / HID Report descriptors that " +
		"*declare* the report layout — vendor ID, product ID, report-ID field, " +
		"non-Boot-Protocol report shapes — are out of scope); composite HID " +
		"devices (devices that mix Keyboard + Mouse + Consumer Control reports " +
		"in the same pipe; callers must split per-report-ID streams before " +
		"feeding this decoder); non-Boot-Protocol reports (devices that opt " +
		"out of Boot Protocol and define a custom HID Report Descriptor with " +
		"Report ID + per-key bitmaps + variable-length reports — most BadUSB " +
		"hardware uses Boot Protocol, but enterprise keyboards often don't); " +
		"locale-specific keymaps (the Shift-variant table reflects US QWERTY; " +
		"reports from a UK / DE / FR / ES / IT / Dvorak / Colemak host would " +
		"map to different printable characters — operators with non-US " +
		"keymaps must re-interpret the surfaced HID Usage codes against their " +
		"local layout); replay timing analysis (the per-report inter-arrival " +
		"timing in a usbmon pcap can fingerprint BadUSB vs human typing — " +
		"BadUSB devices type at uniform sub-10ms cadences; this decoder works " +
		"on pure hex without timing metadata); DuckyScript v2/v3 control flow " +
		"(adds IF, WHILE, VAR, RANDOM_INT(), etc.; this decoder only outputs " +
		"v1 STRING / modifier / key primitives).\n\n" +
		"Source: docs/catalog/gap-analysis.md (top-30 #10 — usb_badusb_classify; " +
		"sole forensic-side native-fit primitive on the list; defensive). " +
		"Wrap-vs-native: native — the USB HID Usage Tables (HID 1.11 + HUT " +
		"1.5) are publicly available; the 8-byte Boot Protocol Keyboard Report " +
		"layout is fully fixed; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Concatenated 8-byte USB HID Keyboard Boot Protocol reports (already extracted from the capture). Must be a multiple of 8 bytes. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated. Mutually exclusive with 'usbmon'."},
			"usbmon":{"type":"string","description":"A raw Linux usbmon text capture (cat /sys/kernel/debug/usb/usbmon/<N>u). The 8-byte Interrupt-IN keyboard reports are extracted from the callback lines automatically. Mutually exclusive with 'hex'."}
		},
		"oneOf":[{"required":["hex"]},{"required":["usbmon"]}]
	}`),
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   usbHIDClassifyHandler,
}

func usbHIDClassifyHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	hexRaw := strings.TrimSpace(str(p, "hex"))
	usbmonRaw := strings.TrimSpace(str(p, "usbmon"))
	if hexRaw == "" && usbmonRaw == "" {
		return "", fmt.Errorf("usb_badusb_classify: one of 'hex' or 'usbmon' is required")
	}
	if hexRaw != "" && usbmonRaw != "" {
		return "", fmt.Errorf("usb_badusb_classify: provide 'hex' OR 'usbmon', not both")
	}

	reportHex := hexRaw
	extracted := 0
	if usbmonRaw != "" {
		var err error
		reportHex, extracted, err = usbhid.ExtractUsbmonReports(usbmonRaw)
		if err != nil {
			return "", fmt.Errorf("usb_badusb_classify: %w", err)
		}
	}

	res, err := usbhid.Decode(reportHex)
	if err != nil {
		return "", fmt.Errorf("usb_badusb_classify: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	if extracted > 0 {
		return fmt.Sprintf("// extracted %d HID keyboard report(s) from usbmon capture\n%s", extracted, string(out)), nil
	}
	return string(out), nil
}
