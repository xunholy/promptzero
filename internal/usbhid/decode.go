// Package usbhid decodes USB HID Keyboard Boot Protocol reports
// — the 8-byte input reports that every BadUSB-class device
// (Hak5 Rubber Ducky, Bash Bunny, OMG Cable, Adafruit Trinket
// BadUSB, the Bruce ESP32 BadUSB add-on) generates to inject
// keystrokes into a victim host.
//
// This package is the **defensive sibling** of the badusb_*
// family — those Specs *generate* BadUSB scripts and target
// profiles; this decoder *reconstructs* the keystrokes from a
// usbmon capture of a suspected rogue device, so an incident
// responder can answer "what did the attacker actually type?"
// from a pcap alone.
//
// Operationally, this Spec is the post-incident forensic
// primitive used in:
//
//   - **Insider-threat investigations** — a rogue HID device
//     plugged into a workstation; the corporate USB-monitoring
//     stack (usbmon, Sysmon, EDR) recorded the URBs but not
//     the rendered text.
//   - **DEF CON Recon Village CTFs** — challenges that hand
//     out a usbmon pcap and ask "what was typed".
//   - **Vendor abuse triage** — a benign HID device suspected
//     of typing without operator intent; comparing recorded
//     reports against authorised payloads.
//
// Wrap-vs-native judgement
//
//	Native. The USB HID Usage Tables (HID 1.11 + HUT 1.5) are
//	publicly available; the 8-byte Boot Protocol Keyboard
//	Report layout is fully fixed (1-byte modifier bitmap +
//	1-byte reserved + 6 bytes of active HID Usage codes). No
//	crypto at the parse layer. The hard part is the
//	reconstruction policy: how to turn a stream of "currently
//	held" reports into a sequence of distinct keystroke events
//	+ a DuckyScript-style transcript.
//
// What this package covers
//
//   - **Per-report decode** (USB HID 1.11 §B.1 Boot Protocol,
//     8 bytes):
//
//   - byte 0: **Modifier bitmap** — bit 0 LCtrl + bit 1
//     LShift + bit 2 LAlt + bit 3 LGui + bit 4 RCtrl +
//     bit 5 RShift + bit 6 RAlt + bit 7 RGui.
//
//   - byte 1: Reserved (= 0).
//
//   - bytes 2-7: up to 6 simultaneous keys held as HID
//     Usage codes (Usage Page Keyboard/Keypad). 0x00
//     padding for unused slots. 0x01-0x03 are error
//     codes (ErrorRollOver / POSTFail /
//     ErrorUndefined).
//
//   - **80+ entry HID Usage code name + Shift-variant table**
//     (HID Usage Tables 1.5 §10 — selected high-runners):
//
//   - 0x04-0x1D `a..z` (Shift → `A..Z`).
//
//   - 0x1E-0x27 `1..9 0` (Shift → `!@#$%^&*()`).
//
//   - 0x28 `Enter` / 0x29 `Escape` / 0x2A `Backspace` /
//     0x2B `Tab` / 0x2C `Space`.
//
//   - 0x2D-0x38 punctuation row (`-/_`, `=/+`, `[/{`,
//     `]/}`, `\/|`, `;/:`, `'/"`, “ `/~ “, `,/<`,
//     `./>`, `//?`).
//
//   - 0x39 Caps Lock.
//
//   - 0x3A-0x45 `F1..F12`.
//
//   - 0x4A-0x4E `Home`, `PageUp`, `Delete`, `End`,
//     `PageDown`.
//
//   - 0x4F-0x52 arrow keys (`Right`, `Left`, `Down`,
//     `Up`).
//
//   - 0x53 NumLock + 0x54-0x63 keypad.
//
//   - **Key-down event detection** by report-to-report
//     diffing — successive reports declare which keys are
//     currently held; transitions from "not in previous
//     report" to "in current report" mark a fresh keystroke.
//     Suppresses repeat reports of the same key-held state.
//
//   - **Reconstructed text** — best-effort string concatenation
//     of every printable key-down event (Shift state honoured).
//     Caps Lock toggling is tracked across the report stream.
//
//   - **DuckyScript-style transcript** — produces a sequence of
//     directives that, fed back into a Rubber-Ducky-class
//     encoder, would approximate the same keystroke sequence:
//
//   - Consecutive printable characters → `STRING "<text>"`.
//
//   - Standalone non-printable keys → their DuckyScript
//     keyword (`ENTER`, `TAB`, `ESC`, `BACKSPACE`,
//     `DELETE`, `UP`, `DOWN`, `LEFT`, `RIGHT`,
//     `F1..F12`, `HOME`, `END`, `PAGEUP`, `PAGEDOWN`,
//     `CAPSLOCK`).
//
//   - Modifier + key combinations → DuckyScript modifier
//     keywords (`CTRL`, `SHIFT`, `ALT`, `GUI`,
//     `CTRL-SHIFT`, `CTRL-ALT`, `ALT-SHIFT`, `GUI-SHIFT`)
//     followed by the bare key.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Capture framing** — this Decode entry point takes the
//     concatenated 8-byte report stream as hex. Stripping the
//     per-URB framing is handled by the sibling extractors:
//     ExtractUsbmonReports (Linux usbmon text) and
//     ExtractUSBPcapReports (Windows USBPcap binary pcap,
//     DLT_USBPCAP/249).
//   - **USB enumeration descriptors** — Device / Configuration /
//     Interface / HID Report descriptors that *declare* the
//     report layout (vendor ID, product ID, report-ID field,
//     non-Boot-Protocol report shapes) are out of scope.
//   - **Composite HID devices** — devices that mix Keyboard +
//     Mouse + Consumer Control reports in the same pipe;
//     callers must split per-report-ID streams before feeding
//     this decoder.
//   - **Non-Boot-Protocol reports** — devices that opt out of
//     Boot Protocol and define a custom HID Report Descriptor
//     (with Report ID + per-key bitmaps + variable-length
//     reports) are out of scope. Most BadUSB hardware uses
//     Boot Protocol, but enterprise keyboards often don't.
//   - **Locale-specific keymaps** — the Shift-variant table
//     reflects US QWERTY; reports from a UK / DE / FR / ES /
//     IT / Dvorak / Colemak host would map to different
//     printable characters. Operators with non-US keymaps must
//     re-interpret the surfaced HID Usage codes against their
//     local layout.
//   - **Replay timing analysis** — the per-report inter-arrival
//     timing in a usbmon pcap can fingerprint BadUSB vs human
//     typing (BadUSB devices type at uniform sub-10ms cadences);
//     this decoder works on pure hex without timing metadata.
//   - **DuckyScript v2 / v3 control flow** — DuckyScript v2+
//     adds `IF`, `WHILE`, `VAR`, `RANDOM_INT()`, etc.; this
//     decoder only outputs the v1 STRING / modifier / key
//     primitives that map back from observed keystrokes.
package usbhid

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured forensic decode of a stream of USB
// HID Keyboard Boot Protocol reports.
type Result struct {
	TotalBytes  int      `json:"total_bytes"`
	ReportCount int      `json:"report_count"`
	Reports     []Report `json:"reports"`

	// Aggregated outputs.
	KeyDownEvents     []KeyDownEvent `json:"key_down_events"`
	ReconstructedText string         `json:"reconstructed_text"`
	DuckyScript       string         `json:"duckyscript"`
}

// Report is one 8-byte HID Keyboard Boot Protocol report.
type Report struct {
	ModifierHex     string   `json:"modifier_hex"`
	ModifiersActive []string `json:"modifiers_active,omitempty"`
	Keys            []KeyRef `json:"keys,omitempty"`
}

// KeyRef is one active key in a report.
type KeyRef struct {
	Code int    `json:"code"`
	Name string `json:"name"`
}

// KeyDownEvent is a key-press transition (key present in this
// report, absent from previous).
type KeyDownEvent struct {
	ReportIndex int      `json:"report_index"`
	Code        int      `json:"code"`
	Name        string   `json:"name"`
	Modifiers   []string `json:"modifiers,omitempty"`
	// Printable rendering of this key under the current modifier
	// state (empty for non-printable keys).
	Char string `json:"char,omitempty"`
}

// Decode parses a hex stream of 8-byte HID Keyboard reports.
// Separators (':' '-' '_' whitespace) tolerated; '0x' prefix
// tolerated.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b)%8 != 0 {
		return nil, fmt.Errorf("input must be a multiple of 8 bytes (got %d)", len(b))
	}

	r := &Result{TotalBytes: len(b), ReportCount: len(b) / 8}
	prevKeys := map[int]bool{}
	capsLock := false
	for i := 0; i < len(b); i += 8 {
		rep := decodeReport(b[i : i+8])
		r.Reports = append(r.Reports, rep)
		shift := containsAny(rep.ModifiersActive, "LShift", "RShift")
		modSet := nonShiftModifiers(rep.ModifiersActive)
		// Detect key-down transitions.
		currentKeys := map[int]bool{}
		for _, k := range rep.Keys {
			currentKeys[k.Code] = true
			if !prevKeys[k.Code] {
				event := KeyDownEvent{
					ReportIndex: i / 8,
					Code:        k.Code,
					Name:        k.Name,
					Modifiers:   modSet,
				}
				event.Char = renderChar(k.Code, shift, capsLock)
				r.KeyDownEvents = append(r.KeyDownEvents, event)
				if k.Code == 0x39 { // Caps Lock toggles
					capsLock = !capsLock
				}
			}
		}
		prevKeys = currentKeys
	}
	r.ReconstructedText = reconstructText(r.KeyDownEvents)
	r.DuckyScript = reconstructDuckyScript(r.KeyDownEvents)
	return r, nil
}

func decodeReport(b []byte) Report {
	r := Report{
		ModifierHex:     fmt.Sprintf("0x%02X", b[0]),
		ModifiersActive: decodeModifiers(b[0]),
	}
	for i := 2; i < 8; i++ {
		if b[i] == 0 {
			continue
		}
		r.Keys = append(r.Keys, KeyRef{
			Code: int(b[i]),
			Name: keyName(int(b[i])),
		})
	}
	return r
}

func decodeModifiers(m byte) []string {
	var names []string
	if m&0x01 != 0 {
		names = append(names, "LCtrl")
	}
	if m&0x02 != 0 {
		names = append(names, "LShift")
	}
	if m&0x04 != 0 {
		names = append(names, "LAlt")
	}
	if m&0x08 != 0 {
		names = append(names, "LGui")
	}
	if m&0x10 != 0 {
		names = append(names, "RCtrl")
	}
	if m&0x20 != 0 {
		names = append(names, "RShift")
	}
	if m&0x40 != 0 {
		names = append(names, "RAlt")
	}
	if m&0x80 != 0 {
		names = append(names, "RGui")
	}
	return names
}

func containsAny(s []string, vals ...string) bool {
	for _, e := range s {
		for _, v := range vals {
			if e == v {
				return true
			}
		}
	}
	return false
}

// nonShiftModifiers returns a deduplicated set of modifier names
// excluding Shift (since Shift is folded into character rendering).
func nonShiftModifiers(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range s {
		base := e
		switch e {
		case "LCtrl", "RCtrl":
			base = "Ctrl"
		case "LAlt", "RAlt":
			base = "Alt"
		case "LGui", "RGui":
			base = "Gui"
		case "LShift", "RShift":
			continue
		}
		if !seen[base] {
			seen[base] = true
			out = append(out, base)
		}
	}
	return out
}

// keyName returns the HID Usage code's documented name.
func keyName(c int) string {
	switch {
	case c >= 0x04 && c <= 0x1D:
		return string(rune('a' + c - 0x04))
	case c >= 0x1E && c <= 0x26:
		return string(rune('1' + c - 0x1E))
	case c == 0x27:
		return "0"
	case c >= 0x3A && c <= 0x45:
		return fmt.Sprintf("F%d", c-0x39)
	}
	switch c {
	case 0x00:
		return ""
	case 0x01:
		return "ErrorRollOver"
	case 0x02:
		return "POSTFail"
	case 0x03:
		return "ErrorUndefined"
	case 0x28:
		return "Enter"
	case 0x29:
		return "Escape"
	case 0x2A:
		return "Backspace"
	case 0x2B:
		return "Tab"
	case 0x2C:
		return "Space"
	case 0x2D:
		return "-"
	case 0x2E:
		return "="
	case 0x2F:
		return "["
	case 0x30:
		return "]"
	case 0x31:
		return "\\"
	case 0x33:
		return ";"
	case 0x34:
		return "'"
	case 0x35:
		return "`"
	case 0x36:
		return ","
	case 0x37:
		return "."
	case 0x38:
		return "/"
	case 0x39:
		return "CapsLock"
	case 0x46:
		return "PrintScreen"
	case 0x47:
		return "ScrollLock"
	case 0x48:
		return "Pause"
	case 0x49:
		return "Insert"
	case 0x4A:
		return "Home"
	case 0x4B:
		return "PageUp"
	case 0x4C:
		return "Delete"
	case 0x4D:
		return "End"
	case 0x4E:
		return "PageDown"
	case 0x4F:
		return "Right"
	case 0x50:
		return "Left"
	case 0x51:
		return "Down"
	case 0x52:
		return "Up"
	case 0x53:
		return "NumLock"
	}
	return fmt.Sprintf("HID 0x%02X", c)
}

// renderChar returns the printable character for a HID Usage
// under the supplied Shift + CapsLock state. Non-printable keys
// return "".
func renderChar(c int, shift, caps bool) string {
	// Letters honour Shift XOR CapsLock.
	if c >= 0x04 && c <= 0x1D {
		upper := shift != caps
		base := rune('a' + c - 0x04)
		if upper {
			base = rune('A' + c - 0x04)
		}
		return string(base)
	}
	// Number row: 0x1E-0x26 = 1..9, 0x27 = 0.
	if c >= 0x1E && c <= 0x27 {
		if !shift {
			if c == 0x27 {
				return "0"
			}
			return string(rune('1' + c - 0x1E))
		}
		shifted := []string{
			"!", "@", "#", "$", "%", "^", "&", "*", "(",
		}
		if c == 0x27 {
			return ")"
		}
		return shifted[c-0x1E]
	}
	// Punctuation row.
	pairs := map[int][2]string{
		0x2D: {"-", "_"},
		0x2E: {"=", "+"},
		0x2F: {"[", "{"},
		0x30: {"]", "}"},
		0x31: {"\\", "|"},
		0x33: {";", ":"},
		0x34: {"'", "\""},
		0x35: {"`", "~"},
		0x36: {",", "<"},
		0x37: {".", ">"},
		0x38: {"/", "?"},
	}
	if p, ok := pairs[c]; ok {
		if shift {
			return p[1]
		}
		return p[0]
	}
	if c == 0x2C {
		return " "
	}
	return ""
}

// reconstructText folds every printable key-down character into a
// single best-effort transcript string.
func reconstructText(events []KeyDownEvent) string {
	var sb strings.Builder
	for _, e := range events {
		if len(e.Modifiers) > 0 {
			// Ctrl/Alt/Gui-modified keys typically don't
			// produce printable text — skip.
			continue
		}
		if e.Char == "" {
			continue
		}
		sb.WriteString(e.Char)
	}
	return sb.String()
}

// reconstructDuckyScript walks key-down events and emits a
// DuckyScript v1 transcript.
func reconstructDuckyScript(events []KeyDownEvent) string {
	var sb strings.Builder
	var stringBuf strings.Builder
	flushString := func() {
		if stringBuf.Len() > 0 {
			sb.WriteString("STRING ")
			sb.WriteString(stringBuf.String())
			sb.WriteString("\n")
			stringBuf.Reset()
		}
	}
	for _, e := range events {
		if len(e.Modifiers) > 0 {
			flushString()
			// Emit modifier(s) + key.
			sb.WriteString(strings.Join(toDuckyMod(e.Modifiers), "-"))
			sb.WriteString(" ")
			sb.WriteString(duckyKeyword(e))
			sb.WriteString("\n")
			continue
		}
		if e.Char != "" {
			stringBuf.WriteString(e.Char)
			continue
		}
		// Non-printable standalone key.
		kw := duckyKeyword(e)
		if kw == "" {
			continue
		}
		flushString()
		sb.WriteString(kw)
		sb.WriteString("\n")
	}
	flushString()
	return strings.TrimRight(sb.String(), "\n")
}

// duckyKeyword maps a non-printable HID Usage to its DuckyScript
// v1 keyword. Returns empty for keys with no documented keyword.
func duckyKeyword(e KeyDownEvent) string {
	switch e.Code {
	case 0x28:
		return "ENTER"
	case 0x29:
		return "ESC"
	case 0x2A:
		return "BACKSPACE"
	case 0x2B:
		return "TAB"
	case 0x2C:
		return "SPACE"
	case 0x39:
		return "CAPSLOCK"
	case 0x46:
		return "PRINTSCREEN"
	case 0x49:
		return "INSERT"
	case 0x4A:
		return "HOME"
	case 0x4B:
		return "PAGEUP"
	case 0x4C:
		return "DELETE"
	case 0x4D:
		return "END"
	case 0x4E:
		return "PAGEDOWN"
	case 0x4F:
		return "RIGHT"
	case 0x50:
		return "LEFT"
	case 0x51:
		return "DOWN"
	case 0x52:
		return "UP"
	}
	if e.Code >= 0x3A && e.Code <= 0x45 {
		return fmt.Sprintf("F%d", e.Code-0x39)
	}
	// Letters / numbers / punctuation under a modifier — fall
	// back to the rendered character / key name.
	if e.Char != "" {
		return strings.ToUpper(e.Char)
	}
	return e.Name
}

// toDuckyMod maps generic modifier names to DuckyScript keywords
// in canonical order.
func toDuckyMod(mods []string) []string {
	order := []string{"Ctrl", "Shift", "Alt", "Gui"}
	want := map[string]bool{}
	for _, m := range mods {
		want[m] = true
	}
	var out []string
	for _, m := range order {
		if want[m] {
			out = append(out, strings.ToUpper(m))
		}
	}
	if len(out) == 0 {
		return mods
	}
	// DuckyScript GUI is "GUI" not "GUI"; check for Windows key.
	return out
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
