// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hidreport decodes a USB HID Report Descriptor — the item-based
// structure (USB HID 1.11 §6.2.2) a HID device returns to declare *what it
// is*: its usage (keyboard / mouse / gamepad / vendor-defined), its
// collections, and the size/shape of its input, output and feature reports.
// It is the deepest layer of USB device identity and the definitive
// BadUSB tell: a device whose report descriptor declares a **Generic Desktop /
// Keyboard** usage with a standard input report is a keyboard — so a flash
// drive or "charging cable" whose HID report descriptor declares a keyboard is
// a keystroke injector (Rubber Ducky / Bash Bunny / O.MG cable). It completes
// the project's USB analysis stack: usb_descriptor (the device / interface /
// endpoint identity), this (the HID usage the device claims), and usbhid (the
// 8-byte report data the device then sends).
//
// # Wrap-vs-native judgement
//
//	Native. A HID report descriptor is a flat sequence of items; each short
//	item is a prefix byte (bTag<<4 | bType<<2 | bSize) plus 0/1/2/4
//	little-endian data bytes, and a long item is 0xFE + size + tag + data. A
//	byte walk + bit-field reads + tag-name tables; stdlib only, no new go.mod
//	dep.
//
// # Verifiable / no confidently-wrong output
//
//	The item encoding, the Main / Global / Local tag tables, the Collection
//	types and the Input/Output/Feature data-flag bits follow the USB HID 1.11
//	specification — deterministic and byte-checkable against the canonical
//	boot-keyboard report descriptor. Usage-page and usage VALUES are a vast,
//	largely vendor-extensible registry, so only the well-known usage pages and
//	the Generic-Desktop usages are named; any other usage page / usage is
//	surfaced by value (never guessed), and a truncated item stops the walk.
package hidreport

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a HID report descriptor.
type Result struct {
	Items          []Item   `json:"items"`
	DeclaredUsages []string `json:"declared_usages,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

// Item is one decoded HID report-descriptor item.
type Item struct {
	Kind    string `json:"kind"` // Main | Global | Local | Long | Reserved
	Tag     string `json:"tag"`
	DataHex string `json:"data_hex,omitempty"`
	Value   *int64 `json:"value,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Decode parses a USB HID report descriptor from hex (whitespace / ':' / '-' /
// '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("hidreport: empty input")
	}
	r := &Result{}
	var curPage int64 = -1
	var pendingUsage int64 = -1
	hasPage := false

	off := 0
	for off < len(b) {
		prefix := b[off]
		if prefix == 0xFE { // long item
			if off+3 > len(b) {
				r.Notes = append(r.Notes, "truncated long item — stopping the walk")
				break
			}
			dataSize := int(b[off+1])
			tag := b[off+2]
			end := off + 3 + dataSize
			if end > len(b) {
				r.Notes = append(r.Notes, "long item overruns the buffer — stopping the walk")
				break
			}
			it := Item{Kind: "Long", Tag: fmt.Sprintf("long item tag 0x%02X", tag)}
			if dataSize > 0 {
				it.DataHex = hexUpper(b[off+3 : end])
			}
			r.Items = append(r.Items, it)
			off = end
			continue
		}
		bSize := int(prefix & 0x03)
		dataLen := bSize
		if bSize == 3 {
			dataLen = 4
		}
		bType := (prefix >> 2) & 0x03
		bTag := prefix >> 4
		if off+1+dataLen > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf("item 0x%02X claims %d data bytes but the buffer ends — stopping the walk", prefix, dataLen))
			break
		}
		data := b[off+1 : off+1+dataLen]
		val := leValue(data)
		it := Item{DataHex: hexUpper(data)}
		if dataLen > 0 {
			v := val
			it.Value = &v
		}
		switch bType {
		case 0: // Main
			it.Kind = "Main"
			it.Tag = mainTag(bTag)
			it.Detail = mainDetail(bTag, val)
		case 1: // Global
			it.Kind = "Global"
			it.Tag = globalTag(bTag)
			if bTag == 0x0 { // Usage Page
				curPage = val
				hasPage = true
				it.Detail = usagePageName(val)
			}
		case 2: // Local
			it.Kind = "Local"
			it.Tag = localTag(bTag)
			if bTag == 0x0 { // Usage
				it.Detail = usageName(curPage, hasPage, val)
				if pendingUsage < 0 {
					pendingUsage = val
				}
				if hasPage {
					r.DeclaredUsages = appendUnique(r.DeclaredUsages, fmt.Sprintf("%s / %s", usagePageName(curPage), usageName(curPage, hasPage, val)))
				}
			}
		default:
			it.Kind = "Reserved"
			it.Tag = fmt.Sprintf("reserved tag 0x%X", bTag)
		}
		r.Items = append(r.Items, it)
		off += 1 + dataLen
	}

	if len(r.Items) == 0 {
		return nil, fmt.Errorf("hidreport: no items decoded")
	}
	addReconNotes(r)
	return r, nil
}

func addReconNotes(r *Result) {
	for _, u := range r.DeclaredUsages {
		if strings.Contains(u, "Keyboard") {
			r.Notes = append(r.Notes, "the descriptor declares a Generic Desktop / Keyboard usage — this device can inject keystrokes; if it is not expected to be a keyboard (e.g. a flash drive or cable), it is a BadUSB / keystroke-injection device")
			break
		}
	}
	r.Notes = append(r.Notes, "USB HID report descriptor — the declared usage is what the device tells the host it is; usage values outside the well-known pages are surfaced by value")
}

func mainTag(t byte) string {
	switch t {
	case 0x8:
		return "Input"
	case 0x9:
		return "Output"
	case 0xB:
		return "Feature"
	case 0xA:
		return "Collection"
	case 0xC:
		return "End Collection"
	}
	return fmt.Sprintf("Main tag 0x%X", t)
}

func mainDetail(t byte, v int64) string {
	switch t {
	case 0x8, 0x9, 0xB: // Input/Output/Feature data flags
		return dataFlags(v)
	case 0xA: // Collection
		switch v {
		case 0x00:
			return "Physical"
		case 0x01:
			return "Application"
		case 0x02:
			return "Logical"
		case 0x03:
			return "Report"
		case 0x04:
			return "Named Array"
		case 0x05:
			return "Usage Switch"
		case 0x06:
			return "Usage Modifier"
		}
		return fmt.Sprintf("0x%02X", v)
	}
	return ""
}

func dataFlags(v int64) string {
	var p []string
	add := func(bit int, set, clr string) {
		if v&(1<<bit) != 0 {
			p = append(p, set)
		} else {
			p = append(p, clr)
		}
	}
	add(0, "Constant", "Data")
	add(1, "Variable", "Array")
	add(2, "Relative", "Absolute")
	if v&(1<<3) != 0 {
		p = append(p, "Wrap")
	}
	if v&(1<<4) != 0 {
		p = append(p, "Nonlinear")
	}
	if v&(1<<5) != 0 {
		p = append(p, "No Preferred")
	}
	if v&(1<<6) != 0 {
		p = append(p, "Null State")
	}
	return strings.Join(p, ",")
}

func globalTag(t byte) string {
	switch t {
	case 0x0:
		return "Usage Page"
	case 0x1:
		return "Logical Minimum"
	case 0x2:
		return "Logical Maximum"
	case 0x3:
		return "Physical Minimum"
	case 0x4:
		return "Physical Maximum"
	case 0x5:
		return "Unit Exponent"
	case 0x6:
		return "Unit"
	case 0x7:
		return "Report Size"
	case 0x8:
		return "Report ID"
	case 0x9:
		return "Report Count"
	case 0xA:
		return "Push"
	case 0xB:
		return "Pop"
	}
	return fmt.Sprintf("Global tag 0x%X", t)
}

func localTag(t byte) string {
	switch t {
	case 0x0:
		return "Usage"
	case 0x1:
		return "Usage Minimum"
	case 0x2:
		return "Usage Maximum"
	case 0x3:
		return "Designator Index"
	case 0x4:
		return "Designator Minimum"
	case 0x5:
		return "Designator Maximum"
	case 0x7:
		return "String Index"
	case 0x8:
		return "String Minimum"
	case 0x9:
		return "String Maximum"
	case 0xA:
		return "Delimiter"
	}
	return fmt.Sprintf("Local tag 0x%X", t)
}

func usagePageName(p int64) string {
	switch p {
	case 0x01:
		return "Generic Desktop"
	case 0x02:
		return "Simulation Controls"
	case 0x03:
		return "VR Controls"
	case 0x04:
		return "Sport Controls"
	case 0x05:
		return "Game Controls"
	case 0x06:
		return "Generic Device Controls"
	case 0x07:
		return "Keyboard/Keypad"
	case 0x08:
		return "LEDs"
	case 0x09:
		return "Button"
	case 0x0A:
		return "Ordinal"
	case 0x0B:
		return "Telephony"
	case 0x0C:
		return "Consumer"
	case 0x0D:
		return "Digitizer"
	case 0x0F:
		return "PID (Force Feedback)"
	case 0x10:
		return "Unicode"
	}
	if p >= 0xFF00 {
		return fmt.Sprintf("Vendor-defined (0x%04X)", p)
	}
	return fmt.Sprintf("0x%04X", p)
}

// usageName names the Generic-Desktop top-level usages (the device-type tell);
// other pages' usages are surfaced by value.
func usageName(page int64, hasPage bool, u int64) string {
	if hasPage && page == 0x01 { // Generic Desktop
		switch u {
		case 0x01:
			return "Pointer"
		case 0x02:
			return "Mouse"
		case 0x04:
			return "Joystick"
		case 0x05:
			return "Gamepad"
		case 0x06:
			return "Keyboard"
		case 0x07:
			return "Keypad"
		case 0x08:
			return "Multi-axis Controller"
		case 0x80:
			return "System Control"
		}
	}
	return fmt.Sprintf("0x%02X", u)
}

func leValue(b []byte) int64 {
	switch len(b) {
	case 0:
		return 0
	case 1:
		return int64(b[0])
	case 2:
		return int64(binary.LittleEndian.Uint16(b))
	case 4:
		return int64(binary.LittleEndian.Uint32(b))
	}
	var v int64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | int64(b[i])
	}
	return v
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("hidreport: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hidreport: input is not valid hex: %w", err)
	}
	return b, nil
}
