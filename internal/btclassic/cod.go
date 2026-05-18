// Package btclassic decodes Bluetooth Classic (BR/EDR)
// metadata fields — primarily the 24-bit Class of Device (CoD)
// value that every classic Bluetooth device advertises during
// inquiry. Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: the CoD encoding is a fully public
// Bluetooth SIG spec (Assigned Numbers — Baseband §1.2). The
// walker is bit-level decoding over a 24-bit value with
// per-major-class minor-class lookup tables. Wrapping a FAP for
// this would require an SD-card install + a firmware-fork
// dependency for a pure lookup. Native delivers offline
// analysis — operators paste a CoD value from any BT inquiry
// tool (hciconfig / bluetoothctl / btmon / nRF Connect /
// Marauder BT scan) and identify the device class without a
// re-scan.
//
// Pairs with the existing ble_continuity_decode /
// ble_eddystone_decode / ble_gap_decode (BLE side); this is
// the BT Classic counterpart.
//
// What this package covers:
//   - 24-bit CoD field walker: Format Type (2 bits) + Minor
//     Device Class (6 bits) + Major Device Class (5 bits) +
//     Service Class field (11 bits)
//   - Major Device Class lookup (~12 classes: Miscellaneous /
//     Computer / Phone / LAN/Network / Audio-Video / Peripheral
//     / Imaging / Wearable / Toy / Health / Uncategorized)
//   - Per-major-class Minor Device Class lookup (Computer →
//     Desktop / Laptop / Server / etc; Phone → Cellular /
//     Cordless / Smart / Wired Modem; Audio/Video → Headset /
//     Hands-free / Microphone / Loudspeaker / Headphones / etc.)
//   - Service Class bitmap: Limited Discoverable, LE audio,
//     Positioning, Networking, Rendering, Capturing, Object
//     Transfer, Audio, Telephony, Information
//
// What this package does NOT cover (deliberately out of scope):
//   - Extended Inquiry Response (EIR) records — same shape as
//     BLE GAP (length + AD type + data); use ble_gap_decode on
//     EIR data
//   - Bluetooth profiles (HSP / HFP / A2DP / AVRCP / etc.) —
//     those are advertised separately via SDP / GATT
//   - BR/EDR security analysis
package btclassic

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// CoD is the decoded view of a 24-bit Class of Device value.
type CoD struct {
	// Raw is the full 24-bit value.
	Raw int `json:"raw"`
	// Hex is the operator-facing 6-character form ("280404").
	Hex string `json:"hex"`
	// FormatType (bits 1..0). Always 0 in the current spec; any
	// other value is reserved.
	FormatType int `json:"format_type"`
	// MajorClass (bits 12..8) — Computer / Phone / Audio /
	// Wearable / etc.
	MajorClass     int    `json:"major_class"`
	MajorClassName string `json:"major_class_name"`
	// MinorClass (bits 7..2) — sub-category. Interpretation
	// depends on MajorClass; we surface both the raw value and
	// the looked-up name.
	MinorClass     int    `json:"minor_class"`
	MinorClassName string `json:"minor_class_name,omitempty"`
	// ServiceClasses (bits 23..13) — bitmap of advertised
	// service-class capabilities.
	ServiceClassesRaw int      `json:"service_classes_raw"`
	ServiceClasses    []string `json:"service_classes,omitempty"`
}

// Decode parses a hex-encoded 24-bit CoD value. Accepts 6 hex
// chars with optional 0x prefix and ':' / '-' / '_' /
// whitespace separators.
func Decode(hexBlob string) (CoD, error) {
	cleaned := stripSeparators(hexBlob)
	cleaned = strings.TrimPrefix(strings.ToLower(cleaned), "0x")
	if cleaned == "" {
		return CoD{}, fmt.Errorf("btclassic: empty input")
	}
	if len(cleaned) != 6 {
		return CoD{}, fmt.Errorf("btclassic: CoD must be 6 hex chars (24 bits); got %d", len(cleaned))
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return CoD{}, fmt.Errorf("btclassic: invalid hex: %w", err)
	}
	raw := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	return DecodeUint24(raw), nil
}

// DecodeUint24 is the integer-input variant of Decode. Takes
// the bottom 24 bits of the input (high byte ignored).
func DecodeUint24(raw uint32) CoD {
	raw &= 0x00FFFFFF
	fmt := int(raw & 0x03)
	minor := int((raw >> 2) & 0x3F)
	major := int((raw >> 8) & 0x1F)
	out := CoD{
		Raw:               int(raw),
		Hex:               fmtHex24(raw),
		FormatType:        fmt,
		MajorClass:        major,
		MajorClassName:    majorClassName(major),
		MinorClass:        minor,
		MinorClassName:    minorClassName(major, minor),
		ServiceClassesRaw: int(raw >> 13),
	}
	out.ServiceClasses = decodeServiceClasses(raw)
	return out
}

// fmtHex24 renders a 24-bit value as a 6-char uppercase hex
// string. Used as our own helper rather than fmt.Sprintf("%06X")
// to keep this file's imports minimal — the same trick I use
// in internal/jtag.
func fmtHex24(v uint32) string {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, 6)
	out[0] = hexDigits[(v>>20)&0x0F]
	out[1] = hexDigits[(v>>16)&0x0F]
	out[2] = hexDigits[(v>>12)&0x0F]
	out[3] = hexDigits[(v>>8)&0x0F]
	out[4] = hexDigits[(v>>4)&0x0F]
	out[5] = hexDigits[v&0x0F]
	return string(out)
}

// majorClassName returns the canonical Bluetooth Major Device
// Class name. Source: Bluetooth Assigned Numbers - Baseband §1.2
// Table 7.
func majorClassName(m int) string {
	switch m {
	case 0:
		return "Miscellaneous"
	case 1:
		return "Computer"
	case 2:
		return "Phone"
	case 3:
		return "LAN / Network Access Point"
	case 4:
		return "Audio / Video"
	case 5:
		return "Peripheral"
	case 6:
		return "Imaging"
	case 7:
		return "Wearable"
	case 8:
		return "Toy"
	case 9:
		return "Health"
	case 0x1F:
		return "Uncategorized"
	}
	return "Reserved"
}

// minorClassName dispatches per-major-class minor lookups. For
// majors we don't have a specific table for, returns "" so the
// caller can render the raw value.
func minorClassName(major, minor int) string {
	switch major {
	case 1: // Computer
		return computerMinor(minor)
	case 2: // Phone
		return phoneMinor(minor)
	case 4: // Audio / Video
		return audioVideoMinor(minor)
	case 5: // Peripheral
		return peripheralMinor(minor)
	case 6: // Imaging
		return imagingMinor(minor)
	case 7: // Wearable
		return wearableMinor(minor)
	case 8: // Toy
		return toyMinor(minor)
	case 9: // Health
		return healthMinor(minor)
	}
	return ""
}

// computerMinor maps the 6-bit minor field for Major Class =
// Computer. Per Bluetooth Assigned Numbers Baseband §1.2
// Table 7. The 6-bit minor value is used directly — the
// per-major Minor Class tables encode the device sub-type in
// the 6-bit minor value space.
func computerMinor(m int) string {
	switch m {
	case 0:
		return "Uncategorized"
	case 1:
		return "Desktop workstation"
	case 2:
		return "Server-class computer"
	case 3:
		return "Laptop"
	case 4:
		return "Handheld PC / PDA (clamshell)"
	case 5:
		return "Palm-sized PC / PDA"
	case 6:
		return "Wearable computer (watch size)"
	case 7:
		return "Tablet"
	}
	return ""
}

// phoneMinor maps Major Class = Phone.
func phoneMinor(m int) string {
	switch m {
	case 0:
		return "Uncategorized"
	case 1:
		return "Cellular"
	case 2:
		return "Cordless"
	case 3:
		return "Smart phone"
	case 4:
		return "Wired modem / voice gateway"
	case 5:
		return "Common ISDN access"
	}
	return ""
}

// audioVideoMinor maps Major Class = Audio/Video. Per Table 7,
// the A/V minor space is rich — covers headsets, microphones,
// car audio, etc.
func audioVideoMinor(m int) string {
	switch m {
	case 0:
		return "Uncategorized"
	case 1:
		return "Wearable headset device"
	case 2:
		return "Hands-free device"
	case 3:
		return "Reserved"
	case 4:
		return "Microphone"
	case 5:
		return "Loudspeaker"
	case 6:
		return "Headphones"
	case 7:
		return "Portable audio"
	case 8:
		return "Car audio"
	case 9:
		return "Set-top box"
	case 10:
		return "HiFi audio device"
	case 11:
		return "VCR"
	case 12:
		return "Video camera"
	case 13:
		return "Camcorder"
	case 14:
		return "Video monitor"
	case 15:
		return "Video display and loudspeaker"
	case 16:
		return "Video conferencing"
	case 17:
		return "Reserved"
	case 18:
		return "Gaming / toy"
	}
	return ""
}

// peripheralMinor maps Major Class = Peripheral. Per Table 7,
// the top 2 bits of the 6-bit minor (bits 5..4) are
// keyboard/pointing combination flags; the bottom 4 bits
// (3..0) are the device type selector.
func peripheralMinor(m int) string {
	kb := m&0x20 != 0
	point := m&0x10 != 0
	devType := m & 0x0F
	var pieces []string
	if kb {
		pieces = append(pieces, "keyboard")
	}
	if point {
		pieces = append(pieces, "pointing device")
	}
	switch devType {
	case 0x1:
		pieces = append(pieces, "joystick")
	case 0x2:
		pieces = append(pieces, "gamepad")
	case 0x3:
		pieces = append(pieces, "remote control")
	case 0x4:
		pieces = append(pieces, "sensing device")
	case 0x5:
		pieces = append(pieces, "digitizer tablet")
	case 0x6:
		pieces = append(pieces, "card reader")
	case 0x7:
		pieces = append(pieces, "digital pen")
	case 0x8:
		pieces = append(pieces, "handheld scanner")
	case 0x9:
		pieces = append(pieces, "handheld gestural input")
	}
	if len(pieces) == 0 {
		return "Uncategorized / reserved peripheral"
	}
	return strings.Join(pieces, " + ")
}

// imagingMinor maps Major Class = Imaging. Per Table 7, the
// bits are flag bits rather than a packed selector — they can
// stand alone or combine.
func imagingMinor(m int) string {
	// Bits 5..2: display=1 / camera=2 / scanner=4 / printer=8
	var pieces []string
	if m&(1<<2) != 0 {
		pieces = append(pieces, "display")
	}
	if m&(1<<3) != 0 {
		pieces = append(pieces, "camera")
	}
	if m&(1<<4) != 0 {
		pieces = append(pieces, "scanner")
	}
	if m&(1<<5) != 0 {
		pieces = append(pieces, "printer")
	}
	if len(pieces) == 0 {
		return "Uncategorized imaging device"
	}
	return strings.Join(pieces, " + ")
}

// wearableMinor maps Major Class = Wearable.
func wearableMinor(m int) string {
	switch m {
	case 1:
		return "Wristwatch"
	case 2:
		return "Pager"
	case 3:
		return "Jacket"
	case 4:
		return "Helmet"
	case 5:
		return "Glasses"
	}
	return "Uncategorized wearable"
}

// toyMinor maps Major Class = Toy.
func toyMinor(m int) string {
	switch m {
	case 1:
		return "Robot"
	case 2:
		return "Vehicle"
	case 3:
		return "Doll / action figure"
	case 4:
		return "Controller"
	case 5:
		return "Game"
	}
	return "Uncategorized toy"
}

// healthMinor maps Major Class = Health. Per Table 7.
func healthMinor(m int) string {
	switch m {
	case 0:
		return "Undefined"
	case 1:
		return "Blood pressure monitor"
	case 2:
		return "Thermometer"
	case 3:
		return "Weighing scale"
	case 4:
		return "Glucose meter"
	case 5:
		return "Pulse oximeter"
	case 6:
		return "Heart rate / pulse monitor"
	case 7:
		return "Health data display"
	case 8:
		return "Step counter"
	case 9:
		return "Body composition analyzer"
	case 10:
		return "Peak flow monitor"
	case 11:
		return "Medication monitor"
	case 12:
		return "Knee prosthesis"
	case 13:
		return "Ankle prosthesis"
	case 14:
		return "Generic health manager"
	case 15:
		return "Personal mobility device"
	}
	return "Reserved health device"
}

// decodeServiceClasses walks the 11-bit Service Class field
// (bits 23..13) and returns the documented capability names
// that are set. Bit positions per Bluetooth Assigned Numbers
// Baseband §1.2 Table 6.
func decodeServiceClasses(raw uint32) []string {
	var out []string
	if raw&(1<<13) != 0 {
		out = append(out, "Limited Discoverable Mode")
	}
	if raw&(1<<14) != 0 {
		out = append(out, "LE audio")
	}
	// Bit 15 reserved
	if raw&(1<<16) != 0 {
		out = append(out, "Positioning")
	}
	if raw&(1<<17) != 0 {
		out = append(out, "Networking")
	}
	if raw&(1<<18) != 0 {
		out = append(out, "Rendering")
	}
	if raw&(1<<19) != 0 {
		out = append(out, "Capturing")
	}
	if raw&(1<<20) != 0 {
		out = append(out, "Object Transfer")
	}
	if raw&(1<<21) != 0 {
		out = append(out, "Audio")
	}
	if raw&(1<<22) != 0 {
		out = append(out, "Telephony")
	}
	if raw&(1<<23) != 0 {
		out = append(out, "Information")
	}
	return out
}

// stripSeparators mirrors the convention across our pure-decoder
// packages.
func stripSeparators(s string) string {
	repl := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		":", "",
		"-", "",
		"_", "",
	)
	return repl.Replace(strings.TrimSpace(s))
}
