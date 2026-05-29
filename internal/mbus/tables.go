// SPDX-License-Identifier: AGPL-3.0-or-later

package mbus

// cFieldNames maps the canonical M-Bus C-field (Control field) values
// to their function names (EN 13757-2 §5.4). The FCB/FCV (master) and
// ACD/DFC (slave) bits produce the two/four variants per function.
var cFieldNames = map[int]string{
	0x40: "SND_NKE (initialise slave)",
	0x53: "SND_UD (send user data, FCB=0)",
	0x73: "SND_UD (send user data, FCB=1)",
	0x5A: "REQ_UD1 (request class 1 data, FCB=0)",
	0x7A: "REQ_UD1 (request class 1 data, FCB=1)",
	0x5B: "REQ_UD2 (request class 2 data, FCB=0)",
	0x7B: "REQ_UD2 (request class 2 data, FCB=1)",
	0x08: "RSP_UD (response, user data)",
	0x18: "RSP_UD (response, DFC=1)",
	0x28: "RSP_UD (response, ACD=1)",
	0x38: "RSP_UD (response, ACD=1 DFC=1)",
}

func cFieldName(c int) string {
	if n, ok := cFieldNames[c]; ok {
		return n
	}
	return "unknown"
}

// cFieldDirection reads the PRM (primary message) bit — bit 6 — to
// report the telegram direction. PRM=1 is a calling message from the
// master; PRM=0 is a replying message from the slave/meter.
func cFieldDirection(c int) string {
	if c&0x40 != 0 {
		return "master → slave (calling)"
	}
	return "slave → master (replying)"
}

// addressType classifies the A-field (EN 13757-2 §5.5).
func addressType(a int) string {
	switch {
	case a == 0:
		return "unconfigured (factory default)"
	case a >= 1 && a <= 250:
		return "primary address"
	case a == 251 || a == 252:
		return "reserved"
	case a == 253:
		return "secondary addressing in use"
	case a == 254:
		return "broadcast (slaves reply)"
	case a == 255:
		return "broadcast (no reply)"
	default:
		return "unknown"
	}
}

// ciFieldNames maps the common CI-field (Control Information) values
// to their application-layer meaning (EN 13757-3 §5.2).
var ciFieldNames = map[int]string{
	0x50: "Application reset",
	0x51: "Data send (command to meter)",
	0x52: "Selection of slaves (secondary addressing)",
	0x54: "Request of selected application errors",
	0x6C: "Set clock / time synchronisation",
	0x70: "Application error from device",
	0x71: "Report of alarm status",
	0x72: "Variable data response, long header (12-byte)",
	0x73: "Fixed data response, long header",
	0x76: "Variable data response, long header (alt)",
	0x78: "Variable data response, no header",
	0x7A: "Variable data response, short header (4-byte)",
	0xB8: "Set baud rate to 300",
	0xB9: "Set baud rate to 600",
	0xBA: "Set baud rate to 1200",
	0xBB: "Set baud rate to 2400",
	0xBC: "Set baud rate to 4800",
	0xBD: "Set baud rate to 9600",
}

func ciFieldName(ci int) string {
	if n, ok := ciFieldNames[ci]; ok {
		return n
	}
	return "unknown / manufacturer-specific"
}

// mediumNames maps the device-type / medium byte in the Variable Data
// Structure long header to a human name (EN 13757-3 Annex A).
var mediumNames = map[int]string{
	0x00: "Other",
	0x01: "Oil",
	0x02: "Electricity",
	0x03: "Gas",
	0x04: "Heat (volume measured at outlet)",
	0x05: "Steam",
	0x06: "Warm water (30–90 °C)",
	0x07: "Water",
	0x08: "Heat cost allocator",
	0x09: "Compressed air",
	0x0A: "Cooling load (outlet)",
	0x0B: "Cooling load (inlet)",
	0x0C: "Heat (volume measured at inlet)",
	0x0D: "Heat / cooling load",
	0x0E: "Bus / system component",
	0x0F: "Unknown medium",
	0x15: "Hot water (≥ 90 °C)",
	0x16: "Cold water",
	0x17: "Dual register (hot/cold) water",
	0x18: "Pressure",
	0x19: "A/D converter",
	0x20: "Breaker (electricity)",
	0x21: "Valve (gas or water)",
	0x28: "Waste water",
	0x29: "Garbage",
}

func mediumName(m int) string {
	if n, ok := mediumNames[m]; ok {
		return n
	}
	return "reserved / manufacturer-specific"
}
