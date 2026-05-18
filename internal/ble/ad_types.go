package ble

// adTypeNames maps the documented Bluetooth SIG AD types to
// their canonical names. Source: Bluetooth SIG Assigned Numbers
// "Generic Access Profile" section. Covers the ~30 types
// operators see in real BLE captures.
var adTypeNames = map[byte]string{
	0x01: "Flags",
	0x02: "Incomplete List of 16-bit Service UUIDs",
	0x03: "Complete List of 16-bit Service UUIDs",
	0x04: "Incomplete List of 32-bit Service UUIDs",
	0x05: "Complete List of 32-bit Service UUIDs",
	0x06: "Incomplete List of 128-bit Service UUIDs",
	0x07: "Complete List of 128-bit Service UUIDs",
	0x08: "Shortened Local Name",
	0x09: "Complete Local Name",
	0x0A: "TX Power Level",
	0x0D: "Class of Device",
	0x0E: "Simple Pairing Hash C-192",
	0x0F: "Simple Pairing Randomizer R-192",
	0x10: "Device ID / Security Manager TK Value",
	0x11: "Security Manager Out-of-Band Flags",
	0x12: "Peripheral Connection Interval Range",
	0x14: "List of 16-bit Service Solicitation UUIDs",
	0x15: "List of 128-bit Service Solicitation UUIDs",
	0x16: "Service Data - 16-bit UUID",
	0x17: "Public Target Address",
	0x18: "Random Target Address",
	0x19: "Appearance",
	0x1A: "Advertising Interval",
	0x1B: "LE Bluetooth Device Address",
	0x1C: "LE Role",
	0x1D: "Simple Pairing Hash C-256",
	0x1E: "Simple Pairing Randomizer R-256",
	0x1F: "List of 32-bit Service Solicitation UUIDs",
	0x20: "Service Data - 32-bit UUID",
	0x21: "Service Data - 128-bit UUID",
	0x22: "LE Secure Connections Confirmation Value",
	0x23: "LE Secure Connections Random Value",
	0x24: "URI",
	0x25: "Indoor Positioning",
	0x26: "Transport Discovery Data",
	0x27: "LE Supported Features",
	0x28: "Channel Map Update Indication",
	0x29: "PB-ADV (Mesh)",
	0x2A: "Mesh Message",
	0x2B: "Mesh Beacon",
	0x2C: "BIGInfo",
	0x2D: "Broadcast Code",
	0x3D: "3D Information Data",
	0xFF: "Manufacturer Specific Data",
}

func adTypeName(t byte) string {
	if n, ok := adTypeNames[t]; ok {
		return n
	}
	return "Unknown"
}

// companyIDs maps the Bluetooth SIG-assigned 16-bit company
// identifiers to vendor names. Source: Bluetooth SIG Assigned
// Numbers "Company Identifiers" document. Covers the ~25 most
// commonly observed vendors in BLE advertisements.
var companyIDs = map[uint16]string{
	0x0000: "Ericsson Technology Licensing",
	0x0001: "Nokia Mobile Phones",
	0x0002: "Intel Corp.",
	0x0003: "IBM Corp.",
	0x0004: "Toshiba Corp.",
	0x0005: "3Com",
	0x0006: "Microsoft",
	0x0007: "Lucent",
	0x0008: "Motorola",
	0x0009: "Infineon Technologies AG",
	0x000A: "Cambridge Silicon Radio",
	0x000F: "Broadcom Corporation",
	0x0010: "Mitsubishi Electric Corporation",
	0x0012: "Zeevo, Inc.",
	0x001D: "Qualcomm",
	0x0030: "ST Microelectronics",
	0x0033: "Renesas Electronics Corporation",
	0x004C: "Apple, Inc.",
	0x0059: "Nordic Semiconductor ASA",
	0x0075: "Samsung Electronics Co., Ltd",
	0x0087: "Garmin International, Inc.",
	0x00BA: "Tile, Inc.",
	0x00C4: "LG Electronics, Inc.",
	0x00D7: "Polar Electro Oy",
	0x00E0: "Google",
	0x0118: "Bose Corporation",
	0x0131: "Cypress Semiconductor",
	0x015D: "Estimote, Inc.",
	0x01D6: "Anhui Huami Information Technology",
	0x021D: "Texas Instruments",
	0x0231: "Fitbit, Inc.",
	0x0388: "Logitech International SA",
	0x0708: "Amazon.com Services LLC",
	0x0B0A: "PinePhone",
	0x0590: "Espressif Incorporated",
}

// wellKnownServices maps the Bluetooth SIG-assigned 16-bit
// Service UUIDs that operators most often see in BLE captures.
// Source: Bluetooth SIG Assigned Numbers "GATT Services".
//
// Limited to ~25 entries — the actual SIG catalog has hundreds
// of services, but operators care mostly about the standard
// device services (Battery, Heart Rate, etc.) and the
// well-known proprietary ones (Apple Continuity 0xFEDx range,
// Google Eddystone 0xFEAA).
var wellKnownServices = map[uint16]string{
	0x1800: "Generic Access",
	0x1801: "Generic Attribute",
	0x1802: "Immediate Alert",
	0x1803: "Link Loss",
	0x1804: "TX Power",
	0x1805: "Current Time",
	0x1806: "Reference Time Update",
	0x1807: "Next DST Change",
	0x1808: "Glucose",
	0x1809: "Health Thermometer",
	0x180A: "Device Information",
	0x180D: "Heart Rate",
	0x180E: "Phone Alert Status",
	0x180F: "Battery",
	0x1810: "Blood Pressure",
	0x1811: "Alert Notification",
	0x1812: "Human Interface Device",
	0x1813: "Scan Parameters",
	0x1814: "Running Speed and Cadence",
	0x1815: "Automation IO",
	0x1816: "Cycling Speed and Cadence",
	0x1818: "Cycling Power",
	0x1819: "Location and Navigation",
	0x181A: "Environmental Sensing",
	0x181B: "Body Composition",
	0x181C: "User Data",
	0x181D: "Weight Scale",
	0x181E: "Bond Management",
	0x181F: "Continuous Glucose Monitoring",
	0x1820: "Internet Protocol Support",
	0x1821: "Indoor Positioning",
	0x1822: "Pulse Oximeter",
	0x1823: "HTTP Proxy",
	0x1824: "Transport Discovery",
	0x1825: "Object Transfer",
	0x1826: "Fitness Machine",
	0x1827: "Mesh Provisioning",
	0x1828: "Mesh Proxy",
	0xFEAA: "Eddystone (Google)",
	0xFE9F: "Google Fast Pair",
	0xFD6F: "Exposure Notification (COVID-19)",
}

// appearanceCategories maps the high 10 bits of the Appearance
// code to the coarse-category name. The low 6 bits select a
// sub-category within each — those are very numerous and we
// don't enumerate them here. Source: Bluetooth SIG Assigned
// Numbers "Appearance Values" document.
var appearanceCategories = map[uint16]string{
	0x0000: "Unknown",
	0x0040: "Phone",
	0x0080: "Computer",
	0x00C0: "Watch",
	0x0100: "Clock",
	0x0140: "Display",
	0x0180: "Remote Control",
	0x01C0: "Eye-glasses",
	0x0200: "Tag",
	0x0240: "Keyring",
	0x0280: "Media Player",
	0x02C0: "Barcode Scanner",
	0x0300: "Thermometer",
	0x0340: "Heart Rate Sensor",
	0x0380: "Blood Pressure",
	0x03C0: "Human Interface Device",
	0x0400: "Glucose Meter",
	0x0440: "Running / Walking Sensor",
	0x0480: "Cycling",
	0x0540: "Pulse Oximeter",
	0x0580: "Weight Scale",
	0x05C0: "Personal Mobility Device",
	0x0600: "Continuous Glucose Monitor",
	0x0640: "Insulin Pump",
	0x0680: "Medication Delivery",
	0x0700: "Outdoor Sports Activity",
	0x0744: "Earbud",
	0x0780: "Hearing Aid",
}
