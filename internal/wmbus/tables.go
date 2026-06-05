// SPDX-License-Identifier: AGPL-3.0-or-later

package wmbus

// crc16Wmbus computes the EN 13757 wM-Bus CRC-16: polynomial 0x3D65,
// initial value 0x0000, no input/output reflection, final XOR 0xFFFF.
func crc16Wmbus(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x3D65
			} else {
				crc <<= 1
			}
		}
	}
	return crc ^ 0xFFFF
}

// manufacturerFLAG decodes the 2-byte M-field into the 3-letter FLAG
// manufacturer code (each 5-bit group + 64 -> 'A'..'Z'); EN 13757.
func manufacturerFLAG(m uint16) string {
	c1 := byte((m>>10)&0x1F) + 64
	c2 := byte((m>>5)&0x1F) + 64
	c3 := byte(m&0x1F) + 64
	return string([]byte{c1, c2, c3})
}

// cFieldNames maps the wM-Bus C (control) field to its name (EN 13757-4).
var cFieldNames = map[byte]string{
	0x44: "SND-NR (send, no reply — spontaneous)",
	0x46: "SND-IR (send installation request)",
	0x47: "ACC-NR (access, no reply)",
	0x48: "ACC-DMD (access demand)",
	0x06: "RSP-UD (response, more data follows)",
	0x08: "RSP-UD (response user data)",
	0x53: "SND-UD (send user data to meter)",
	0x73: "SND-UD2 (send user data, FCB set)",
	0x40: "SND-NKE (link reset)",
	0x0B: "RSP-UD (response, no more data)",
}

func cFieldName(c byte) string {
	if n, ok := cFieldNames[c]; ok {
		return n
	}
	return "unknown control field"
}

// deviceTypeNames maps the wM-Bus device/medium type byte (EN 13757-3
// Annex A) to its name.
var deviceTypeNames = map[byte]string{
	0x00: "other", 0x01: "oil", 0x02: "electricity", 0x03: "gas",
	0x04: "heat (outlet)", 0x05: "steam", 0x06: "warm water (30-90°C)",
	0x07: "water", 0x08: "heat cost allocator", 0x09: "compressed air",
	0x0A: "cooling (outlet)", 0x0B: "cooling (inlet)", 0x0C: "heat (inlet)",
	0x0D: "combined heat/cooling", 0x0E: "bus/system component",
	0x0F: "unknown medium", 0x15: "hot water (>90°C)", 0x16: "cold water",
	0x17: "dual-register water", 0x18: "pressure", 0x19: "A/D converter",
	0x1A: "smoke detector", 0x1B: "room sensor", 0x1C: "gas detector",
	0x20: "breaker (electricity)", 0x21: "valve (gas/water)",
	0x25: "customer unit (display)", 0x28: "waste water", 0x29: "garbage",
	0x37: "radio converter (meter side)",
}

func deviceTypeName(t byte) string {
	if n, ok := deviceTypeNames[t]; ok {
		return n
	}
	return "reserved / unknown"
}
