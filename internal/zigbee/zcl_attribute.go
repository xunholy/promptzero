package zigbee

// zcl_attribute.go — Zigbee Cluster Library attribute data type
// decoder. The existing zigbee_zcl_decode walks the frame
// structure (FC + TSN + Command ID + payload); this dissects
// the typed attribute values inside a Read Attributes Response /
// Report Attributes / Write Attributes payload.
//
// Per ZCL Spec 07-5123-08 §2.5.2, every attribute value is
// preceded by a 1-byte data type tag that selects the value
// encoding. The catalog covers ~30 types from null (0x00)
// through IEEE address (0xF0).

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// AttributeValue is one decoded ZCL attribute value.
type AttributeValue struct {
	// DataType is the 1-byte type tag.
	DataType    int    `json:"data_type"`
	DataTypeHex string `json:"data_type_hex"`
	// TypeName is the canonical name from ZCL §2.5.2.
	TypeName string `json:"type_name"`
	// Value is the decoded value in the most natural Go type
	// for the underlying data — int64 for numeric, float64 for
	// float, bool for boolean, string for char string, etc.
	// nil for "no data" / "null" types.
	Value any `json:"value,omitempty"`
	// RawHex is the operator-facing hex rendering of the value
	// bytes (excluding the type tag). Empty for types with no
	// data (null, no-data).
	RawHex string `json:"raw_hex,omitempty"`
	// Length is the byte length of the value (excluding the
	// type tag).
	Length int `json:"length"`
}

// DecodeAttribute parses a hex-encoded ZCL attribute (type
// tag + value bytes) into a structured AttributeValue. Returns
// the decoded value + the number of bytes consumed (so callers
// walking a multi-attribute payload can advance the offset).
// Tolerates ':' / '-' / '_' / whitespace separators.
func DecodeAttribute(hexBlob string) (AttributeValue, int, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return AttributeValue{}, 0, fmt.Errorf("zigbee: empty attribute input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return AttributeValue{}, 0, fmt.Errorf("zigbee: invalid hex: %w", err)
	}
	return DecodeAttributeBytes(b)
}

// DecodeAttributeBytes is the byte-slice variant of
// DecodeAttribute.
func DecodeAttributeBytes(b []byte) (AttributeValue, int, error) {
	if len(b) < 1 {
		return AttributeValue{}, 0, fmt.Errorf("zigbee: empty attribute input")
	}
	t := b[0]
	out := AttributeValue{
		DataType:    int(t),
		DataTypeHex: fmt.Sprintf("%02X", t),
		TypeName:    attributeTypeName(t),
	}
	body := b[1:]
	consumed, err := decodeAttributeValue(&out, t, body)
	if err != nil {
		return out, 0, err
	}
	out.Length = consumed
	out.RawHex = strings.ToUpper(hex.EncodeToString(body[:consumed]))
	return out, 1 + consumed, nil
}

// decodeAttributeValue dispatches per-type decoders, populating
// the AttributeValue.Value field. Returns the number of value
// bytes consumed (so the caller knows how to advance).
func decodeAttributeValue(out *AttributeValue, t byte, body []byte) (int, error) {
	switch t {
	case 0x00, 0xFF:
		// No data / unknown — zero bytes.
		return 0, nil
	case 0x08:
		// 8-bit data — surface as uint8.
		if len(body) < 1 {
			return 0, fmt.Errorf("zigbee attribute: 8-bit data truncated")
		}
		out.Value = int64(body[0])
		return 1, nil
	case 0x09:
		// 16-bit data.
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: 16-bit data truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint16(body[0:2]))
		return 2, nil
	case 0x0A:
		// 24-bit data — LE-packed in 3 bytes.
		if len(body) < 3 {
			return 0, fmt.Errorf("zigbee attribute: 24-bit data truncated")
		}
		out.Value = int64(uint32(body[0]) | uint32(body[1])<<8 | uint32(body[2])<<16)
		return 3, nil
	case 0x0B:
		// 32-bit data.
		if len(body) < 4 {
			return 0, fmt.Errorf("zigbee attribute: 32-bit data truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint32(body[0:4]))
		return 4, nil
	case 0x10:
		// Boolean.
		if len(body) < 1 {
			return 0, fmt.Errorf("zigbee attribute: boolean truncated")
		}
		out.Value = body[0] != 0
		return 1, nil
	case 0x18:
		// 8-bit bitmap.
		if len(body) < 1 {
			return 0, fmt.Errorf("zigbee attribute: bitmap8 truncated")
		}
		out.Value = int64(body[0])
		return 1, nil
	case 0x19:
		// 16-bit bitmap.
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: bitmap16 truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint16(body[0:2]))
		return 2, nil
	case 0x1B:
		// 32-bit bitmap.
		if len(body) < 4 {
			return 0, fmt.Errorf("zigbee attribute: bitmap32 truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint32(body[0:4]))
		return 4, nil
	case 0x20:
		// uint8
		if len(body) < 1 {
			return 0, fmt.Errorf("zigbee attribute: uint8 truncated")
		}
		out.Value = int64(body[0])
		return 1, nil
	case 0x21:
		// uint16
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: uint16 truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint16(body[0:2]))
		return 2, nil
	case 0x22:
		// uint24
		if len(body) < 3 {
			return 0, fmt.Errorf("zigbee attribute: uint24 truncated")
		}
		out.Value = int64(uint32(body[0]) | uint32(body[1])<<8 | uint32(body[2])<<16)
		return 3, nil
	case 0x23:
		// uint32
		if len(body) < 4 {
			return 0, fmt.Errorf("zigbee attribute: uint32 truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint32(body[0:4]))
		return 4, nil
	case 0x27:
		// uint64
		if len(body) < 8 {
			return 0, fmt.Errorf("zigbee attribute: uint64 truncated")
		}
		// Surface as int64 — ZCL uint64 attributes that overflow
		// int64 are rare in practice; operators with overflow
		// concerns can read the raw bytes from RawHex.
		out.Value = int64(binary.LittleEndian.Uint64(body[0:8]))
		return 8, nil
	case 0x28:
		// int8
		if len(body) < 1 {
			return 0, fmt.Errorf("zigbee attribute: int8 truncated")
		}
		out.Value = int64(int8(body[0]))
		return 1, nil
	case 0x29:
		// int16
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: int16 truncated")
		}
		out.Value = int64(int16(binary.LittleEndian.Uint16(body[0:2])))
		return 2, nil
	case 0x2B:
		// int32
		if len(body) < 4 {
			return 0, fmt.Errorf("zigbee attribute: int32 truncated")
		}
		out.Value = int64(int32(binary.LittleEndian.Uint32(body[0:4])))
		return 4, nil
	case 0x2F:
		// int64
		if len(body) < 8 {
			return 0, fmt.Errorf("zigbee attribute: int64 truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint64(body[0:8]))
		return 8, nil
	case 0x30:
		// 8-bit enum
		if len(body) < 1 {
			return 0, fmt.Errorf("zigbee attribute: enum8 truncated")
		}
		out.Value = int64(body[0])
		return 1, nil
	case 0x31:
		// 16-bit enum
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: enum16 truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint16(body[0:2]))
		return 2, nil
	case 0x38:
		// Semi-precision (16-bit half float) — convert via the
		// IEEE 754 half-float layout.
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: semi-float truncated")
		}
		out.Value = float16ToFloat64(binary.LittleEndian.Uint16(body[0:2]))
		return 2, nil
	case 0x39:
		// Single-precision (32-bit) float
		if len(body) < 4 {
			return 0, fmt.Errorf("zigbee attribute: float32 truncated")
		}
		out.Value = float64(math.Float32frombits(binary.LittleEndian.Uint32(body[0:4])))
		return 4, nil
	case 0x3A:
		// Double-precision (64-bit) float
		if len(body) < 8 {
			return 0, fmt.Errorf("zigbee attribute: float64 truncated")
		}
		out.Value = math.Float64frombits(binary.LittleEndian.Uint64(body[0:8]))
		return 8, nil
	case 0x41:
		// Octet string — 1-byte length prefix + bytes.
		if len(body) < 1 {
			return 0, fmt.Errorf("zigbee attribute: octet string length truncated")
		}
		l := int(body[0])
		if 1+l > len(body) {
			return 0, fmt.Errorf("zigbee attribute: octet string body truncated (want %d bytes)", l)
		}
		out.Value = strings.ToUpper(hex.EncodeToString(body[1 : 1+l]))
		return 1 + l, nil
	case 0x42:
		// Character string — 1-byte length prefix + UTF-8 bytes.
		if len(body) < 1 {
			return 0, fmt.Errorf("zigbee attribute: char string length truncated")
		}
		l := int(body[0])
		if 1+l > len(body) {
			return 0, fmt.Errorf("zigbee attribute: char string body truncated (want %d bytes)", l)
		}
		out.Value = string(body[1 : 1+l])
		return 1 + l, nil
	case 0x43:
		// Long octet string — 2-byte LE length prefix + bytes.
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: long octet string length truncated")
		}
		l := int(binary.LittleEndian.Uint16(body[0:2]))
		if 2+l > len(body) {
			return 0, fmt.Errorf("zigbee attribute: long octet string body truncated")
		}
		out.Value = strings.ToUpper(hex.EncodeToString(body[2 : 2+l]))
		return 2 + l, nil
	case 0x44:
		// Long character string — 2-byte LE length prefix + UTF-8.
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: long char string length truncated")
		}
		l := int(binary.LittleEndian.Uint16(body[0:2]))
		if 2+l > len(body) {
			return 0, fmt.Errorf("zigbee attribute: long char string body truncated")
		}
		out.Value = string(body[2 : 2+l])
		return 2 + l, nil
	case 0xE0:
		// Time of day — 4 bytes (hours/min/sec/hundredths).
		if len(body) < 4 {
			return 0, fmt.Errorf("zigbee attribute: time of day truncated")
		}
		out.Value = fmt.Sprintf("%02d:%02d:%02d.%02d",
			body[0], body[1], body[2], body[3])
		return 4, nil
	case 0xE1:
		// Date — 4 bytes (year-1900, month, day, day-of-week).
		if len(body) < 4 {
			return 0, fmt.Errorf("zigbee attribute: date truncated")
		}
		out.Value = fmt.Sprintf("%04d-%02d-%02d (dow %d)",
			int(body[0])+1900, body[1], body[2], body[3])
		return 4, nil
	case 0xE2:
		// UTC time — 32-bit seconds since 2000-01-01 00:00:00.
		if len(body) < 4 {
			return 0, fmt.Errorf("zigbee attribute: UTC time truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint32(body[0:4]))
		return 4, nil
	case 0xE8:
		// Cluster ID
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: cluster ID truncated")
		}
		out.Value = fmt.Sprintf("%04X", binary.LittleEndian.Uint16(body[0:2]))
		return 2, nil
	case 0xE9:
		// Attribute ID
		if len(body) < 2 {
			return 0, fmt.Errorf("zigbee attribute: attribute ID truncated")
		}
		out.Value = fmt.Sprintf("%04X", binary.LittleEndian.Uint16(body[0:2]))
		return 2, nil
	case 0xEA:
		// BACnet OID
		if len(body) < 4 {
			return 0, fmt.Errorf("zigbee attribute: BACnet OID truncated")
		}
		out.Value = int64(binary.LittleEndian.Uint32(body[0:4]))
		return 4, nil
	case 0xF0:
		// IEEE address (8 bytes, little-endian on wire — render
		// big-endian to match device-label form).
		if len(body) < 8 {
			return 0, fmt.Errorf("zigbee attribute: IEEE address truncated")
		}
		rev := reverseBytes(body[0:8])
		out.Value = strings.ToUpper(hex.EncodeToString(rev))
		return 8, nil
	case 0xF1:
		// 128-bit security key (16 bytes).
		if len(body) < 16 {
			return 0, fmt.Errorf("zigbee attribute: security key truncated")
		}
		out.Value = strings.ToUpper(hex.EncodeToString(body[0:16]))
		return 16, nil
	}
	return 0, fmt.Errorf("zigbee: unknown attribute data type 0x%02X", t)
}

// attributeTypeName returns the canonical ZCL data-type name
// per Spec §2.5.2 Table 2-10.
func attributeTypeName(t byte) string {
	switch t {
	case 0x00:
		return "No data"
	case 0x08:
		return "General Data 8-bit"
	case 0x09:
		return "General Data 16-bit"
	case 0x0A:
		return "General Data 24-bit"
	case 0x0B:
		return "General Data 32-bit"
	case 0x10:
		return "Boolean"
	case 0x18:
		return "8-bit bitmap"
	case 0x19:
		return "16-bit bitmap"
	case 0x1B:
		return "32-bit bitmap"
	case 0x20:
		return "uint8"
	case 0x21:
		return "uint16"
	case 0x22:
		return "uint24"
	case 0x23:
		return "uint32"
	case 0x27:
		return "uint64"
	case 0x28:
		return "int8"
	case 0x29:
		return "int16"
	case 0x2B:
		return "int32"
	case 0x2F:
		return "int64"
	case 0x30:
		return "8-bit enumeration"
	case 0x31:
		return "16-bit enumeration"
	case 0x38:
		return "Semi-precision float (16-bit)"
	case 0x39:
		return "Single-precision float (32-bit)"
	case 0x3A:
		return "Double-precision float (64-bit)"
	case 0x41:
		return "Octet string"
	case 0x42:
		return "Character string"
	case 0x43:
		return "Long octet string"
	case 0x44:
		return "Long character string"
	case 0xE0:
		return "Time of day"
	case 0xE1:
		return "Date"
	case 0xE2:
		return "UTC time"
	case 0xE8:
		return "Cluster ID"
	case 0xE9:
		return "Attribute ID"
	case 0xEA:
		return "BACnet OID"
	case 0xF0:
		return "IEEE address"
	case 0xF1:
		return "128-bit security key"
	case 0xFF:
		return "Unknown / unspecified"
	}
	return "Reserved"
}

// float16ToFloat64 converts an IEEE 754 half-precision (16-bit)
// float to a float64. ZCL semi-precision attributes use this
// format.
//
// Layout: 1-bit sign + 5-bit exponent (bias 15) + 10-bit
// mantissa. Subnormals + infinities + NaN handled.
func float16ToFloat64(h uint16) float64 {
	sign := uint32(h>>15) & 0x1
	exp := uint32(h>>10) & 0x1F
	mantissa := uint32(h) & 0x3FF
	var f32bits uint32
	switch exp {
	case 0:
		if mantissa == 0 {
			// Signed zero.
			f32bits = sign << 31
		} else {
			// Subnormal — normalise.
			for mantissa&0x400 == 0 {
				mantissa <<= 1
				exp--
			}
			exp++
			mantissa &= 0x3FF
			f32bits = (sign << 31) | ((exp + 127 - 15) << 23) | (mantissa << 13)
		}
	case 31:
		// Infinity or NaN.
		f32bits = (sign << 31) | (0xFF << 23) | (mantissa << 13)
	default:
		f32bits = (sign << 31) | ((exp + 127 - 15) << 23) | (mantissa << 13)
	}
	return float64(math.Float32frombits(f32bits))
}
