// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cbordecode parses CBOR (Concise Binary Object
// Representation) per RFC 8949. CBOR is the binary JSON-like
// format used by COSE (signed/encrypted JWT alternative),
// WebAuthn / CTAP (FIDO2 hardware-token transport), Bluetooth
// Mesh, CoAP IoT payloads, MQTT-SN attribute encoding, and
// the "self-describing binary" of choice for any IoT /
// constrained-device flow since ~2014.
//
// # Wrap-vs-native judgement
//
// Native. CBOR is fully published in RFC 8949 with a clean
// 8-major-type scheme + a small dispatch table for the
// "additional information" sub-field that encodes either a
// direct argument value (0-23), a 1/2/4/8-byte argument
// (24/25/26/27), or an indefinite-length marker (31).
// Tagged values (major type 6) and simple values (major type
// 7) round out the model. Pasting a hex blob from a WebAuthn
// authenticator response, a CTAP request, a CoAP body, or
// any CBOR-emitting IoT device is enough — no library, no
// network, no key material.
//
// # What this package covers
//
//   - **8 major types** per RFC 8949 §3:
//   - 0 unsigned integer (0..2^64-1).
//   - 1 negative integer (-1..-2^64).
//   - 2 byte string (rendered as hex; indefinite chunks
//     concatenated).
//   - 3 text string (UTF-8; indefinite chunks concatenated).
//   - 4 array (recursive).
//   - 5 map (recursive; rendered as ordered list of
//     key/value pairs to preserve duplicate keys + key
//     ordering).
//   - 6 tagged value (semantic tag + nested value, with
//     a ~30-entry well-known tag-name table).
//   - 7 simple value / float:
//   - 20 false / 21 true / 22 null / 23 undefined.
//   - 24 simple value (1-byte argument).
//   - 25 IEEE 754 half-precision float.
//   - 26 IEEE 754 single-precision float.
//   - 27 IEEE 754 double-precision float.
//   - 31 "break" stop code (for indefinite-length
//     containers).
//   - **Argument encoding** (low 5 bits of initial byte):
//     0..23 direct, 24 = 1-byte uint8 follows, 25 = 2-byte
//     uint16, 26 = 4-byte uint32, 27 = 8-byte uint64, 31 =
//     indefinite-length marker (for byte strings / text
//     strings / arrays / maps).
//   - **Indefinite-length containers**: byte/text-string
//     chunks concatenated until 0xFF break; arrays / maps
//     walk children until the same break code.
//   - **Tagged values**: ~30-entry well-known tag table
//     covering the RFC 8949 §3.4 standard tags (0 RFC 3339
//     date-time string / 1 epoch-time / 2/3 unsigned/negative
//     bignum / 4 decimal fraction / 5 bigfloat / 21/22/23
//     expected-base64url/base64/base16 / 24 encoded CBOR
//     data / 32 URI / 33 base64url text / 34 base64 text /
//     35 regex / 36 MIME / 55799 self-describe-CBOR magic),
//     plus the COSE tags (16 Encrypt0 / 17 Mac0 / 18 Sign1 /
//     96 Encrypt / 97 Mac / 98 Sign) and the WebAuthn
//     CTAP-specific tag 24 (encoded-CBOR-data-item).
//   - **Floats**: IEEE 754 half precision (16-bit), single
//     (32-bit), and double (64-bit) with NaN / Inf detection.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - COSE message body decode beyond the tag — the wrapped
//     COSE_Encrypt0 / COSE_Sign1 / etc. structures are
//     arrays whose contents are themselves CBOR; the outer
//     tag + array is decoded, but COSE-specific
//     semantics (protected header / unprotected header /
//     payload / signature) are not interpreted as named
//     fields.
//   - WebAuthn / CTAP request-body schema knowledge — the
//     CBOR is decoded as a map, but the field meanings
//     (authData / publicKey / clientDataJSON / etc.) are
//     not annotated.
//   - Strict mode validation (RFC 8949 §3.1 well-formed +
//     §5.4 deterministic encoding) — we accept any well-
//     formed input even if not minimally encoded; explicit
//     non-conforming inputs (e.g. arg 24 with value < 24)
//     are decoded as-is.
//   - CDDL (Concise Data Definition Language, RFC 8610)
//     schema validation — pure decode only.
package cbordecode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// Value is the recursive decoded view of one CBOR data item.
//
// Only the fields that match MajorType are populated; the
// others are zero/nil.
type Value struct {
	MajorType  int         `json:"major_type"`
	MajorName  string      `json:"major_name"`
	Uint       *uint64     `json:"uint,omitempty"`
	Int        *int64      `json:"int,omitempty"`
	Bytes      string      `json:"bytes_hex,omitempty"`
	Text       string      `json:"text,omitempty"`
	Array      []*Value    `json:"array,omitempty"`
	Map        []*MapEntry `json:"map,omitempty"`
	Tag        *uint64     `json:"tag,omitempty"`
	TagName    string      `json:"tag_name,omitempty"`
	TagValue   *Value      `json:"tag_value,omitempty"`
	Simple     *uint8      `json:"simple_value,omitempty"`
	SimpleName string      `json:"simple_name,omitempty"`
	Float      *float64    `json:"float,omitempty"`
	FloatSpec  string      `json:"float_special,omitempty"`
	Indefinite bool        `json:"indefinite,omitempty"`
}

// MapEntry is one CBOR map key/value pair.
type MapEntry struct {
	Key   *Value `json:"key"`
	Value *Value `json:"value"`
}

// Decode parses a hex-encoded CBOR data item. Trailing bytes
// after the first item are rejected.
func Decode(hexBlob string) (*Value, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw CBOR byte buffer into a single
// data item. Use DecodeStream if multiple items are expected.
func DecodeBytes(b []byte) (*Value, error) {
	v, used, err := decodeItem(b, 0)
	if err != nil {
		return nil, err
	}
	if used != len(b) {
		return nil, fmt.Errorf("cbordecode: %d trailing bytes after first item", len(b)-used)
	}
	return v, nil
}

// breakValue is the singleton "break" code (0xFF) sentinel
// for indefinite-length container termination.
var breakValue = &Value{MajorType: 7, MajorName: "Float / Simple", Simple: u8ptr(31), SimpleName: "break"}

// decodeItem parses one CBOR data item starting at offset
// off and returns (parsed Value, bytes consumed, error).
func decodeItem(b []byte, off int) (*Value, int, error) {
	if off >= len(b) {
		return nil, 0, fmt.Errorf("CBOR ran off end at offset %d", off)
	}
	start := off
	ib := b[off]
	major := int(ib >> 5)
	additional := int(ib & 0x1F)

	v := &Value{MajorType: major, MajorName: majorTypeName(major)}

	// Indefinite-length marker.
	if additional == 31 {
		off++ // consume initial byte
		switch major {
		case 2:
			text, n, err := readIndefiniteByteString(b, off)
			if err != nil {
				return nil, 0, err
			}
			v.Indefinite = true
			v.Bytes = text
			return v, (off - start) + n, nil
		case 3:
			s, n, err := readIndefiniteTextString(b, off)
			if err != nil {
				return nil, 0, err
			}
			v.Indefinite = true
			v.Text = s
			return v, (off - start) + n, nil
		case 4:
			arr, n, err := readIndefiniteArray(b, off)
			if err != nil {
				return nil, 0, err
			}
			v.Indefinite = true
			v.Array = arr
			return v, (off - start) + n, nil
		case 5:
			m, n, err := readIndefiniteMap(b, off)
			if err != nil {
				return nil, 0, err
			}
			v.Indefinite = true
			v.Map = m
			return v, (off - start) + n, nil
		case 7:
			// "break" stop code (0xFF).
			return breakValue, 1, nil
		default:
			return nil, 0, fmt.Errorf("indefinite-length not allowed for major type %d", major)
		}
	}

	// Definite-length: read argument (advances off past the
	// initial byte + 0..8 arg bytes).
	arg, argBytes, err := readArgument(b, off, additional)
	if err != nil {
		return nil, 0, err
	}
	off += argBytes

	switch major {
	case 0:
		v.Uint = u64ptr(arg)
	case 1:
		// Negative: -1 - arg. For arg = MaxUint64 the result
		// overflows int64; surface the truncated value.
		neg := -1 - int64(arg) //nolint:gosec // documented overflow case
		v.Int = &neg
	case 2:
		if off+int(arg) > len(b) {
			return nil, 0, fmt.Errorf("byte string length %d exceeds remaining buffer", arg)
		}
		v.Bytes = strings.ToUpper(hex.EncodeToString(b[off : off+int(arg)]))
		off += int(arg)
	case 3:
		if off+int(arg) > len(b) {
			return nil, 0, fmt.Errorf("text string length %d exceeds remaining buffer", arg)
		}
		v.Text = string(b[off : off+int(arg)])
		off += int(arg)
	case 4:
		v.Array = make([]*Value, 0, int(arg))
		for i := uint64(0); i < arg; i++ {
			child, used, err := decodeItem(b, off)
			if err != nil {
				return nil, 0, fmt.Errorf("array element %d: %w", i, err)
			}
			v.Array = append(v.Array, child)
			off += used
		}
	case 5:
		v.Map = make([]*MapEntry, 0, int(arg))
		for i := uint64(0); i < arg; i++ {
			key, used1, err := decodeItem(b, off)
			if err != nil {
				return nil, 0, fmt.Errorf("map entry %d key: %w", i, err)
			}
			off += used1
			val, used2, err := decodeItem(b, off)
			if err != nil {
				return nil, 0, fmt.Errorf("map entry %d value: %w", i, err)
			}
			off += used2
			v.Map = append(v.Map, &MapEntry{Key: key, Value: val})
		}
	case 6:
		v.Tag = u64ptr(arg)
		v.TagName = tagName(arg)
		inner, used, err := decodeItem(b, off)
		if err != nil {
			return nil, 0, fmt.Errorf("tagged value contents: %w", err)
		}
		v.TagValue = inner
		off += used
	case 7:
		switch additional {
		case 25:
			// argBytes = 3 (1 initial + 2 arg). The 2 arg
			// bytes are at b[start+1:start+3].
			f := decodeFloat16(b[start+1 : start+3])
			setFloat(v, f)
		case 26:
			f := float64(math.Float32frombits(uint32(arg)))
			setFloat(v, f)
		case 27:
			f := math.Float64frombits(arg)
			setFloat(v, f)
		default:
			val := uint8(arg)
			v.Simple = &val
			v.SimpleName = simpleValueName(val)
		}
	default:
		return nil, 0, fmt.Errorf("major type %d out of 0..7", major)
	}
	return v, off - start, nil
}

// readArgument reads the additional-information argument for
// a CBOR data item. ibIdx is the offset of the initial byte;
// additional is the low 5 bits. Returns (value, total-bytes-
// consumed-including-initial-byte, error).
func readArgument(b []byte, ibIdx, additional int) (uint64, int, error) {
	if additional < 24 {
		return uint64(additional), 1, nil
	}
	off := ibIdx + 1
	switch additional {
	case 24:
		if off+1 > len(b) {
			return 0, 0, fmt.Errorf("1-byte argument truncated")
		}
		return uint64(b[off]), 2, nil
	case 25:
		if off+2 > len(b) {
			return 0, 0, fmt.Errorf("2-byte argument truncated")
		}
		return uint64(binary.BigEndian.Uint16(b[off : off+2])), 3, nil
	case 26:
		if off+4 > len(b) {
			return 0, 0, fmt.Errorf("4-byte argument truncated")
		}
		return uint64(binary.BigEndian.Uint32(b[off : off+4])), 5, nil
	case 27:
		if off+8 > len(b) {
			return 0, 0, fmt.Errorf("8-byte argument truncated")
		}
		return binary.BigEndian.Uint64(b[off : off+8]), 9, nil
	case 28, 29, 30:
		return 0, 0, fmt.Errorf("reserved additional-information value %d", additional)
	}
	return 0, 0, fmt.Errorf("invalid additional %d", additional)
}

// readIndefiniteByteString concatenates byte-string chunks
// until a 0xFF break code.
func readIndefiniteByteString(b []byte, off int) (string, int, error) {
	startOff := off
	var out []byte
	for {
		if off >= len(b) {
			return "", 0, fmt.Errorf("indefinite byte string missing break")
		}
		if b[off] == 0xFF {
			off++
			break
		}
		// Must be a definite-length byte string (major 2).
		if b[off]>>5 != 2 {
			return "", 0, fmt.Errorf("indefinite byte string chunk must be major 2; got major %d", b[off]>>5)
		}
		chunk, used, err := decodeItem(b, off)
		if err != nil {
			return "", 0, err
		}
		raw, err := hex.DecodeString(chunk.Bytes)
		if err != nil {
			return "", 0, err
		}
		out = append(out, raw...)
		off += used
	}
	return strings.ToUpper(hex.EncodeToString(out)), off - startOff, nil
}

// readIndefiniteTextString concatenates text-string chunks
// until 0xFF break.
func readIndefiniteTextString(b []byte, off int) (string, int, error) {
	startOff := off
	var sb strings.Builder
	for {
		if off >= len(b) {
			return "", 0, fmt.Errorf("indefinite text string missing break")
		}
		if b[off] == 0xFF {
			off++
			break
		}
		if b[off]>>5 != 3 {
			return "", 0, fmt.Errorf("indefinite text string chunk must be major 3; got major %d", b[off]>>5)
		}
		chunk, used, err := decodeItem(b, off)
		if err != nil {
			return "", 0, err
		}
		sb.WriteString(chunk.Text)
		off += used
	}
	return sb.String(), off - startOff, nil
}

// readIndefiniteArray reads children until break.
func readIndefiniteArray(b []byte, off int) ([]*Value, int, error) {
	startOff := off
	var out []*Value
	for {
		if off >= len(b) {
			return nil, 0, fmt.Errorf("indefinite array missing break")
		}
		if b[off] == 0xFF {
			off++
			break
		}
		child, used, err := decodeItem(b, off)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, child)
		off += used
	}
	return out, off - startOff, nil
}

// readIndefiniteMap reads key/value pairs until break.
func readIndefiniteMap(b []byte, off int) ([]*MapEntry, int, error) {
	startOff := off
	var out []*MapEntry
	for {
		if off >= len(b) {
			return nil, 0, fmt.Errorf("indefinite map missing break")
		}
		if b[off] == 0xFF {
			off++
			break
		}
		key, used1, err := decodeItem(b, off)
		if err != nil {
			return nil, 0, err
		}
		off += used1
		if off >= len(b) || b[off] == 0xFF {
			return nil, 0, fmt.Errorf("indefinite map has key without value")
		}
		val, used2, err := decodeItem(b, off)
		if err != nil {
			return nil, 0, err
		}
		off += used2
		out = append(out, &MapEntry{Key: key, Value: val})
	}
	return out, off - startOff, nil
}

// decodeFloat16 decodes an IEEE 754 half-precision float
// per RFC 8949 §D.3.
func decodeFloat16(b []byte) float64 {
	if len(b) < 2 {
		return 0
	}
	half := binary.BigEndian.Uint16(b)
	exp := (half >> 10) & 0x1F
	mant := half & 0x3FF
	var val float64
	switch exp {
	case 0:
		val = math.Ldexp(float64(mant), -24)
	case 31:
		if mant == 0 {
			val = math.Inf(1)
		} else {
			val = math.NaN()
		}
	default:
		val = math.Ldexp(float64(mant+1024), int(exp)-25)
	}
	if half&0x8000 != 0 {
		val = -val
	}
	return val
}

func setFloat(v *Value, f float64) {
	v.Float = &f
	switch {
	case math.IsNaN(f):
		v.FloatSpec = "NaN"
	case math.IsInf(f, 1):
		v.FloatSpec = "+Inf"
	case math.IsInf(f, -1):
		v.FloatSpec = "-Inf"
	}
}

func majorTypeName(m int) string {
	switch m {
	case 0:
		return "Unsigned Integer"
	case 1:
		return "Negative Integer"
	case 2:
		return "Byte String"
	case 3:
		return "Text String"
	case 4:
		return "Array"
	case 5:
		return "Map"
	case 6:
		return "Tagged Value"
	case 7:
		return "Float / Simple"
	}
	return ""
}

// tagName labels well-known CBOR tags per RFC 8949 §3.4 +
// IANA CBOR Tags registry + the COSE / CTAP / WebAuthn
// vendor tags operators routinely encounter.
func tagName(t uint64) string {
	switch t {
	case 0:
		return "Standard date/time string (RFC 3339)"
	case 1:
		return "Epoch-based date/time (numeric)"
	case 2:
		return "Positive bignum (RFC 8949 §3.4.3)"
	case 3:
		return "Negative bignum"
	case 4:
		return "Decimal fraction"
	case 5:
		return "Bigfloat"
	case 16:
		return "COSE_Encrypt0 (RFC 9052)"
	case 17:
		return "COSE_Mac0 (RFC 9052)"
	case 18:
		return "COSE_Sign1 (RFC 9052)"
	case 19:
		return "COSE_Countersignature"
	case 21:
		return "Expected conversion to base64url encoding"
	case 22:
		return "Expected conversion to base64 encoding"
	case 23:
		return "Expected conversion to base16 (hex) encoding"
	case 24:
		return "Encoded CBOR data item (CTAP / WebAuthn nested)"
	case 27:
		return "Serialised language-independent object (PartialOrder)"
	case 28:
		return "Mark value as shared"
	case 29:
		return "Reference nth previously marked value"
	case 30:
		return "Rational number"
	case 32:
		return "URI (RFC 3986)"
	case 33:
		return "base64url text encoded string (RFC 4648)"
	case 34:
		return "base64 text encoded string"
	case 35:
		return "Regular expression (PCRE)"
	case 36:
		return "MIME message (RFC 2045)"
	case 37:
		return "Binary UUID (RFC 4122)"
	case 38:
		return "Language-tagged string (BCP 47)"
	case 96:
		return "COSE_Encrypt (RFC 9052)"
	case 97:
		return "COSE_Mac (RFC 9052)"
	case 98:
		return "COSE_Sign (RFC 9052)"
	case 100:
		return "Number of days since 1970-01-01 (RFC 8943)"
	case 1004:
		return "Full-date string (RFC 3339)"
	case 1040:
		return "Multidimensional array (row-major)"
	case 55799:
		return "Self-describe CBOR magic"
	}
	return ""
}

// simpleValueName labels the documented simple values
// (RFC 8949 §3.3).
func simpleValueName(v uint8) string {
	switch v {
	case 20:
		return "false"
	case 21:
		return "true"
	case 22:
		return "null"
	case 23:
		return "undefined"
	case 31:
		return "break"
	}
	return ""
}

func u8ptr(v uint8) *uint8    { return &v }
func u64ptr(v uint64) *uint64 { return &v }

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("cbordecode: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cbordecode: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
