// SPDX-License-Identifier: AGPL-3.0-or-later

// Package protobufdecode parses raw Protocol Buffers
// wire-format bytes without needing the .proto schema —
// the equivalent of `protoc --decode_raw`. gRPC, Google
// APIs, mobile apps, modern microservices, and Faultier's
// own command framing all carry protobuf bytes; operators
// routinely have hex blobs of unknown messages and want
// the field-number / wire-type / value breakdown without
// hunting down the right .proto file.
//
// # Wrap-vs-native judgement
//
// Native. The Protobuf wire format is fully published
// (developers.google.com/protocol-buffers/docs/encoding).
// Every field begins with a tag = (field_number << 3) |
// wire_type, encoded as a varint. Six wire types dispatch
// to a small set of value parsers: VARINT (0), I64 (1),
// LEN (2, length-prefixed bytes), SGROUP/EGROUP (3/4,
// deprecated), I32 (5). Pasting a hex blob from
// `grpcurl -d` output, a Wireshark gRPC dissector, an
// Android app traffic capture, or an mitmproxy export
// is enough — no .proto, no generated code, no library.
//
// # What this package covers
//
//   - **Tag decoding**: field_number + wire_type extracted
//     from the leading varint of each field.
//   - **Wire type dispatch**:
//   - 0 VARINT — surfaced as both unsigned uint64 and
//     zigzag-decoded int64 (for sint32 / sint64 schema
//     fields). Bool interpretation (0/1) also surfaced
//     when applicable.
//   - 1 I64 — surfaced as raw uint64 + float64
//     interpretation (for double / fixed64 / sfixed64).
//   - 2 LEN — recursively tries to decode the bytes as
//     a nested message; if that succeeds and consumes
//     all bytes, surfaces the nested view. Otherwise
//     falls back to UTF-8 string (if every byte is
//     printable) or raw hex.
//   - 3 SGROUP / 4 EGROUP — deprecated; surfaced by name
//     but no body decode attempted (groups are obsolete).
//   - 5 I32 — surfaced as raw uint32 + float32
//     interpretation (for float / fixed32 / sfixed32).
//   - **Varint reader** with continuation-bit handling and
//     a max-10-byte guard (uint64 max).
//   - **Nested message detection**: for LEN fields, the
//     decoder probes by attempting to parse the payload as
//     a top-level message. If parsing consumes exactly
//     the declared length and every field has a plausible
//     tag, the nested view is preferred over the
//     string/hex fallback.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - **Schema-aware decode**: without the .proto, field
//     names + types are unknown. This decoder surfaces
//     field numbers (1, 2, 3, ...) and wire types — the
//     operator maps those back to the .proto file
//     themselves.
//   - **Packed repeated fields**: a packed repeated of
//     varint / fixed32 / fixed64 is encoded as a single
//     LEN field whose body is a concatenation of values
//     (no per-element tag). Without schema awareness, the
//     LEN body falls through to nested-message / string /
//     hex heuristics; in practice the operator can spot
//     packed repeats by looking at the raw hex.
//   - **gRPC framing**: the 5-byte gRPC HTTP/2 message
//     prefix (1-byte compression flag + 4-byte big-endian
//     length) is the caller's responsibility to strip
//     before passing in.
//   - **Proto 3 default-value semantics** and the wire
//     encoding's "this field is set to default" markers —
//     this is a wire-level decoder, not a semantic one.
package protobufdecode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// Message is the recursive decoded view of one protobuf
// message (a sequence of fields).
type Message struct {
	Fields []*Field `json:"fields,omitempty"`
}

// Field is one tag/wire-type/value triple.
type Field struct {
	FieldNumber  int    `json:"field_number"`
	WireType     int    `json:"wire_type"`
	WireTypeName string `json:"wire_type_name"`

	// At most one of these is populated, depending on wire
	// type + heuristic outcome.
	Uint64        *uint64  `json:"uint64,omitempty"`
	SInt64        *int64   `json:"sint64_zigzag,omitempty"`
	Bool          *bool    `json:"bool,omitempty"`
	Uint32        *uint32  `json:"uint32,omitempty"`
	Float32       *float64 `json:"float32,omitempty"`
	Float64       *float64 `json:"float64,omitempty"`
	String        string   `json:"string,omitempty"`
	BytesHex      string   `json:"bytes_hex,omitempty"`
	NestedMessage *Message `json:"nested_message,omitempty"`
}

// Decode parses a hex-encoded Protobuf message. Trailing
// bytes after the last field are rejected.
func Decode(hexBlob string) (*Message, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses raw Protobuf bytes.
func DecodeBytes(b []byte) (*Message, error) {
	m, used, err := decodeMessage(b, 0)
	if err != nil {
		return nil, err
	}
	if used != len(b) {
		return nil, fmt.Errorf("protobufdecode: %d trailing bytes after last field", len(b)-used)
	}
	return m, nil
}

// decodeMessage walks fields starting at off until limit.
// Returns the message + bytes consumed + error.
func decodeMessage(b []byte, off int) (*Message, int, error) {
	m := &Message{}
	start := off
	for off < len(b) {
		f, used, err := decodeField(b, off)
		if err != nil {
			return nil, 0, err
		}
		m.Fields = append(m.Fields, f)
		off += used
	}
	return m, off - start, nil
}

// decodeField parses one field starting at off.
func decodeField(b []byte, off int) (*Field, int, error) {
	start := off
	tag, used, err := readVarint(b, off)
	if err != nil {
		return nil, 0, fmt.Errorf("tag: %w", err)
	}
	off += used
	fieldNum := int(tag >> 3)
	wireType := int(tag & 0x07)
	f := &Field{
		FieldNumber:  fieldNum,
		WireType:     wireType,
		WireTypeName: wireTypeName(wireType),
	}
	if fieldNum < 1 || fieldNum > (1<<29)-1 {
		return nil, 0, fmt.Errorf("field number %d out of valid range 1..2^29-1", fieldNum)
	}

	switch wireType {
	case 0:
		// VARINT
		val, n, err := readVarint(b, off)
		if err != nil {
			return nil, 0, fmt.Errorf("varint value: %w", err)
		}
		off += n
		uval := val
		f.Uint64 = &uval
		zigzag := int64(val>>1) ^ -int64(val&1) //nolint:gosec // zigzag is documented to alias
		f.SInt64 = &zigzag
		if val == 0 || val == 1 {
			b := val == 1
			f.Bool = &b
		}
	case 1:
		// I64 — fixed 64-bit
		if off+8 > len(b) {
			return nil, 0, fmt.Errorf("I64 truncated at offset %d", off)
		}
		raw := binary.LittleEndian.Uint64(b[off : off+8])
		f.Uint64 = &raw
		flt := math.Float64frombits(raw)
		f.Float64 = &flt
		off += 8
	case 2:
		// LEN — length-prefixed bytes
		length, n, err := readVarint(b, off)
		if err != nil {
			return nil, 0, fmt.Errorf("LEN length: %w", err)
		}
		off += n
		if uint64(off)+length > uint64(len(b)) {
			return nil, 0, fmt.Errorf("LEN value (length %d) exceeds buffer", length)
		}
		body := b[off : off+int(length)]
		// Heuristic: try nested message first.
		if nested, ok := tryDecodeNested(body); ok {
			f.NestedMessage = nested
		} else if isPrintableUTF8(body) {
			f.String = string(body)
		} else {
			f.BytesHex = strings.ToUpper(hex.EncodeToString(body))
		}
		off += int(length)
	case 3:
		// SGROUP — deprecated; no body parse.
	case 4:
		// EGROUP — deprecated; no body parse.
	case 5:
		// I32 — fixed 32-bit
		if off+4 > len(b) {
			return nil, 0, fmt.Errorf("I32 truncated at offset %d", off)
		}
		raw := binary.LittleEndian.Uint32(b[off : off+4])
		f.Uint32 = &raw
		flt := float64(math.Float32frombits(raw))
		f.Float32 = &flt
		off += 4
	default:
		return nil, 0, fmt.Errorf("unknown wire type %d", wireType)
	}
	return f, off - start, nil
}

// tryDecodeNested attempts to parse body as a top-level
// protobuf message. Returns (nested, true) iff the parse
// consumed exactly len(body) AND every field tag is valid.
// Empty body succeeds (zero-field nested message).
func tryDecodeNested(body []byte) (*Message, bool) {
	if len(body) == 0 {
		return &Message{}, true
	}
	m, used, err := decodeMessage(body, 0)
	if err != nil || used != len(body) {
		return nil, false
	}
	return m, true
}

// readVarint reads a single varint starting at off. Returns
// (value, bytes consumed, error). Max varint width is 10
// bytes (uint64 max).
func readVarint(b []byte, off int) (uint64, int, error) {
	var v uint64
	var shift uint
	start := off
	for i := 0; i < 10; i++ {
		if off >= len(b) {
			return 0, 0, fmt.Errorf("varint truncated at offset %d", off)
		}
		c := b[off]
		off++
		v |= uint64(c&0x7F) << shift
		if c < 0x80 {
			return v, off - start, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("varint at offset %d exceeds 10-byte max", start)
}

// isPrintableUTF8 returns true when every byte of b is
// printable UTF-8 (plus tab / newline / carriage return /
// space). Empty input is considered printable.
func isPrintableUTF8(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || c == ' ' {
			continue
		}
		if c < 0x20 {
			return false
		}
		// Allow extended UTF-8 (bytes >= 0x80 form multi-byte
		// sequences which utf8.Valid already verified).
	}
	return true
}

func wireTypeName(wt int) string {
	switch wt {
	case 0:
		return "VARINT"
	case 1:
		return "I64 (fixed64 / sfixed64 / double)"
	case 2:
		return "LEN (string / bytes / embedded message / packed)"
	case 3:
		return "SGROUP (deprecated)"
	case 4:
		return "EGROUP (deprecated)"
	case 5:
		return "I32 (fixed32 / sfixed32 / float)"
	}
	return fmt.Sprintf("Reserved (wire type %d)", wt)
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("protobufdecode: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("protobufdecode: invalid hex: %w", err)
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
