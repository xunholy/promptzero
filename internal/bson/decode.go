// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bson decodes a BSON document (the binary serialization MongoDB stores
// and that `mongodump` writes to `.bson` files) into a structured tree. It is
// the document-format complement to mongodb_decode (which dissects the MongoDB
// *wire protocol* and only shallowly extracts a command name + a few argument
// fields): this fully, recursively decodes a standalone BSON document — every
// element type, nested documents and arrays, ObjectId, dates, binary subtypes,
// regex, timestamps — the way cbor_decode / msgpack_decode handle their
// formats. An operator pastes the hex of a `.bson` record (mongodump loot, a
// stored document, a captured payload) and gets the full structure without a
// MongoDB driver. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. BSON is a fully public, little-endian, length-prefixed format
// (bsonspec.org v1.1): a document is an int32 byte-length, a sequence of
// typed elements (type byte + NUL-terminated name + type-specific value), and a
// 0x00 terminator. It is a recursive-descent walk over a byte cursor; there is
// nothing to wrap, and adding go.mongodb.org/mongo-driver/bson as a runtime
// dependency to decode untrusted bytes is unwarranted. Consistent with
// internal/cbordecode, internal/msgpack, and internal/protobufdecode owning
// their parse in-tree.
//
// # Verifiable / no confidently-wrong output
//
// Strongest verification class — every element type is gated byte-for-byte
// against vectors produced by the reference PyMongo `bson` library (double,
// string, embedded doc, array, binary + subtype, ObjectId, bool, UTC datetime,
// null, regex, int32, timestamp, int64, decimal128, min/max key, and a nested
// doc+array). A truncated/malformed document is rejected with an error (never a
// partial/guessed decode), nesting is depth-capped, and length fields are
// bounds-checked against the buffer.
//
// # Covered / deferred
//
// Covered: all current BSON element types, including Decimal128 (0x13) decoded
// from its IEEE 754-2008 Binary-Integer-Decimal form to sign + 113-bit
// coefficient + biased exponent and an exact plain (non-scientific) decimal
// string, with NaN / ±Infinity surfaced as such (the raw 16 bytes are also kept
// for traceability). The deprecated DBPointer (0x0C) and Symbol (0x0E) and
// JavaScript-code-with-scope (0x0F) are decoded structurally.
package bson

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"
)

// Field is one named element of a BSON document (order-preserving).
type Field struct {
	Name  string `json:"name"`
	Value *Value `json:"value"`
}

// Value is one decoded BSON value.
type Value struct {
	Type string `json:"type"`

	Double *float64 `json:"double,omitempty"`
	Str    *string  `json:"string,omitempty"`
	Doc    []*Field `json:"document,omitempty"`
	Array  []*Value `json:"array,omitempty"`

	BinarySubtype     *int   `json:"binary_subtype,omitempty"`
	BinarySubtypeName string `json:"binary_subtype_name,omitempty"`
	BytesHex          string `json:"bytes_hex,omitempty"`

	ObjectID string `json:"object_id,omitempty"`
	Bool     *bool  `json:"bool,omitempty"`

	DateTime   string `json:"datetime,omitempty"` // RFC 3339 (UTC)
	DateUnixMS *int64 `json:"date_unix_ms,omitempty"`

	Int32 *int32 `json:"int32,omitempty"`
	Int64 *int64 `json:"int64,omitempty"`

	TimestampSeconds   *uint32 `json:"timestamp_seconds,omitempty"`
	TimestampIncrement *uint32 `json:"timestamp_increment,omitempty"`

	RegexPattern *string `json:"regex_pattern,omitempty"`
	RegexOptions *string `json:"regex_options,omitempty"`

	Code   *string `json:"code,omitempty"`
	Symbol *string `json:"symbol,omitempty"`

	Decimal128Hex         string `json:"decimal128_hex,omitempty"`
	Decimal128            string `json:"decimal128,omitempty"` // plain value, or NaN / ±Infinity
	Decimal128Coefficient string `json:"decimal128_coefficient,omitempty"`
	Decimal128Exponent    *int   `json:"decimal128_exponent,omitempty"`

	Note string `json:"note,omitempty"`
}

// Result is the decoded top-level document plus framing metadata.
type Result struct {
	Document      []*Field `json:"document"`
	TotalBytes    int      `json:"total_bytes"`
	TrailingHex   string   `json:"trailing_bytes_hex,omitempty"`
	TrailingCount int      `json:"trailing_bytes,omitempty"`
}

// Decode parses the hex of a BSON document (separators and an optional 0x
// prefix tolerated).
func Decode(hexBlob string) (*Result, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a BSON document from raw bytes.
func DecodeBytes(b []byte) (*Result, error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("bson: document needs >= 5 bytes (int32 length + terminator), got %d", len(b))
	}
	d := &decoder{buf: b}
	fields, n, err := d.document(b, 0)
	if err != nil {
		return nil, err
	}
	r := &Result{Document: fields, TotalBytes: n}
	if n < len(b) {
		r.TrailingCount = len(b) - n
		r.TrailingHex = strings.ToUpper(hex.EncodeToString(b[n:]))
	}
	return r, nil
}

const maxDepth = 64

type decoder struct{ buf []byte }

// document parses a BSON document from doc and returns its fields and the
// number of bytes it occupies (the leading int32 length).
func (d *decoder) document(doc []byte, depth int) ([]*Field, int, error) {
	if depth > maxDepth {
		return nil, 0, fmt.Errorf("bson: nesting deeper than %d", maxDepth)
	}
	if len(doc) < 5 {
		return nil, 0, fmt.Errorf("bson: truncated document (need >= 5 bytes)")
	}
	docLen := int(binary.LittleEndian.Uint32(doc[0:4]))
	if docLen < 5 || docLen > len(doc) {
		return nil, 0, fmt.Errorf("bson: document length %d out of range (have %d bytes)", docLen, len(doc))
	}
	if doc[docLen-1] != 0x00 {
		return nil, 0, fmt.Errorf("bson: document not NUL-terminated at offset %d", docLen-1)
	}
	var fields []*Field
	off := 4
	for off < docLen-1 {
		t := doc[off]
		off++
		nameEnd, err := cstringEnd(doc, off, docLen-1)
		if err != nil {
			return nil, 0, err
		}
		name := string(doc[off:nameEnd])
		off = nameEnd + 1
		v, consumed, err := d.value(t, doc[off:docLen-1], depth)
		if err != nil {
			return nil, 0, err
		}
		off += consumed
		fields = append(fields, &Field{Name: name, Value: v})
	}
	if off != docLen-1 {
		return nil, 0, fmt.Errorf("bson: element walk ended at %d, expected %d", off, docLen-1)
	}
	return fields, docLen, nil
}

// value decodes a single element value of type t from the bytes b (which run to
// the end of the enclosing document, excluding its terminator). It returns the
// value and how many bytes it consumed.
func (d *decoder) value(t byte, b []byte, depth int) (*Value, int, error) {
	switch t {
	case 0x01: // double
		raw, err := need(b, 8)
		if err != nil {
			return nil, 0, err
		}
		f := math.Float64frombits(binary.LittleEndian.Uint64(raw))
		return &Value{Type: "double", Double: &f}, 8, nil
	case 0x02, 0x0D, 0x0E: // string / JavaScript code / symbol
		s, n, err := bsonString(b)
		if err != nil {
			return nil, 0, err
		}
		v := &Value{}
		switch t {
		case 0x02:
			v.Type, v.Str = "string", &s
		case 0x0D:
			v.Type, v.Code = "javascript", &s
		case 0x0E:
			v.Type, v.Symbol = "symbol", &s
		}
		return v, n, nil
	case 0x03: // embedded document
		fields, n, err := d.document(b, depth+1)
		if err != nil {
			return nil, 0, err
		}
		return &Value{Type: "document", Doc: fields}, n, nil
	case 0x04: // array
		fields, n, err := d.document(b, depth+1)
		if err != nil {
			return nil, 0, err
		}
		arr := make([]*Value, 0, len(fields))
		for _, f := range fields {
			arr = append(arr, f.Value)
		}
		return &Value{Type: "array", Array: arr}, n, nil
	case 0x05: // binary
		return bsonBinary(b)
	case 0x06: // undefined (deprecated)
		return &Value{Type: "undefined"}, 0, nil
	case 0x07: // ObjectId
		raw, err := need(b, 12)
		if err != nil {
			return nil, 0, err
		}
		return &Value{Type: "objectId", ObjectID: hex.EncodeToString(raw)}, 12, nil
	case 0x08: // boolean
		raw, err := need(b, 1)
		if err != nil {
			return nil, 0, err
		}
		bl := raw[0] != 0
		return &Value{Type: "bool", Bool: &bl}, 1, nil
	case 0x09: // UTC datetime (int64 ms since epoch)
		raw, err := need(b, 8)
		if err != nil {
			return nil, 0, err
		}
		ms := int64(binary.LittleEndian.Uint64(raw))
		return &Value{
			Type: "datetime", DateUnixMS: &ms,
			DateTime: time.UnixMilli(ms).UTC().Format(time.RFC3339Nano),
		}, 8, nil
	case 0x0A: // null
		return &Value{Type: "null"}, 0, nil
	case 0x0B: // regex (two cstrings)
		return bsonRegex(b)
	case 0x0C: // DBPointer (deprecated): string + 12-byte ObjectId
		s, n, err := bsonString(b)
		if err != nil {
			return nil, 0, err
		}
		raw, err := need(b[n:], 12)
		if err != nil {
			return nil, 0, err
		}
		return &Value{Type: "dbpointer", Str: &s, ObjectID: hex.EncodeToString(raw)}, n + 12, nil
	case 0x0F: // JavaScript code with scope: int32 totalLen + string + document
		if len(b) < 4 {
			return nil, 0, fmt.Errorf("bson: truncated code-with-scope")
		}
		total := int(binary.LittleEndian.Uint32(b[0:4]))
		if total < 4 || total > len(b) {
			return nil, 0, fmt.Errorf("bson: code-with-scope length out of range")
		}
		s, sn, err := bsonString(b[4:total])
		if err != nil {
			return nil, 0, err
		}
		fields, _, err := d.document(b[4+sn:total], depth+1)
		if err != nil {
			return nil, 0, err
		}
		return &Value{Type: "javascript_with_scope", Code: &s, Doc: fields}, total, nil
	case 0x10: // int32
		raw, err := need(b, 4)
		if err != nil {
			return nil, 0, err
		}
		i := int32(binary.LittleEndian.Uint32(raw))
		return &Value{Type: "int32", Int32: &i}, 4, nil
	case 0x11: // timestamp (uint32 increment, uint32 seconds; both LE)
		raw, err := need(b, 8)
		if err != nil {
			return nil, 0, err
		}
		inc := binary.LittleEndian.Uint32(raw[0:4])
		sec := binary.LittleEndian.Uint32(raw[4:8])
		return &Value{Type: "timestamp", TimestampIncrement: &inc, TimestampSeconds: &sec}, 8, nil
	case 0x12: // int64
		raw, err := need(b, 8)
		if err != nil {
			return nil, 0, err
		}
		i := int64(binary.LittleEndian.Uint64(raw))
		return &Value{Type: "int64", Int64: &i}, 8, nil
	case 0x13: // decimal128 (16 bytes, IEEE 754-2008 BID)
		raw, err := need(b, 16)
		if err != nil {
			return nil, 0, err
		}
		v := &Value{Type: "decimal128", Decimal128Hex: strings.ToUpper(hex.EncodeToString(raw))}
		decodeDecimal128(v, raw)
		return v, 16, nil
	case 0xFF: // min key
		return &Value{Type: "minKey"}, 0, nil
	case 0x7F: // max key
		return &Value{Type: "maxKey"}, 0, nil
	}
	return nil, 0, fmt.Errorf("bson: unknown element type 0x%02x", t)
}

// decodeDecimal128 decodes the 16 little-endian bytes of a BSON Decimal128
// (IEEE 754-2008 decimal128, Binary Integer Decimal encoding) into a sign +
// 113-bit coefficient + 14-bit biased exponent, and renders the exact value as
// a plain (non-scientific) decimal string. NaN / ±Infinity are surfaced as
// such. The "11" combination form (coefficient ≥ 10^34) is, per the spec,
// treated as a zero coefficient.
func decodeDecimal128(v *Value, raw []byte) {
	lo := binary.LittleEndian.Uint64(raw[0:8])
	hi := binary.LittleEndian.Uint64(raw[8:16])
	neg := hi>>63&1 == 1

	switch {
	case hi&0x7c00000000000000 == 0x7c00000000000000: // combination 11111 → NaN
		v.Decimal128 = "NaN"
		return
	case hi&0x7800000000000000 == 0x7800000000000000: // combination 11110 → Infinity
		if neg {
			v.Decimal128 = "-Infinity"
		} else {
			v.Decimal128 = "Infinity"
		}
		return
	}

	var coeffHi uint64
	var exp int
	if hi>>61&3 == 3 { // G0 G1 = 11: implied coefficient ≥ 10^34 → zero (IEEE 754)
		exp = int((hi>>47)&0x3fff) - 6176
		coeffHi, lo = 0, 0
	} else {
		exp = int((hi>>49)&0x3fff) - 6176
		coeffHi = hi & 0x0001ffffffffffff // bits 112..64 of the coefficient
	}

	c := new(big.Int).SetUint64(coeffHi)
	c.Lsh(c, 64)
	c.Or(c, new(big.Int).SetUint64(lo))
	coeff := c.String()

	v.Decimal128Coefficient = coeff
	e := exp
	v.Decimal128Exponent = &e
	v.Decimal128 = formatDecimal128(neg, coeff, exp)
}

// formatDecimal128 renders coefficient × 10^exp as an exact plain decimal
// string (no scientific notation — so trailing zeros and scale are preserved
// exactly, since Decimal128 is unnormalized).
func formatDecimal128(neg bool, digits string, exp int) string {
	var s string
	switch {
	case exp >= 0:
		s = digits + strings.Repeat("0", exp)
	case len(digits) > -exp:
		p := len(digits) + exp
		s = digits[:p] + "." + digits[p:]
	default:
		s = "0." + strings.Repeat("0", -exp-len(digits)) + digits
	}
	if neg {
		s = "-" + s
	}
	return s
}

// bsonString reads an int32-length-prefixed UTF-8 string (with a trailing NUL).
func bsonString(b []byte) (string, int, error) {
	if len(b) < 4 {
		return "", 0, fmt.Errorf("bson: truncated string length")
	}
	l := int(binary.LittleEndian.Uint32(b[0:4]))
	if l < 1 || 4+l > len(b) {
		return "", 0, fmt.Errorf("bson: string length %d out of range", l)
	}
	if b[4+l-1] != 0x00 {
		return "", 0, fmt.Errorf("bson: string not NUL-terminated")
	}
	s := string(b[4 : 4+l-1])
	if !utf8.ValidString(s) {
		return "", 0, fmt.Errorf("bson: string is not valid UTF-8")
	}
	return s, 4 + l, nil
}

func bsonBinary(b []byte) (*Value, int, error) {
	if len(b) < 5 {
		return nil, 0, fmt.Errorf("bson: truncated binary")
	}
	l := int(binary.LittleEndian.Uint32(b[0:4]))
	sub := int(b[4])
	if l < 0 || 5+l > len(b) {
		return nil, 0, fmt.Errorf("bson: binary length %d out of range", l)
	}
	return &Value{
		Type: "binary", BinarySubtype: &sub, BinarySubtypeName: binarySubtypeName(b[4]),
		BytesHex: strings.ToUpper(hex.EncodeToString(b[5 : 5+l])),
	}, 5 + l, nil
}

func bsonRegex(b []byte) (*Value, int, error) {
	patEnd, err := cstringEnd(b, 0, len(b))
	if err != nil {
		return nil, 0, fmt.Errorf("bson: regex pattern: %w", err)
	}
	optEnd, err := cstringEnd(b, patEnd+1, len(b))
	if err != nil {
		return nil, 0, fmt.Errorf("bson: regex options: %w", err)
	}
	pat := string(b[:patEnd])
	opt := string(b[patEnd+1 : optEnd])
	return &Value{Type: "regex", RegexPattern: &pat, RegexOptions: &opt}, optEnd + 1, nil
}

// cstringEnd returns the index of the NUL terminating a cstring starting at
// off, searching up to limit.
func cstringEnd(b []byte, off, limit int) (int, error) {
	for i := off; i < limit; i++ {
		if b[i] == 0x00 {
			return i, nil
		}
	}
	return 0, fmt.Errorf("bson: unterminated cstring at offset %d", off)
}

func need(b []byte, n int) ([]byte, error) {
	if len(b) < n {
		return nil, fmt.Errorf("bson: truncated value: need %d bytes, have %d", n, len(b))
	}
	return b[:n], nil
}

func binarySubtypeName(s byte) string {
	switch s {
	case 0x00:
		return "generic"
	case 0x01:
		return "function"
	case 0x02:
		return "binary (old)"
	case 0x03:
		return "UUID (old)"
	case 0x04:
		return "UUID"
	case 0x05:
		return "MD5"
	case 0x06:
		return "encrypted (CSFLE)"
	case 0x07:
		return "compressed"
	}
	if s >= 0x80 {
		return "user-defined"
	}
	return ""
}

// parseHex strips common separators / 0x prefix and decodes a hex string.
func parseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "",
		":", "", "-", "", "_", "", "0x", "", "0X", "").Replace(s)
	if s == "" {
		return nil, fmt.Errorf("bson: empty input")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("bson: hex has odd length")
	}
	return hex.DecodeString(s)
}
