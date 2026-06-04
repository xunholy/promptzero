// SPDX-License-Identifier: AGPL-3.0-or-later

// Package msgpack decodes a MessagePack-encoded value to a structured tree —
// the compact binary serialization (https://msgpack.org) used by Redis
// internals, msgpack-RPC, many web/API backends, mobile sync protocols, and
// game-server traffic. It is the binary-serialization sibling of cbor_decode:
// an operator pastes the hex of a captured msgpack blob (from a packet dump, a
// cache value, a stored token) and gets the decoded structure without writing a
// throwaway script. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. MessagePack is a fully public, byte-oriented format
// (github.com/msgpack/msgpack spec.md) — a one-byte type tag selecting a fixed
// family (fixint / fixstr / fixarray / fixmap, nil/bool, bin, ext, the
// big-endian uint/int/float widths, and the str/array/map length-prefixed
// forms). It is a recursive-descent walk over a byte cursor; there is nothing
// to wrap, and adding github.com/vmihailenco/msgpack as a runtime dependency to
// decode untrusted bytes is unwarranted. Consistent with internal/cbordecode
// and internal/protobufdecode owning their parse in-tree.
//
// # Verifiable / no confidently-wrong output
//
// Strongest verification class — every format family is gated byte-for-byte
// against vectors produced by the reference `msgpack` Python library (nil/bool,
// fixint / negative fixint, uint8..uint64, int8..int64, float32/float64,
// fixstr / str8, bin8, fixarray, fixmap, fixext4, and a nested map/array). A
// truncated or malformed blob is rejected with an error (never a partial/guessed
// decode), the reserved 0xc1 tag is rejected, and any trailing bytes after the
// top-level value are surfaced as trailing_bytes_hex rather than ignored.
//
// # Covered / deferred
//
// Covered: all MessagePack core types. Deferred: the Timestamp extension (ext
// type -1) is surfaced as a raw ext (type + data hex) rather than decoded into a
// time — its 32/64/96-bit variants are a clean follow-up; surfacing raw avoids a
// confidently-wrong time. Invalid-UTF-8 str payloads are surfaced as hex with a
// note instead of an invalid string.
package msgpack

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// Value is one decoded MessagePack value.
type Value struct {
	Type   string `json:"type"`
	Format string `json:"format"`

	Bool  *bool    `json:"bool,omitempty"`
	Int   *int64   `json:"int,omitempty"`
	Uint  *uint64  `json:"uint,omitempty"`
	Float *float64 `json:"float,omitempty"`
	Str   *string  `json:"str,omitempty"`
	// BytesHex carries a bin payload, or a str payload that is not valid UTF-8.
	BytesHex string `json:"bytes_hex,omitempty"`
	Note     string `json:"note,omitempty"`

	Array []*Value    `json:"array,omitempty"`
	Map   []*MapEntry `json:"map,omitempty"`

	// Ext fields (msgpack extension types).
	ExtType *int8  `json:"ext_type,omitempty"`
	ExtData string `json:"ext_data_hex,omitempty"`
}

// MapEntry is one key/value pair of a decoded map (order-preserving).
type MapEntry struct {
	Key   *Value `json:"key"`
	Value *Value `json:"value"`
}

// Result is the decoded top-level value plus framing metadata.
type Result struct {
	Value         *Value `json:"value"`
	TotalBytes    int    `json:"total_bytes"`
	TrailingHex   string `json:"trailing_bytes_hex,omitempty"`
	TrailingCount int    `json:"trailing_bytes,omitempty"`
}

// Decode parses the hex of a MessagePack blob (separators and an optional 0x
// prefix tolerated) into a single top-level value.
func Decode(hexBlob string) (*Result, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a MessagePack blob from raw bytes.
func DecodeBytes(b []byte) (*Result, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("msgpack: empty input")
	}
	d := &decoder{buf: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	r := &Result{Value: v, TotalBytes: d.pos}
	if d.pos < len(b) {
		r.TrailingCount = len(b) - d.pos
		r.TrailingHex = strings.ToUpper(hex.EncodeToString(b[d.pos:]))
	}
	return r, nil
}

const maxDepth = 64

type decoder struct {
	buf []byte
	pos int
}

// take advances the cursor by n bytes and returns them, erroring on truncation.
func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || d.pos+n > len(d.buf) {
		return nil, fmt.Errorf("msgpack: truncated: need %d more bytes at offset %d", n, d.pos)
	}
	s := d.buf[d.pos : d.pos+n]
	d.pos += n
	return s, nil
}

func (d *decoder) value(depth int) (*Value, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("msgpack: nesting deeper than %d", maxDepth)
	}
	tagB, err := d.take(1)
	if err != nil {
		return nil, err
	}
	c := tagB[0]
	switch {
	case c <= 0x7f: // positive fixint
		return uintVal("positive fixint", uint64(c)), nil
	case c >= 0xe0: // negative fixint
		return intVal("negative fixint", int64(int8(c))), nil
	case c >= 0x80 && c <= 0x8f: // fixmap
		return d.mapVal("fixmap", int(c&0x0f), depth)
	case c >= 0x90 && c <= 0x9f: // fixarray
		return d.arrayVal("fixarray", int(c&0x0f), depth)
	case c >= 0xa0 && c <= 0xbf: // fixstr
		return d.strVal("fixstr", int(c&0x1f))
	}
	switch c {
	case 0xc0:
		return &Value{Type: "nil", Format: "nil"}, nil
	case 0xc1:
		return nil, fmt.Errorf("msgpack: reserved tag 0xc1 (never used) at offset %d", d.pos-1)
	case 0xc2:
		return boolVal(false), nil
	case 0xc3:
		return boolVal(true), nil
	case 0xc4, 0xc5, 0xc6: // bin8/16/32
		n, err := d.lenField(c - 0xc4)
		if err != nil {
			return nil, err
		}
		return d.binVal([]string{"bin8", "bin16", "bin32"}[c-0xc4], n)
	case 0xc7, 0xc8, 0xc9: // ext8/16/32
		n, err := d.lenField(c - 0xc7)
		if err != nil {
			return nil, err
		}
		return d.extVal([]string{"ext8", "ext16", "ext32"}[c-0xc7], n)
	case 0xca: // float32
		raw, err := d.take(4)
		if err != nil {
			return nil, err
		}
		return floatVal("float32", float64(math.Float32frombits(binary.BigEndian.Uint32(raw)))), nil
	case 0xcb: // float64
		raw, err := d.take(8)
		if err != nil {
			return nil, err
		}
		return floatVal("float64", math.Float64frombits(binary.BigEndian.Uint64(raw))), nil
	case 0xcc, 0xcd, 0xce, 0xcf: // uint8/16/32/64
		return d.uintWidth(c)
	case 0xd0, 0xd1, 0xd2, 0xd3: // int8/16/32/64
		return d.intWidth(c)
	case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8: // fixext1/2/4/8/16
		n := 1 << (c - 0xd4)
		return d.extVal(fmt.Sprintf("fixext%d", n), n)
	case 0xd9, 0xda, 0xdb: // str8/16/32
		n, err := d.lenField(c - 0xd9)
		if err != nil {
			return nil, err
		}
		return d.strVal([]string{"str8", "str16", "str32"}[c-0xd9], n)
	case 0xdc, 0xdd: // array16/32
		n, err := d.lenField(1 + 2*(c-0xdc)) // 0xdc→2-byte len, 0xdd→4-byte len
		if err != nil {
			return nil, err
		}
		return d.arrayVal([]string{"array16", "array32"}[c-0xdc], n, depth)
	case 0xde, 0xdf: // map16/32
		n, err := d.lenField(1 + 2*(c-0xde))
		if err != nil {
			return nil, err
		}
		return d.mapVal([]string{"map16", "map32"}[c-0xde], n, depth)
	}
	return nil, fmt.Errorf("msgpack: unhandled tag 0x%02x at offset %d", c, d.pos-1)
}

// lenField reads a big-endian length: order 0 = 1 byte, 1 = 2 bytes, 2 = 4 bytes.
func (d *decoder) lenField(order byte) (int, error) {
	switch order {
	case 0:
		raw, err := d.take(1)
		if err != nil {
			return 0, err
		}
		return int(raw[0]), nil
	case 1:
		raw, err := d.take(2)
		if err != nil {
			return 0, err
		}
		return int(binary.BigEndian.Uint16(raw)), nil
	default:
		raw, err := d.take(4)
		if err != nil {
			return 0, err
		}
		return int(binary.BigEndian.Uint32(raw)), nil
	}
}

func (d *decoder) uintWidth(c byte) (*Value, error) {
	width := 1 << (c - 0xcc) // 1,2,4,8
	raw, err := d.take(width)
	if err != nil {
		return nil, err
	}
	var v uint64
	for _, x := range raw {
		v = v<<8 | uint64(x)
	}
	return uintVal([]string{"uint8", "uint16", "uint32", "uint64"}[c-0xcc], v), nil
}

func (d *decoder) intWidth(c byte) (*Value, error) {
	width := 1 << (c - 0xd0)
	raw, err := d.take(width)
	if err != nil {
		return nil, err
	}
	var u uint64
	for _, x := range raw {
		u = u<<8 | uint64(x)
	}
	// Sign-extend from the width.
	shift := uint(64 - 8*width)
	return intVal([]string{"int8", "int16", "int32", "int64"}[c-0xd0], int64(u<<shift)>>shift), nil
}

func (d *decoder) strVal(format string, n int) (*Value, error) {
	raw, err := d.take(n)
	if err != nil {
		return nil, err
	}
	if utf8.Valid(raw) {
		s := string(raw)
		return &Value{Type: "str", Format: format, Str: &s}, nil
	}
	return &Value{
		Type: "str", Format: format,
		BytesHex: strings.ToUpper(hex.EncodeToString(raw)),
		Note:     "str payload is not valid UTF-8; surfaced as hex",
	}, nil
}

func (d *decoder) binVal(format string, n int) (*Value, error) {
	raw, err := d.take(n)
	if err != nil {
		return nil, err
	}
	return &Value{Type: "bin", Format: format, BytesHex: strings.ToUpper(hex.EncodeToString(raw))}, nil
}

func (d *decoder) extVal(format string, n int) (*Value, error) {
	t, err := d.take(1)
	if err != nil {
		return nil, err
	}
	raw, err := d.take(n)
	if err != nil {
		return nil, err
	}
	et := int8(t[0])
	v := &Value{Type: "ext", Format: format, ExtType: &et,
		ExtData: strings.ToUpper(hex.EncodeToString(raw))}
	if et == -1 {
		v.Note = "ext type -1 is the MessagePack Timestamp; surfaced as raw (time decode deferred)"
	}
	return v, nil
}

func (d *decoder) arrayVal(format string, n, depth int) (*Value, error) {
	v := &Value{Type: "array", Format: format, Array: make([]*Value, 0, minCap(n))}
	for i := 0; i < n; i++ {
		el, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.Array = append(v.Array, el)
	}
	return v, nil
}

func (d *decoder) mapVal(format string, n, depth int) (*Value, error) {
	v := &Value{Type: "map", Format: format, Map: make([]*MapEntry, 0, minCap(n))}
	for i := 0; i < n; i++ {
		k, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		val, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.Map = append(v.Map, &MapEntry{Key: k, Value: val})
	}
	return v, nil
}

// minCap bounds the pre-allocation so a hostile huge length field can't cause a
// giant up-front allocation; the slice still grows to the real count if valid.
func minCap(n int) int {
	if n > 1024 {
		return 1024
	}
	if n < 0 {
		return 0
	}
	return n
}

func uintVal(format string, v uint64) *Value { return &Value{Type: "uint", Format: format, Uint: &v} }
func intVal(format string, v int64) *Value   { return &Value{Type: "int", Format: format, Int: &v} }
func floatVal(format string, v float64) *Value {
	return &Value{Type: "float", Format: format, Float: &v}
}
func boolVal(b bool) *Value { return &Value{Type: "bool", Format: "bool", Bool: &b} }

// parseHex strips common separators / 0x prefix and decodes a hex string.
func parseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "",
		":", "", "-", "", "_", "", "0x", "", "0X", "").Replace(s)
	if s == "" {
		return nil, fmt.Errorf("msgpack: empty input")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("msgpack: hex has odd length")
	}
	return hex.DecodeString(s)
}
