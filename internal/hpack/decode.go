// Package hpack decodes HPACK-compressed HTTP/2 header blocks
// per RFC 7541.
//
// Wrap-vs-native judgement
//
//	Native. RFC 7541 is fully public; HPACK uses no
//	cryptography and no third-party libraries. The wire
//	format is a compact bit-packed stream of five
//	representation types (indexed header, literal with /
//	without indexing, never indexed, dynamic table size
//	update), variable-length integer encoding, and an
//	optional Huffman layer over the same canonical Appendix
//	B code book. Operators paste a HEADERS / CONTINUATION /
//	PUSH_PROMISE frame body (the HPACK block bytes surfaced
//	by `http2_frame_decode`) and inspect each header field
//	plus the per-field representation choice.
//
// What this package covers
//
//   - **Five representation types** per RFC 7541 §6:
//
//   - Indexed Header Field (1xxxxxxx prefix) — references
//     the static (1-61) or dynamic table by index; both
//     name + value come from the table.
//
//   - Literal with Incremental Indexing (01xxxxxx) — name
//     indexed OR literal, value literal; entry is added
//     to the dynamic table.
//
//   - Literal without Indexing (0000xxxx) — name indexed
//     OR literal, value literal; entry is NOT added.
//
//   - Literal Never Indexed (0001xxxx) — same as without
//     indexing, plus a 'never index in any hop' hint.
//
//   - Dynamic Table Size Update (001xxxxx) — change max
//     dynamic table size.
//
//   - **N-bit prefix integer encoding** (RFC 7541 §5.1) —
//     small values fit in the prefix bits; large values use
//     a continuation chain in which each octet contributes 7
//     bits with the high bit signalling 'more octets follow'.
//
//   - **Literal string** (RFC 7541 §5.2) — optional H bit
//     (high bit of length byte) signals Huffman-encoded; the
//     bytes are then either raw octets or a Huffman-encoded
//     stream over the canonical 257-symbol Appendix B table.
//
//   - **Static table** (Appendix A, 61 entries) — pre-baked
//     into the decoder.
//
//   - **Dynamic table** — newly-indexed headers are appended
//     in the order encoded; per RFC 7541 §2.3.3 the first
//     entry inserted gets the lowest index above the static
//     table (62). The dynamic table is per-Decoder instance
//     so a single `Decode` call evolves it as it consumes
//     headers.
//
//   - **Huffman decoder** — bit-trie walker over the
//     Appendix B codes. Trailing partial-byte padding must
//     be a strict prefix of the EOS code (all-ones); EOS
//     in mid-stream is an error.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - HPACK encoding (the inverse direction) — operators
//     who need to craft requests have plenty of higher-level
//     tools.
//
//   - Cross-frame dynamic-table continuity — each `Decode`
//     call starts with an empty dynamic table. A multi-frame
//     session-tracker would need to feed CONTINUATION /
//     subsequent HEADERS bytes back into the same decoder
//     instance.
//
//   - Header validation (e.g. lower-case constraint per RFC
//     9113 §8.2.1, pseudo-header rules) — names + values
//     are surfaced verbatim; semantic validation belongs in
//     a separate Spec.
package hpack

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Header is one decoded HTTP/2 header field plus a hint on how
// it was encoded on the wire.
type Header struct {
	Name           string `json:"name"`
	Value          string `json:"value"`
	Representation string `json:"representation"`
	Indexed        bool   `json:"indexed,omitempty"`
}

// Result is the top-level decoded view.
type Result struct {
	Headers          []Header `json:"headers"`
	HeaderCount      int      `json:"header_count"`
	DynamicTableSize int      `json:"dynamic_table_final_size"`
	BytesConsumed    int      `json:"bytes_consumed"`
	Notes            []string `json:"notes,omitempty"`
}

// dynEntry is one entry in the dynamic table.
type dynEntry struct {
	name  string
	value string
}

// Decoder holds dynamic-table state. For a one-shot Decode the
// outer Decode function constructs a fresh Decoder.
type Decoder struct {
	dyn     []dynEntry
	maxSize int
	curSize int
}

// Decode parses an HPACK-encoded header block from hex and
// returns the decoded headers.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}

	d := &Decoder{maxSize: 4096}
	r := &Result{}
	off := 0
	for off < len(b) {
		h, used, repr, err := d.decodeOne(b[off:])
		if err != nil {
			return nil, fmt.Errorf("at offset %d: %w", off, err)
		}
		if repr == "size_update" {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"dynamic table size update: %d bytes", d.maxSize))
		} else {
			r.Headers = append(r.Headers, *h)
		}
		off += used
	}
	r.HeaderCount = len(r.Headers)
	r.DynamicTableSize = d.curSize
	r.BytesConsumed = off
	return r, nil
}

// decodeOne parses one representation from b and returns the
// resulting Header (or nil for table-size updates), the number
// of bytes consumed, and the representation type name.
func (d *Decoder) decodeOne(b []byte) (*Header, int, string, error) {
	if len(b) == 0 {
		return nil, 0, "", fmt.Errorf("empty buffer")
	}
	first := b[0]
	switch {
	case first&0x80 != 0:
		// Indexed Header Field (1xxxxxxx).
		idx, used, err := readInt(b, 7)
		if err != nil {
			return nil, 0, "", fmt.Errorf("indexed integer: %w", err)
		}
		name, value, err := d.lookup(idx)
		if err != nil {
			return nil, 0, "", err
		}
		return &Header{
			Name: name, Value: value,
			Representation: "indexed",
			Indexed:        true,
		}, used, "indexed", nil

	case first&0xC0 == 0x40:
		// Literal Header Field with Incremental Indexing (01xxxxxx).
		idx, used, err := readInt(b, 6)
		if err != nil {
			return nil, 0, "", err
		}
		name, valBytes, valStr, vused, err := d.readNameAndValue(b[used:], idx)
		if err != nil {
			return nil, 0, "", err
		}
		used += vused
		d.add(name, valStr)
		_ = valBytes
		return &Header{
			Name: name, Value: valStr,
			Representation: "literal_incremental",
			Indexed:        true,
		}, used, "literal_incremental", nil

	case first&0xE0 == 0x20:
		// Dynamic Table Size Update (001xxxxx).
		newSize, used, err := readInt(b, 5)
		if err != nil {
			return nil, 0, "", err
		}
		d.maxSize = newSize
		d.evict()
		return nil, used, "size_update", nil

	case first&0xF0 == 0x10:
		// Literal Header Field Never Indexed (0001xxxx).
		idx, used, err := readInt(b, 4)
		if err != nil {
			return nil, 0, "", err
		}
		name, _, valStr, vused, err := d.readNameAndValue(b[used:], idx)
		if err != nil {
			return nil, 0, "", err
		}
		used += vused
		return &Header{
			Name: name, Value: valStr,
			Representation: "literal_never_indexed",
		}, used, "literal_never_indexed", nil

	case first&0xF0 == 0x00:
		// Literal Header Field without Indexing (0000xxxx).
		idx, used, err := readInt(b, 4)
		if err != nil {
			return nil, 0, "", err
		}
		name, _, valStr, vused, err := d.readNameAndValue(b[used:], idx)
		if err != nil {
			return nil, 0, "", err
		}
		used += vused
		return &Header{
			Name: name, Value: valStr,
			Representation: "literal_without_indexing",
		}, used, "literal_without_indexing", nil
	}
	return nil, 0, "", fmt.Errorf("unknown HPACK representation byte 0x%02X", first)
}

// readNameAndValue handles the name (indexed or literal) + value
// (always literal) portion of the three literal representations.
// If idx == 0, the name is a literal that immediately follows;
// otherwise the name comes from the table at idx.
func (d *Decoder) readNameAndValue(b []byte, idx int) (
	name string, valBytes []byte, valStr string, used int, err error) {
	off := 0
	if idx == 0 {
		nameStr, n, e := readString(b)
		if e != nil {
			return "", nil, "", 0, fmt.Errorf("name literal: %w", e)
		}
		name = nameStr
		off += n
	} else {
		var v string
		name, v, err = d.lookup(idx)
		_ = v
		if err != nil {
			return "", nil, "", 0, fmt.Errorf("name index %d: %w", idx, err)
		}
	}
	if off >= len(b) {
		return "", nil, "", 0, fmt.Errorf("value literal missing")
	}
	valStr, n, e := readString(b[off:])
	if e != nil {
		return "", nil, "", 0, fmt.Errorf("value literal: %w", e)
	}
	off += n
	return name, []byte(valStr), valStr, off, nil
}

// lookup resolves an index to (name, value) — index 1-61 from
// static table, 62+ from dynamic table (newest = lowest index
// per RFC 7541 §2.3.3).
func (d *Decoder) lookup(idx int) (string, string, error) {
	if idx <= 0 {
		return "", "", fmt.Errorf("index 0 is reserved")
	}
	if idx <= staticTableSize {
		e := staticTable[idx]
		return e.name, e.value, nil
	}
	dynIdx := idx - staticTableSize - 1
	if dynIdx < 0 || dynIdx >= len(d.dyn) {
		return "", "", fmt.Errorf("dynamic index %d out of range (table size %d)",
			idx, len(d.dyn))
	}
	e := d.dyn[dynIdx]
	return e.name, e.value, nil
}

// add appends a new entry to the front of the dynamic table
// per RFC 7541 §4.4 and evicts older entries until curSize
// fits maxSize.
func (d *Decoder) add(name, value string) {
	entrySize := len(name) + len(value) + 32 // RFC 7541 §4.1
	if entrySize > d.maxSize {
		// Per RFC 7541 §4.4, if the new entry is larger than
		// the max size, the table is emptied and the entry is
		// not inserted.
		d.dyn = nil
		d.curSize = 0
		return
	}
	d.dyn = append([]dynEntry{{name: name, value: value}}, d.dyn...)
	d.curSize += entrySize
	d.evict()
}

func (d *Decoder) evict() {
	for d.curSize > d.maxSize && len(d.dyn) > 0 {
		last := d.dyn[len(d.dyn)-1]
		d.curSize -= len(last.name) + len(last.value) + 32
		d.dyn = d.dyn[:len(d.dyn)-1]
	}
}

// readInt decodes an N-bit prefix integer per RFC 7541 §5.1.
// prefixBits is N (typically 4, 5, 6, or 7). The first byte's
// low-N bits are read; if they're all 1, a continuation chain
// follows.
func readInt(b []byte, prefixBits int) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("readInt: empty buffer")
	}
	mask := byte((1 << uint(prefixBits)) - 1)
	v := int(b[0] & mask)
	if v < int(mask) {
		return v, 1, nil
	}
	off := 1
	m := 0
	for {
		if off >= len(b) {
			return 0, 0, fmt.Errorf("readInt: continuation truncated")
		}
		bb := b[off]
		off++
		v += int(bb&0x7F) << uint(m)
		m += 7
		if bb&0x80 == 0 {
			return v, off, nil
		}
		if m > 28 {
			return 0, 0, fmt.Errorf("readInt: continuation chain too long")
		}
	}
}

// readString decodes a length-prefixed octet sequence per RFC
// 7541 §5.2. The high bit of the length byte (H) signals
// Huffman encoding.
func readString(b []byte) (string, int, error) {
	if len(b) == 0 {
		return "", 0, fmt.Errorf("readString: empty buffer")
	}
	huff := b[0]&0x80 != 0
	ln, used, err := readInt(b, 7)
	if err != nil {
		return "", 0, fmt.Errorf("string length: %w", err)
	}
	if used+ln > len(b) {
		return "", 0, fmt.Errorf("string length %d exceeds buffer (%d left)",
			ln, len(b)-used)
	}
	raw := b[used : used+ln]
	if huff {
		s, err := huffmanDecode(raw)
		if err != nil {
			return "", 0, fmt.Errorf("huffman decode: %w", err)
		}
		return s, used + ln, nil
	}
	return string(raw), used + ln, nil
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
