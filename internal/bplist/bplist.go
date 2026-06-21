// Package bplist decodes an Apple binary property list (bplist00) into a
// structured tree.
//
// Binary plists are pervasive in iOS / macOS loot: app preferences
// (Library/Preferences/*.plist), .mobileconfig configuration profiles,
// NSKeyedArchiver blobs, and many forensic artifacts are stored in this format
// rather than the XML variant. This turns a binary plist into a readable tree —
// the bplist sibling of cbor_decode / msgpack_decode / bson_decode for the Apple
// domain.
//
// No confidently-wrong output: the file is recognised only by its "bplist00"
// magic; the object/offset tables and the trailer are bounds-checked; an
// out-of-range object reference or a malformed marker yields an error or an
// "<error>" leaf rather than a guess; recursion is depth- and node-budget-capped
// against a hostile self-referential plist; an UID (NSKeyedArchiver) is surfaced
// as {"$uid": n}, a date as RFC 3339 (the 2001 epoch), and data as hex.
//
// Wrap-vs-native: native — a recursive-descent walk of the documented
// CFBinaryPlist layout (CFBinaryPList.c / the Apple format); stdlib only, no new
// go.mod dependency. Anchored byte-for-byte to Python's stdlib plistlib (see the
// package test). Only the v0 (bplist00) format is handled; v1.5/v2.0 are rare.
package bplist

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"time"
	"unicode/utf16"
)

const (
	magic         = "bplist00"
	trailerLen    = 32
	maxDepth      = 64
	maxNodeBudget = 1 << 20 // total objects decoded across the whole walk
)

// Result is the decoded property list.
type Result struct {
	Format      string `json:"format"`
	ObjectCount int    `json:"object_count"`
	Root        any    `json:"root"`
	Note        string `json:"note"`
}

// decoder holds the parse state.
type decoder struct {
	b             []byte
	offsets       []uint64
	offsetIntSize int
	objectRefSize int
	numObjects    uint64
	nodes         int
}

// Decode parses a binary property list.
func Decode(data []byte) (*Result, error) {
	if len(data) < len(magic)+trailerLen {
		return nil, fmt.Errorf("bplist: too short (%d bytes)", len(data))
	}
	if string(data[:len(magic)]) != magic {
		return nil, fmt.Errorf("bplist: missing bplist00 magic")
	}
	tr := data[len(data)-trailerLen:]
	d := &decoder{
		b:             data,
		offsetIntSize: int(tr[6]),
		objectRefSize: int(tr[7]),
		numObjects:    binary.BigEndian.Uint64(tr[8:16]),
	}
	topObject := binary.BigEndian.Uint64(tr[16:24])
	offsetTableOffset := binary.BigEndian.Uint64(tr[24:32])

	if d.offsetIntSize < 1 || d.offsetIntSize > 8 || d.objectRefSize < 1 || d.objectRefSize > 8 {
		return nil, fmt.Errorf("bplist: bad trailer sizes (offset=%d ref=%d)", d.offsetIntSize, d.objectRefSize)
	}
	if d.numObjects > uint64(len(data)) || topObject >= d.numObjects {
		return nil, fmt.Errorf("bplist: implausible object count %d / top %d", d.numObjects, topObject)
	}
	// Read the offset table.
	end := offsetTableOffset + d.numObjects*uint64(d.offsetIntSize)
	if offsetTableOffset > uint64(len(data)) || end > uint64(len(data)) {
		return nil, fmt.Errorf("bplist: offset table out of range")
	}
	d.offsets = make([]uint64, d.numObjects)
	for i := range d.offsets {
		p := offsetTableOffset + uint64(i)*uint64(d.offsetIntSize)
		d.offsets[i] = beUint(data[p : p+uint64(d.offsetIntSize)])
	}

	root, err := d.object(topObject, 0)
	if err != nil {
		return nil, err
	}
	return &Result{
		Format:      "bplist",
		ObjectCount: int(d.numObjects),
		Root:        root,
		Note: "Apple binary property list (bplist00) decoded to a tree. Dates are RFC 3339 (the 2001 epoch); " +
			"data is hex; an NSKeyedArchiver UID is {\"$uid\": n}. Offline; no network, no device.",
	}, nil
}

// object decodes the object at index idx.
func (d *decoder) object(idx uint64, depth int) (any, error) {
	if depth > maxDepth {
		return "<max depth>", nil
	}
	if d.nodes++; d.nodes > maxNodeBudget {
		return nil, fmt.Errorf("bplist: object budget exceeded (possible cyclic plist)")
	}
	if idx >= uint64(len(d.offsets)) {
		return nil, fmt.Errorf("bplist: object index %d out of range", idx)
	}
	off := d.offsets[idx]
	if off >= uint64(len(d.b)) {
		return nil, fmt.Errorf("bplist: object offset out of range")
	}
	marker := d.b[off]
	hi, lo := marker>>4, marker&0x0F
	switch hi {
	case 0x0:
		switch marker {
		case 0x00:
			return nil, nil
		case 0x08:
			return false, nil
		case 0x09:
			return true, nil
		case 0x0F:
			return nil, nil // fill
		default:
			return nil, fmt.Errorf("bplist: unknown marker 0x%02x", marker)
		}
	case 0x1: // int
		return d.readInt(off+1, 1<<lo)
	case 0x2: // real
		return d.readReal(off+1, 1<<lo)
	case 0x3: // date
		v, err := d.readFloat(off+1, 8)
		if err != nil {
			return nil, err
		}
		// seconds since 2001-01-01 UTC.
		return time.Unix(978307200, 0).Add(time.Duration(v * float64(time.Second))).UTC().Format(time.RFC3339), nil
	case 0x4: // data
		n, p, err := d.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		raw, err := d.bytesAt(p, n)
		if err != nil {
			return nil, err
		}
		return hex.EncodeToString(raw), nil
	case 0x5: // ASCII string
		n, p, err := d.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		raw, err := d.bytesAt(p, n)
		if err != nil {
			return nil, err
		}
		return string(raw), nil
	case 0x6: // UTF-16BE string
		n, p, err := d.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		raw, err := d.bytesAt(p, n*2)
		if err != nil {
			return nil, err
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(raw[i*2:])
		}
		return string(utf16.Decode(u)), nil
	case 0x8: // UID
		v, err := d.readInt(off+1, int(lo)+1)
		if err != nil {
			return nil, err
		}
		return map[string]any{"$uid": v}, nil
	case 0xA, 0xC: // array / set
		n, p, err := d.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		return d.collection(p, n, depth)
	case 0xD: // dict
		n, p, err := d.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		return d.dict(p, n, depth)
	default:
		return nil, fmt.Errorf("bplist: unsupported marker 0x%02x", marker)
	}
}

// sizedCount returns the element/byte count for a marker whose low nibble is the
// count, or 0xF meaning the next object is an int with the real count. It also
// returns the offset where the element data begins.
func (d *decoder) sizedCount(off uint64, lo byte) (uint64, uint64, error) {
	if lo != 0x0F {
		return uint64(lo), off + 1, nil
	}
	// Next is an int marker giving the count.
	p := off + 1
	if p >= uint64(len(d.b)) {
		return 0, 0, fmt.Errorf("bplist: truncated extended count")
	}
	im := d.b[p]
	if im>>4 != 0x1 {
		return 0, 0, fmt.Errorf("bplist: bad extended-count marker 0x%02x", im)
	}
	n := 1 << (im & 0x0F)
	v, err := d.readInt(p+1, n)
	if err != nil {
		return 0, 0, err
	}
	cnt, ok := v.(int64)
	if !ok || cnt < 0 {
		return 0, 0, fmt.Errorf("bplist: bad extended count")
	}
	// No object can hold more elements/bytes than the whole file contains (a
	// data byte costs 1 byte on disk, a UTF-16 char 2, an object ref
	// objectRefSize>=1). Bounding the count here keeps the n*2 / n*objectRefSize
	// span computations in object() / refs() from overflowing uint64 and
	// wrapping their range checks small — the path that otherwise reaches
	// make([]T, hugeN) and panics (makeslice) / OOMs on a crafted plist, since
	// Decode has no recover.
	if uint64(cnt) > uint64(len(d.b)) {
		return 0, 0, fmt.Errorf("bplist: implausible element count %d (exceeds the %d-byte file)", cnt, len(d.b))
	}
	return uint64(cnt), p + 1 + uint64(n), nil
}

func (d *decoder) collection(p, n uint64, depth int) (any, error) {
	refs, err := d.refs(p, n)
	if err != nil {
		return nil, err
	}
	out := make([]any, n)
	for i, r := range refs {
		v, err := d.object(r, depth+1)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

func (d *decoder) dict(p, n uint64, depth int) (any, error) {
	keyRefs, err := d.refs(p, n)
	if err != nil {
		return nil, err
	}
	valRefs, err := d.refs(p+n*uint64(d.objectRefSize), n)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, n)
	for i := uint64(0); i < n; i++ {
		k, err := d.object(keyRefs[i], depth+1)
		if err != nil {
			return nil, err
		}
		v, err := d.object(valRefs[i], depth+1)
		if err != nil {
			return nil, err
		}
		out[stringKey(k)] = v
	}
	return out, nil
}

// refs reads n object references of objectRefSize bytes each.
func (d *decoder) refs(p, n uint64) ([]uint64, error) {
	need := n * uint64(d.objectRefSize)
	if p+need > uint64(len(d.b)) {
		return nil, fmt.Errorf("bplist: refs out of range")
	}
	out := make([]uint64, n)
	for i := uint64(0); i < n; i++ {
		q := p + i*uint64(d.objectRefSize)
		out[i] = beUint(d.b[q : q+uint64(d.objectRefSize)])
	}
	return out, nil
}

// readInt reads an n-byte big-endian integer (1/2/4 unsigned, 8 signed, 16 via
// big.Int) and returns an int64 or a string for 16-byte values.
func (d *decoder) readInt(p uint64, n int) (any, error) {
	raw, err := d.bytesAt(p, uint64(n))
	if err != nil {
		return nil, err
	}
	switch {
	case n <= 4:
		return int64(beUint(raw)), nil
	case n == 8:
		return int64(binary.BigEndian.Uint64(raw)), nil
	default: // 16-byte signed
		v := new(big.Int).SetBytes(raw)
		if len(raw) == 16 && raw[0]&0x80 != 0 {
			v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(len(raw)*8)))
		}
		return v.String(), nil
	}
}

func (d *decoder) readReal(p uint64, n int) (any, error) {
	v, err := d.readFloat(p, n)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (d *decoder) readFloat(p uint64, n int) (float64, error) {
	raw, err := d.bytesAt(p, uint64(n))
	if err != nil {
		return 0, err
	}
	switch n {
	case 4:
		return float64(math.Float32frombits(binary.BigEndian.Uint32(raw))), nil
	case 8:
		return math.Float64frombits(binary.BigEndian.Uint64(raw)), nil
	default:
		return 0, fmt.Errorf("bplist: bad real size %d", n)
	}
}

func (d *decoder) bytesAt(p, n uint64) ([]byte, error) {
	if p > uint64(len(d.b)) || p+n > uint64(len(d.b)) {
		return nil, fmt.Errorf("bplist: read %d bytes at %d out of range", n, p)
	}
	return d.b[p : p+n], nil
}

func beUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func stringKey(k any) string {
	switch v := k.(type) {
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
