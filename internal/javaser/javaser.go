// Package javaser structurally decodes a Java serialized-object stream (the
// Java Object Serialization Stream Protocol) for deserialization-RCE triage.
//
// Java deserialization is one of the highest-impact RCE classes: an app that
// calls ObjectInputStream.readObject() on attacker data can be driven to
// remote code execution through a "gadget chain" of classes already on its
// classpath (ysoserial: CommonsCollections, the xalan TemplatesImpl, the
// reflection AnnotationInvocationHandler, BeanComparator, …). A serialized
// blob shows up in HTTP cookies, parameters, RMI / JMX / JNDI / T3 traffic, and
// .ser files. The analyst question is "what classes does this instantiate, and
// does it carry a known gadget?" — and the safe way to answer it is to parse
// the wire format, never to call readObject (which is the exploit).
//
// This walks the stream per the JDK spec (java.io.ObjectStreamConstants) and
// surfaces the magic / version, the top-level type, every class name in
// encounter order, a sample of the embedded strings, and — flagged — any class
// matching the known gadget / dangerous set. It never deserializes, never loads
// a class, never runs a constructor.
//
// No confidently-wrong output: the grammar is parsed deterministically; an
// unsupported construct or a short buffer stops the walk with `truncated:true`
// and a note, returning the (correctly parsed) class names found so far — it
// never fabricates a class name or guesses past an ambiguity. Recursion is
// depth-capped against a serialization bomb (which `recover` cannot catch).
//
// Wrap-vs-native: native — a recursive-descent parser of the documented wire
// format, stdlib only, no new go.mod dependency. Anchored to real
// javac/ObjectOutputStream-produced streams (see the test).
package javaser

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Stream constants (java.io.ObjectStreamConstants).
const (
	streamMagic    = 0xACED
	baseWireHandle = 0x7E0000

	tcNull           = 0x70
	tcReference      = 0x71
	tcClassDesc      = 0x72
	tcObject         = 0x73
	tcString         = 0x74
	tcArray          = 0x75
	tcClass          = 0x76
	tcBlockData      = 0x77
	tcEndBlockData   = 0x78
	tcReset          = 0x79
	tcBlockDataLong  = 0x7A
	tcException      = 0x7B
	tcLongString     = 0x7C
	tcProxyClassDesc = 0x7D
	tcEnum           = 0x7E

	scWriteMethod    = 0x01
	scSerializable   = 0x02
	scExternalizable = 0x04
	scBlockData      = 0x08
	scEnum           = 0x10

	maxDepth   = 200
	maxStrings = 64
)

// Result is the structural triage of a Java serialized stream.
type Result struct {
	Format        string   `json:"format"`
	Version       int      `json:"version"`
	TopLevel      string   `json:"top_level,omitempty"`
	Classes       []string `json:"classes,omitempty"`
	GadgetClasses []string `json:"gadget_classes,omitempty"`
	Strings       []string `json:"strings,omitempty"`
	Truncated     bool     `json:"truncated,omitempty"`
	Suspicious    bool     `json:"suspicious"`
	Note          string   `json:"note"`
}

// classDesc holds a parsed class descriptor: its name, flags, fields, and super.
type classDesc struct {
	name   string
	flags  byte
	fields []fieldDesc
	super  *classDesc
}

type fieldDesc struct {
	typ  byte
	name string
}

type parser struct {
	b        []byte
	pos      int
	handles  []*classDesc // handle table (only class descs are referenced back here)
	res      *Result
	classSet map[string]bool
	depth    int
}

// Decode structurally parses a Java serialized stream.
func Decode(data []byte) (*Result, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("javaser: too short to be a serialized stream")
	}
	magic := binary.BigEndian.Uint16(data[0:2])
	if magic != streamMagic {
		return nil, fmt.Errorf("javaser: bad stream magic 0x%04x (want 0xaced)", magic)
	}
	res := &Result{
		Format:  "java-serialized",
		Version: int(binary.BigEndian.Uint16(data[2:4])),
	}
	p := &parser{b: data, pos: 4, res: res, classSet: map[string]bool{}}

	first := true
	for p.pos < len(p.b) && !res.Truncated {
		top := p.readContent()
		if first && top != "" {
			res.TopLevel = top
			first = false
		}
	}

	res.Suspicious = len(res.GadgetClasses) > 0
	res.Note = noteFor(res)
	return res, nil
}

// readContent parses one stream element and returns a short label for it (used
// only for the top-level element). It advances p.pos; on any shortfall or
// unsupported construct it sets Truncated and returns.
func (p *parser) readContent() string {
	if p.depth > maxDepth {
		p.truncate("nesting exceeds max depth")
		return ""
	}
	tag, ok := p.u8()
	if !ok {
		return ""
	}
	switch tag {
	case tcNull:
		return "null"
	case tcReference:
		if _, ok := p.u32(); !ok {
			return ""
		}
		return "reference"
	case tcString:
		return p.readString(false)
	case tcLongString:
		return p.readString(true)
	case tcObject:
		return p.readObject()
	case tcArray:
		return p.readArray()
	case tcClass:
		cd := p.readClassDesc()
		if cd != nil {
			return cd.name
		}
		return "class"
	case tcEnum:
		return p.readEnum()
	case tcClassDesc, tcProxyClassDesc:
		p.pos-- // let readClassDesc re-read the tag
		cd := p.readClassDesc()
		if cd != nil {
			return cd.name
		}
		return "classdesc"
	case tcBlockData:
		p.skipBlockData(false)
		return "blockdata"
	case tcBlockDataLong:
		p.skipBlockData(true)
		return "blockdata"
	case tcReset:
		p.handles = nil
		return "reset"
	case tcEndBlockData:
		return ""
	case tcException:
		p.truncate("stream contains a TC_EXCEPTION")
		return "exception"
	default:
		p.truncate(fmt.Sprintf("unsupported tag 0x%02x at offset %d", tag, p.pos-1))
		return ""
	}
}

// readObject parses TC_OBJECT: a classDesc followed by the class data.
func (p *parser) readObject() string {
	p.depth++
	defer func() { p.depth-- }()
	cd := p.readClassDesc()
	if cd == nil {
		return "object"
	}
	p.readClassData(cd)
	return cd.name
}

// readClassData reads the serialized field data for the whole class hierarchy,
// super-most first.
func (p *parser) readClassData(cd *classDesc) {
	chain := []*classDesc{}
	for c := cd; c != nil; c = c.super {
		chain = append(chain, c)
	}
	for i := len(chain) - 1; i >= 0 && !p.res.Truncated; i-- {
		c := chain[i]
		if c.flags&scExternalizable != 0 {
			// Externalizable: only parseable when written in block-data mode.
			if c.flags&scBlockData != 0 {
				p.readAnnotations()
			} else {
				p.truncate("externalizable object without block-data (custom wire format)")
			}
			continue
		}
		for _, f := range c.fields {
			if p.res.Truncated {
				return
			}
			p.readFieldValue(f.typ)
		}
		// SC_WRITE_METHOD => a custom writeObject wrote extra annotation data.
		if c.flags&scWriteMethod != 0 {
			p.readAnnotations()
		}
	}
}

// readFieldValue consumes one field's value by its type code.
func (p *parser) readFieldValue(typ byte) {
	switch typ {
	case 'B', 'Z': // byte, boolean
		p.skip(1)
	case 'C', 'S': // char, short
		p.skip(2)
	case 'I', 'F': // int, float
		p.skip(4)
	case 'J', 'D': // long, double
		p.skip(8)
	case 'L', '[': // object, array
		p.readContent()
	default:
		p.truncate(fmt.Sprintf("unknown field type %q", string(typ)))
	}
}

// readClassDesc parses a class descriptor (or null / reference / proxy).
func (p *parser) readClassDesc() *classDesc {
	tag, ok := p.u8()
	if !ok {
		return nil
	}
	switch tag {
	case tcNull:
		return nil
	case tcReference:
		h, ok := p.u32()
		if !ok {
			return nil
		}
		idx := int(h) - baseWireHandle
		if idx < 0 || idx >= len(p.handles) {
			return nil
		}
		return p.handles[idx]
	case tcProxyClassDesc:
		return p.readProxyClassDesc()
	case tcClassDesc:
		return p.readNewClassDesc()
	default:
		p.truncate(fmt.Sprintf("expected a class descriptor, got tag 0x%02x", tag))
		return nil
	}
}

// readNewClassDesc parses TC_CLASSDESC.
func (p *parser) readNewClassDesc() *classDesc {
	name := p.readUTF(false)
	if p.res.Truncated {
		return nil
	}
	p.skip(8) // serialVersionUID
	cd := &classDesc{name: name}
	p.handles = append(p.handles, cd)
	p.recordClass(name)

	flags, ok := p.u8()
	if !ok {
		return cd
	}
	cd.flags = flags
	n, ok := p.u16()
	if !ok {
		return cd
	}
	for i := 0; i < int(n) && !p.res.Truncated; i++ {
		tc, ok := p.u8()
		if !ok {
			return cd
		}
		fname := p.readUTF(false)
		f := fieldDesc{typ: tc, name: fname}
		if tc == 'L' || tc == '[' {
			// Field className: a TC_STRING or TC_REFERENCE (consumed, ignored).
			p.readContent()
		}
		cd.fields = append(cd.fields, f)
	}
	p.readAnnotations()          // classAnnotation
	cd.super = p.readClassDesc() // superClassDesc
	return cd
}

// readProxyClassDesc parses TC_PROXYCLASSDESC (dynamic-proxy interfaces).
func (p *parser) readProxyClassDesc() *classDesc {
	cd := &classDesc{name: "<proxy>"}
	p.handles = append(p.handles, cd)
	n, ok := p.u32()
	if !ok {
		return cd
	}
	var ifaces []string
	for i := 0; i < int(n) && !p.res.Truncated; i++ {
		ifaces = append(ifaces, p.readUTF(false))
	}
	cd.name = "proxy(" + strings.Join(ifaces, ", ") + ")"
	for _, n := range ifaces {
		p.recordClass(n)
	}
	p.readAnnotations()
	cd.super = p.readClassDesc()
	return cd
}

// readArray parses TC_ARRAY.
func (p *parser) readArray() string {
	p.depth++
	defer func() { p.depth-- }()
	cd := p.readClassDesc()
	name := "array"
	elem := byte('L')
	if cd != nil {
		name = cd.name
		// Component type is the char after the leading '['.
		if len(cd.name) >= 2 && cd.name[0] == '[' {
			elem = cd.name[1]
		}
	}
	size, ok := p.u32()
	if !ok {
		return name
	}
	for i := 0; i < int(size) && !p.res.Truncated; i++ {
		switch elem {
		case 'B', 'Z':
			p.skip(1)
		case 'C', 'S':
			p.skip(2)
		case 'I', 'F':
			p.skip(4)
		case 'J', 'D':
			p.skip(8)
		default: // 'L', '['
			p.readContent()
		}
	}
	return name
}

// readEnum parses TC_ENUM.
func (p *parser) readEnum() string {
	cd := p.readClassDesc()
	p.readContent() // constant name (TC_STRING)
	if cd != nil {
		return cd.name
	}
	return "enum"
}

// readString parses TC_STRING / TC_LONGSTRING and records the value.
func (p *parser) readString(long bool) string {
	s := p.readUTF(long)
	p.handles = append(p.handles, &classDesc{name: "<string>"})
	if s != "" && len(p.res.Strings) < maxStrings {
		p.res.Strings = append(p.res.Strings, s)
	}
	return s
}

// readAnnotations consumes a sequence of content until TC_ENDBLOCKDATA.
func (p *parser) readAnnotations() {
	for !p.res.Truncated {
		tag, ok := p.peek()
		if !ok {
			return
		}
		if tag == tcEndBlockData {
			p.pos++
			return
		}
		p.readContent()
	}
}

func (p *parser) skipBlockData(long bool) {
	var n int
	if long {
		v, ok := p.u32()
		if !ok {
			return
		}
		n = int(v)
	} else {
		v, ok := p.u8()
		if !ok {
			return
		}
		n = int(v)
	}
	p.skip(n)
}

// recordClass adds a class name (deduped) and flags it if it is a known gadget.
func (p *parser) recordClass(name string) {
	if name == "" || p.classSet[name] {
		return
	}
	p.classSet[name] = true
	p.res.Classes = append(p.res.Classes, name)
	if g := gadgetReason(name); g != "" {
		p.res.GadgetClasses = append(p.res.GadgetClasses, name+" — "+g)
	}
}

func (p *parser) truncate(reason string) {
	if !p.res.Truncated {
		p.res.Truncated = true
		p.res.Note = reason
	}
}

// --- low-level readers (all bounds-checked) ---------------------------------

func (p *parser) u8() (byte, bool) {
	if p.pos+1 > len(p.b) {
		p.truncate("unexpected end of stream")
		return 0, false
	}
	v := p.b[p.pos]
	p.pos++
	return v, true
}

func (p *parser) peek() (byte, bool) {
	if p.pos >= len(p.b) {
		return 0, false
	}
	return p.b[p.pos], true
}

func (p *parser) u16() (uint16, bool) {
	if p.pos+2 > len(p.b) {
		p.truncate("unexpected end of stream")
		return 0, false
	}
	v := binary.BigEndian.Uint16(p.b[p.pos:])
	p.pos += 2
	return v, true
}

func (p *parser) u32() (uint32, bool) {
	if p.pos+4 > len(p.b) {
		p.truncate("unexpected end of stream")
		return 0, false
	}
	v := binary.BigEndian.Uint32(p.b[p.pos:])
	p.pos += 4
	return v, true
}

func (p *parser) skip(n int) {
	if n < 0 || p.pos+n > len(p.b) {
		p.truncate("field data runs past end of stream")
		p.pos = len(p.b)
		return
	}
	p.pos += n
}

// readUTF reads a Java modified-UTF-8 string (2-byte length, or 8-byte for
// TC_LONGSTRING). The bytes are surfaced as-is (ASCII-clean for class names).
func (p *parser) readUTF(long bool) string {
	var n int
	if long {
		v, ok := p.u32()
		if !ok {
			return ""
		}
		if hi, ok2 := p.u32Tail(v); ok2 {
			n = hi
		} else {
			return ""
		}
	} else {
		v, ok := p.u16()
		if !ok {
			return ""
		}
		n = int(v)
	}
	if n < 0 || p.pos+n > len(p.b) {
		p.truncate("string length runs past end of stream")
		p.pos = len(p.b)
		return ""
	}
	s := string(p.b[p.pos : p.pos+n])
	p.pos += n
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	return s
}

// u32Tail combines the already-read high uint32 of an 8-byte length with the
// low uint32. Lengths beyond int range are rejected.
func (p *parser) u32Tail(hi uint32) (int, bool) {
	lo, ok := p.u32()
	if !ok {
		return 0, false
	}
	full := uint64(hi)<<32 | uint64(lo)
	if full > uint64(len(p.b)) {
		p.truncate("long-string length exceeds the buffer")
		return 0, false
	}
	return int(full), true
}

func noteFor(res *Result) string {
	base := "Structural decode only — the stream was NOT deserialized (readObject would be the exploit). "
	if len(res.GadgetClasses) > 0 {
		base += "DANGEROUS: known deserialization-gadget class(es) present — " + strings.Join(res.GadgetClasses, "; ") + ". Treat this stream as a likely RCE payload. "
	}
	if res.Truncated {
		base += "Parsing stopped early (" + res.Note + "); the classes listed were parsed before that point. "
	}
	if len(res.GadgetClasses) == 0 && !res.Truncated {
		base += "No known gadget class found — not a guarantee of safety (custom or unknown gadgets exist). "
	}
	return strings.TrimSpace(base)
}
