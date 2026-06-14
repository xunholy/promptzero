// Package phpserialize decodes a PHP serialize() string into its object tree
// for PHP Object Injection (POI) triage.
//
// PHP's serialize() / unserialize() is the wire format behind session files,
// signed/unsigned cookies, caches, and many framework "remember me" tokens. If
// an app calls unserialize() on attacker-controlled data, an attacker can inject
// an arbitrary object (O:…) whose magic methods (__wakeup / __destruct /
// __toString) fire a "POP chain" — the phpggc gadget families (Monolog,
// Guzzle, Laravel/Illuminate, Symfony, Doctrine, WordPress, …) turn that into
// RCE / file-write / SSRF. The analyst question is "does this blob instantiate
// objects, of what classes, and is a known gadget present?".
//
// This parses the documented serialize() grammar — N (null), b (bool), i (int),
// d (double), s (string, byte-length-prefixed), a (array), O (object), C
// (custom/Serializable), E (enum, PHP 8.1), r/R (reference) — into a
// JSON-friendly value tree, collecting every object class name, de-mangling
// private (\0Class\0prop) and protected (\0*\0prop) property keys, flagging any
// class in the known gadget set, and noting that the mere presence of an object
// is an object-injection surface. It never instantiates anything.
//
// No confidently-wrong output: the grammar is parsed deterministically; a
// malformed or unsupported construct stops the parse with `truncated:true` and a
// note, returning the (correctly parsed) tree so far — it never guesses past an
// ambiguity. Recursion is depth-capped against a nested-array/object bomb.
//
// Wrap-vs-native: native — a recursive-descent parser of the documented text
// grammar, stdlib only, no new go.mod dependency. Anchored to hand-built and
// published phpggc-style vectors (see the test).
package phpserialize

import (
	"fmt"
	"strconv"
	"strings"
)

const maxDepth = 256

// Result is the decoded PHP serialized value.
type Result struct {
	Format          string   `json:"format"`
	Type            string   `json:"type"`
	Value           any      `json:"value"`
	Classes         []string `json:"classes,omitempty"`
	GadgetClasses   []string `json:"gadget_classes,omitempty"`
	ObjectInjection bool     `json:"object_injection_surface"`
	Truncated       bool     `json:"truncated,omitempty"`
	Suspicious      bool     `json:"suspicious"`
	Note            string   `json:"note"`
}

type parser struct {
	s        []byte
	pos      int
	res      *Result
	classSet map[string]bool
	depth    int
}

// Decode parses a PHP serialize() string.
func Decode(data []byte) (*Result, error) {
	s := trimWS(data)
	if len(s) == 0 {
		return nil, fmt.Errorf("phpserialize: empty input")
	}
	res := &Result{Format: "php-serialized"}
	p := &parser{s: s, res: res, classSet: map[string]bool{}}
	v := p.readValue()
	if res.Truncated && len(res.Classes) == 0 && v == nil {
		return nil, fmt.Errorf("phpserialize: not a PHP serialize() stream: %s", res.Note)
	}
	res.Value = v
	res.Type = topType(v)
	res.ObjectInjection = len(res.Classes) > 0
	res.Suspicious = len(res.GadgetClasses) > 0
	res.Note = noteFor(res)
	return res, nil
}

// readValue parses one serialized value.
func (p *parser) readValue() any {
	if p.depth > maxDepth {
		p.truncate("nesting exceeds max depth")
		return nil
	}
	c, ok := p.peek()
	if !ok {
		p.truncate("unexpected end of input")
		return nil
	}
	switch c {
	case 'N':
		if !p.lit("N;") {
			return nil
		}
		return nil
	case 'b':
		return p.readBool()
	case 'i':
		return p.readInt()
	case 'd':
		return p.readDouble()
	case 's':
		return p.readString()
	case 'a':
		return p.readArray()
	case 'O':
		return p.readObject()
	case 'C':
		return p.readCustom()
	case 'E':
		return p.readEnum()
	case 'r', 'R':
		return p.readReference(c)
	default:
		p.truncate(fmt.Sprintf("unexpected type marker %q at offset %d", string(c), p.pos))
		return nil
	}
}

func (p *parser) readBool() any {
	if !p.lit("b:") {
		return nil
	}
	v, ok := p.u8()
	if !ok || !p.lit(";") {
		return nil
	}
	return v == '1'
}

func (p *parser) readInt() any {
	if !p.lit("i:") {
		return nil
	}
	tok := p.readUntil(';')
	if p.res.Truncated {
		return nil
	}
	n, err := strconv.ParseInt(tok, 10, 64)
	if err != nil {
		p.truncate("invalid integer literal")
		return nil
	}
	return n
}

func (p *parser) readDouble() any {
	if !p.lit("d:") {
		return nil
	}
	tok := p.readUntil(';')
	if p.res.Truncated {
		return nil
	}
	switch tok {
	case "NAN":
		return "NaN"
	case "INF":
		return "Inf"
	case "-INF":
		return "-Inf"
	}
	f, err := strconv.ParseFloat(tok, 64)
	if err != nil {
		p.truncate("invalid double literal")
		return nil
	}
	return f
}

// readString parses s:<len>:"<bytes>"; — len is a byte count, so the bytes are
// read verbatim (they may contain '"' / ';' / NUL).
func (p *parser) readString() string {
	if !p.lit(`s:`) {
		return ""
	}
	return p.readSizedString()
}

// readSizedString reads <len>:"<bytes>"; (the part after the leading marker).
func (p *parser) readSizedString() string {
	n, ok := p.readLen()
	if !ok || !p.lit(`:"`) {
		return ""
	}
	if n < 0 || p.pos+n > len(p.s) {
		p.truncate("string length runs past end of input")
		return ""
	}
	v := string(p.s[p.pos : p.pos+n])
	p.pos += n
	p.lit(`";`)
	return v
}

func (p *parser) readArray() any {
	if !p.lit("a:") {
		return nil
	}
	n, ok := p.readLen()
	if !ok || !p.lit(":{") {
		return nil
	}
	p.depth++
	defer func() { p.depth-- }()
	entries := make([]kv, 0, clamp(n))
	for i := 0; i < n && !p.res.Truncated; i++ {
		key := p.readValue()
		val := p.readValue()
		entries = append(entries, kv{key: key, val: val})
	}
	p.lit("}")
	return renderArray(entries)
}

func (p *parser) readObject() any {
	if !p.lit("O:") {
		return nil
	}
	class := p.readSizedClassName()
	if p.res.Truncated {
		return nil
	}
	p.recordClass(class)
	n, ok := p.readLen()
	if !ok || !p.lit(":{") {
		return map[string]any{"__class": class}
	}
	p.depth++
	defer func() { p.depth-- }()
	out := map[string]any{"__class": class}
	for i := 0; i < n && !p.res.Truncated; i++ {
		rawKey := p.readValue()
		val := p.readValue()
		out[demangle(toStr(rawKey))] = val
	}
	p.lit("}")
	return out
}

// readCustom parses C:<len>:"<Class>":<datalen>:{<opaque>} (a Serializable's
// own wire format — the data is not the standard grammar, so it is surfaced as
// an opaque length, never parsed/guessed).
func (p *parser) readCustom() any {
	if !p.lit("C:") {
		return nil
	}
	class := p.readSizedClassName()
	if p.res.Truncated {
		return nil
	}
	p.recordClass(class)
	dl, ok := p.readLen()
	if !ok || !p.lit(":{") {
		return map[string]any{"__class": class, "__serializable": true}
	}
	if dl < 0 || p.pos+dl > len(p.s) {
		p.truncate("custom-object data length runs past end of input")
		return map[string]any{"__class": class, "__serializable": true}
	}
	p.pos += dl
	p.lit("}")
	return map[string]any{"__class": class, "__serializable": true, "__data_len": dl}
}

func (p *parser) readEnum() any {
	if !p.lit("E:") {
		return nil
	}
	v := p.readSizedString()
	if class, _, ok := strings.Cut(v, ":"); ok {
		p.recordClass(class)
	}
	return map[string]any{"__enum": v}
}

func (p *parser) readReference(marker byte) any {
	if !p.lit(string(marker) + ":") {
		return nil
	}
	tok := p.readUntil(';')
	if p.res.Truncated {
		return nil
	}
	return map[string]any{"__ref": tok}
}

// readSizedClassName reads <len>:"<Class>": and returns the class name.
func (p *parser) readSizedClassName() string {
	n, ok := p.readLen()
	if !ok || !p.lit(`:"`) {
		return ""
	}
	if n < 0 || p.pos+n > len(p.s) {
		p.truncate("class-name length runs past end of input")
		return ""
	}
	name := string(p.s[p.pos : p.pos+n])
	p.pos += n
	p.lit(`":`)
	return name
}

// --- low-level helpers ------------------------------------------------------

func (p *parser) peek() (byte, bool) {
	if p.pos >= len(p.s) {
		return 0, false
	}
	return p.s[p.pos], true
}

func (p *parser) u8() (byte, bool) {
	if p.pos >= len(p.s) {
		p.truncate("unexpected end of input")
		return 0, false
	}
	v := p.s[p.pos]
	p.pos++
	return v, true
}

// lit consumes an exact literal; on mismatch it truncates.
func (p *parser) lit(want string) bool {
	if p.pos+len(want) > len(p.s) || string(p.s[p.pos:p.pos+len(want)]) != want {
		p.truncate(fmt.Sprintf("expected %q at offset %d", want, p.pos))
		return false
	}
	p.pos += len(want)
	return true
}

// readUntil reads up to (and consuming) the delimiter, returning the text
// before it.
func (p *parser) readUntil(delim byte) string {
	start := p.pos
	for p.pos < len(p.s) {
		if p.s[p.pos] == delim {
			tok := string(p.s[start:p.pos])
			p.pos++
			return tok
		}
		p.pos++
	}
	p.truncate(fmt.Sprintf("missing %q delimiter", string(delim)))
	return ""
}

// readLen reads a non-negative length token terminated by ':' (consumed below
// by the caller's lit) — it reads digits only and leaves pos at the ':'.
func (p *parser) readLen() (int, bool) {
	start := p.pos
	for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == start {
		p.truncate("expected a length")
		return 0, false
	}
	n, err := strconv.Atoi(string(p.s[start:p.pos]))
	if err != nil {
		p.truncate("length overflow")
		return 0, false
	}
	return n, true
}

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

type kv struct {
	key any
	val any
}

// renderArray renders a PHP array as a list when its keys are 0..n-1 (a
// sequential list), else as a string-keyed map (preserving mixed keys).
func renderArray(entries []kv) any {
	isList := true
	for i, e := range entries {
		if n, ok := e.key.(int64); !ok || int(n) != i {
			isList = false
			break
		}
	}
	if isList {
		out := make([]any, len(entries))
		for i, e := range entries {
			out[i] = e.val
		}
		return out
	}
	out := make(map[string]any, len(entries))
	for _, e := range entries {
		out[toStr(e.key)] = e.val
	}
	return out
}

// demangle resolves PHP's private/protected property-key mangling.
func demangle(k string) string {
	if !strings.HasPrefix(k, "\x00") {
		return k
	}
	parts := strings.Split(k, "\x00")
	// "\0*\0prop" (protected) or "\0Class\0prop" (private).
	if len(parts) >= 3 {
		if parts[1] == "*" {
			return parts[2] + " (protected)"
		}
		return parts[2] + " (private:" + parts[1] + ")"
	}
	return k
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func topType(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case int64:
		return "int"
	case float64, string:
		if _, ok := t.(string); ok {
			return "string"
		}
		return "double"
	case []any:
		return "array"
	case map[string]any:
		if _, ok := t["__class"]; ok {
			return "object"
		}
		if _, ok := t["__enum"]; ok {
			return "enum"
		}
		if _, ok := t["__ref"]; ok {
			return "reference"
		}
		return "array"
	default:
		return "unknown"
	}
}

func noteFor(res *Result) string {
	base := "Parsed only — nothing was instantiated. "
	if len(res.GadgetClasses) > 0 {
		base += "DANGEROUS: known PHP Object Injection gadget class(es) present — " + strings.Join(res.GadgetClasses, "; ") + ". Treat as a likely POI/RCE payload. "
	} else if res.ObjectInjection {
		base += "Contains serialized object(s): " + strings.Join(res.Classes, ", ") + ". Any object reaching unserialize() is an object-injection surface (its magic methods run). "
	}
	if res.Truncated {
		base += "Parsing stopped early (" + res.Note + "). "
	}
	if !res.ObjectInjection && !res.Truncated {
		base += "Plain data, no serialized objects. "
	}
	return strings.TrimSpace(base)
}

func trimWS(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func clamp(n int) int {
	if n < 0 || n > 1024 {
		return 0
	}
	return n
}
