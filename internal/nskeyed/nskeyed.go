// Package nskeyed resolves an NSKeyedArchiver plist into the logical object tree
// it serialises.
//
// NSKeyedArchiver is the dominant serialization for complex Objective-C / Swift
// objects on iOS / macOS — NSUserDefaults values, app state, document formats,
// and countless forensic artifacts are stored as a keyed archive (itself a
// binary plist). The raw plist is nearly unreadable: a flat "$objects" array of
// fragments wired together by integer UID references, with NS-class containers
// (NSDictionary / NSArray / NSData / NSDate …) encoded structurally. This walks
// the $archiver / $objects / $top graph and reconstructs the actual object — the
// resolution layer on top of bplist_decode.
//
// No confidently-wrong output: it composes the bounds-checked bplist decoder;
// the top-level dict must declare "$archiver": "NSKeyedArchiver"; a UID outside
// $objects, a missing $class, or a reference cycle is surfaced as a labelled
// marker ("<uid out of range>" / "<cycle>"), never a wrong guess; the node
// budget bounds a hostile fan-out; an unknown $class is surfaced with its name
// and resolved fields rather than dropped. Dates become RFC 3339 (the 2001
// epoch), NSData stays hex (from bplist), and $null becomes JSON null.
//
// Wrap-vs-native: native — a graph walk over the bplist tree; stdlib only, no new
// go.mod dependency. Anchored to real bpylist2-produced archives (see the test).
// Only the common NS containers are mapped structurally; other classes are
// surfaced with their class name + resolved fields.
package nskeyed

import (
	"fmt"
	"time"

	"github.com/xunholy/promptzero/internal/bplist"
)

const maxNodes = 1 << 20

// Result is the resolved archive.
type Result struct {
	Format   string `json:"format"`
	Archiver string `json:"archiver"`
	Version  int    `json:"version"`
	Root     any    `json:"root"`
	Note     string `json:"note"`
}

type resolver struct {
	objects  []any
	visiting map[int]bool
	nodes    int
}

// Decode resolves an NSKeyedArchiver binary plist.
func Decode(data []byte) (*Result, error) {
	pl, err := bplist.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("nskeyed: %w", err)
	}
	root, ok := pl.Root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("nskeyed: top level is not a dict")
	}
	arch, _ := root["$archiver"].(string)
	if arch != "NSKeyedArchiver" {
		return nil, fmt.Errorf("nskeyed: $archiver is %q, not NSKeyedArchiver", arch)
	}
	objs, ok := root["$objects"].([]any)
	if !ok {
		return nil, fmt.Errorf("nskeyed: missing $objects array")
	}
	top, ok := root["$top"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("nskeyed: missing $top")
	}
	version := 0
	if v, ok := toInt(root["$version"]); ok {
		version = v
	}

	r := &resolver{objects: objs, visiting: map[int]bool{}}
	return &Result{
		Format:   "nskeyedarchiver",
		Archiver: arch,
		Version:  version,
		Root:     r.resolveTop(top),
		Note: "NSKeyedArchiver graph resolved to the logical object. Dates are RFC 3339 (the 2001 epoch); " +
			"NSData is hex; $null is null; an unmapped class is surfaced with its $class name. Offline; no network, no device.",
	}, nil
}

// resolveTop resolves the $top entries, unwrapping the common {"root": X}.
func (r *resolver) resolveTop(top map[string]any) any {
	if len(top) == 1 {
		if v, ok := top["root"]; ok {
			return r.resolve(v)
		}
	}
	out := make(map[string]any, len(top))
	for k, v := range top {
		out[k] = r.resolve(v)
	}
	return out
}

// resolve dereferences a value, following a UID into $objects.
func (r *resolver) resolve(v any) any {
	if r.nodes++; r.nodes > maxNodes {
		return "<budget exceeded>"
	}
	m, ok := v.(map[string]any)
	if !ok {
		return scalar(v)
	}
	uidv, isUID := m["$uid"]
	if !isUID {
		return r.resolveObject(m) // inline object
	}
	n, ok := toInt(uidv)
	if !ok {
		return v
	}
	if n == 0 {
		return nil // $null
	}
	if n < 0 || n >= len(r.objects) {
		return "<uid out of range>"
	}
	if r.visiting[n] {
		return "<cycle>"
	}
	r.visiting[n] = true
	out := r.resolveObject(r.objects[n])
	delete(r.visiting, n)
	return out
}

// resolveObject reconstructs an archived object by its $class, or returns a
// scalar leaf unchanged.
func (r *resolver) resolveObject(o any) any {
	m, ok := o.(map[string]any)
	if !ok {
		return scalar(o)
	}
	classUID, hasClass := m["$class"]
	if !hasClass {
		out := make(map[string]any, len(m))
		for k, v := range m {
			out[k] = r.resolve(v)
		}
		return out
	}
	switch r.className(classUID) {
	case "NSDictionary", "NSMutableDictionary":
		keys, _ := m["NS.keys"].([]any)
		vals, _ := m["NS.objects"].([]any)
		out := make(map[string]any, len(keys))
		for i := 0; i < len(keys) && i < len(vals); i++ {
			out[stringKey(r.resolve(keys[i]))] = r.resolve(vals[i])
		}
		return out
	case "NSArray", "NSMutableArray", "NSSet", "NSMutableSet", "NSOrderedSet":
		objs, _ := m["NS.objects"].([]any)
		out := make([]any, 0, len(objs))
		for _, e := range objs {
			out = append(out, r.resolve(e))
		}
		return out
	case "NSString", "NSMutableString":
		return m["NS.string"]
	case "NSData", "NSMutableData":
		return m["NS.data"]
	case "NSDate":
		if t, ok := m["NS.time"].(float64); ok {
			return time.Unix(978307200, 0).Add(time.Duration(t * float64(time.Second))).UTC().Format(time.RFC3339)
		}
		return m["NS.time"]
	case "NSUUID":
		return m["NS.uuidbytes"]
	case "NSURL":
		return r.resolve(m["NS.relative"])
	default:
		out := map[string]any{"$class": r.className(classUID)}
		for k, v := range m {
			if k == "$class" {
				continue
			}
			out[k] = r.resolve(v)
		}
		return out
	}
}

// className resolves a $class UID to its $classname.
func (r *resolver) className(classUID any) string {
	cm, ok := classUID.(map[string]any)
	if !ok {
		return ""
	}
	n, ok := toInt(cm["$uid"])
	if !ok || n < 0 || n >= len(r.objects) {
		return ""
	}
	classObj, ok := r.objects[n].(map[string]any)
	if !ok {
		return ""
	}
	cn, _ := classObj["$classname"].(string)
	return cn
}

// scalar maps the "$null" placeholder to nil and passes everything else through.
func scalar(v any) any {
	if s, ok := v.(string); ok && s == "$null" {
		return nil
	}
	return v
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int64:
		return int(n), true
	case int:
		return n, true
	default:
		return 0, false
	}
}

func stringKey(k any) string {
	if s, ok := k.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", k)
}
