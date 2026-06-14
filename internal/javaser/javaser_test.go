package javaser

import (
	"encoding/base64"
	"strings"
	"testing"
)

// All vectors are real java.io.ObjectOutputStream output (javac/java), one per
// shape. b64-encoded.
const (
	vString    = "rO0ABXQAC2hlbGxvIHdvcmxk"
	vArrayList = "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdwQAAAACdAABYXQAAWJ4"
	vHashMap   = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdXNlcnNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAqeA=="
	vCreds     = "rO0ABXNyAApHZW4yJENyZWRzAAAAAAAAAAECAAVaAAZhY3RpdmVKAAJpZEkABWxldmVsTAAFcm9sZXN0ABBMamF2YS91dGlsL0xpc3Q7TAAEdXNlcnQAEkxqYXZhL2xhbmcvU3RyaW5nO3hwAQAAAAEAAAAAAAAAB3NyABpqYXZhLnV0aWwuQXJyYXlzJEFycmF5TGlzdNmkPL7NiAbSAgABWwABYXQAE1tMamF2YS9sYW5nL09iamVjdDt4cHVyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAJ0AAFhdAABYnQABWFkbWlu"
	vNested    = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEbGlzdHNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdwQAAAABdAABenh4"
	vStrArr    = "rO0ABXVyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAN0AAFwdAABcXQAAXI="
)

func decode(t *testing.T, b64 string) *Result {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	r, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Truncated {
		t.Fatalf("unexpected truncation: %s", r.Note)
	}
	return r
}

func TestDecode_String(t *testing.T) {
	r := decode(t, vString)
	if r.Version != 5 {
		t.Errorf("version = %d, want 5", r.Version)
	}
	if !contains(r.Strings, "hello world") {
		t.Errorf("strings = %v", r.Strings)
	}
	if len(r.Classes) != 0 {
		t.Errorf("a plain string has no classes, got %v", r.Classes)
	}
}

func TestDecode_ArrayList(t *testing.T) {
	r := decode(t, vArrayList)
	if r.TopLevel != "java.util.ArrayList" {
		t.Errorf("top = %q", r.TopLevel)
	}
	if !contains(r.Classes, "java.util.ArrayList") {
		t.Errorf("classes = %v", r.Classes)
	}
	if !contains(r.Strings, "a") || !contains(r.Strings, "b") {
		t.Errorf("strings = %v", r.Strings)
	}
}

func TestDecode_HashMap(t *testing.T) {
	r := decode(t, vHashMap)
	for _, want := range []string{"java.util.HashMap", "java.lang.Integer", "java.lang.Number"} {
		if !contains(r.Classes, want) {
			t.Errorf("classes missing %q: %v", want, r.Classes)
		}
	}
	if !contains(r.Strings, "user") {
		t.Errorf("strings = %v", r.Strings)
	}
}

func TestDecode_CustomClass(t *testing.T) {
	r := decode(t, vCreds)
	if r.TopLevel != "Gen2$Creds" {
		t.Errorf("top = %q", r.TopLevel)
	}
	for _, want := range []string{"Gen2$Creds", "java.util.Arrays$ArrayList"} {
		if !contains(r.Classes, want) {
			t.Errorf("classes missing %q: %v", want, r.Classes)
		}
	}
	if !contains(r.Strings, "admin") {
		t.Errorf("expected the 'user' field value 'admin' in strings: %v", r.Strings)
	}
}

func TestDecode_Nested(t *testing.T) {
	r := decode(t, vNested)
	for _, want := range []string{"java.util.HashMap", "java.util.ArrayList"} {
		if !contains(r.Classes, want) {
			t.Errorf("classes missing %q: %v", want, r.Classes)
		}
	}
	if !contains(r.Strings, "list") || !contains(r.Strings, "z") {
		t.Errorf("strings = %v", r.Strings)
	}
}

func TestDecode_StringArray(t *testing.T) {
	r := decode(t, vStrArr)
	if !strings.Contains(r.TopLevel, "java.lang.String") {
		t.Errorf("top = %q", r.TopLevel)
	}
	for _, s := range []string{"p", "q", "r"} {
		if !contains(r.Strings, s) {
			t.Errorf("strings missing %q: %v", s, r.Strings)
		}
	}
}

// TestDecode_GadgetFlagged hand-builds a minimal valid stream declaring the
// xalan TemplatesImpl class and asserts it is flagged. (Real gadget jars are
// not on the test classpath, so the stream is constructed by hand per the
// grammar: TC_OBJECT TC_CLASSDESC <name> <suid> flags=SERIALIZABLE 0-fields
// TC_ENDBLOCKDATA TC_NULL-super, no class data.)
func TestDecode_GadgetFlagged(t *testing.T) {
	name := "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"
	var b []byte
	b = append(b, 0xAC, 0xED, 0x00, 0x05) // magic + version
	b = append(b, tcObject, tcClassDesc)
	b = append(b, byte(len(name)>>8), byte(len(name))) // utf len
	b = append(b, []byte(name)...)
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // serialVersionUID
	b = append(b, scSerializable)         // flags
	b = append(b, 0, 0)                   // field count = 0
	b = append(b, tcEndBlockData)         // class annotation end
	b = append(b, tcNull)                 // no super
	// no class data (0 fields, no write method)

	r, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Suspicious || len(r.GadgetClasses) == 0 {
		t.Fatalf("expected gadget flag, got %+v", r)
	}
	if !strings.Contains(r.GadgetClasses[0], "TemplatesImpl") {
		t.Errorf("gadget = %v", r.GadgetClasses)
	}
	if !strings.Contains(r.Note, "DANGEROUS") {
		t.Errorf("note = %q", r.Note)
	}
}

func TestGadgetReason(t *testing.T) {
	for _, g := range []string{
		"org.apache.commons.collections.functors.InvokerTransformer",
		"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
		"sun.reflect.annotation.AnnotationInvocationHandler",
		"clojure.core.ArrayChunk",                           // prefix match
		"org.apache.commons.collections4.functors.Whatever", // prefix match
	} {
		if gadgetReason(g) == "" {
			t.Errorf("expected %q to be flagged as a gadget", g)
		}
	}
	for _, ok := range []string{"java.util.HashMap", "java.lang.String", "com.example.User"} {
		if gadgetReason(ok) != "" {
			t.Errorf("did not expect %q to be flagged", ok)
		}
	}
}

func TestDecode_Errors(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":     {},
		"short":     {0xAC},
		"bad magic": {0x00, 0x05, 0x74, 0x00},
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, v := range []string{vString, vArrayList, vHashMap, vCreds, vNested, vStrArr} {
		if b, err := base64.StdEncoding.DecodeString(v); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte{0xAC, 0xED, 0x00, 0x05})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Decode(data) // must never panic
	})
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestDecode_DeepNestBounded builds a deeply-nested array chain past maxDepth
// and asserts Decode bounds the recursion (truncates) instead of overflowing
// the goroutine stack. The first array defines the "[Ljava.lang.Object;" class
// desc (handle 0x7E0000); each nested array references it.
func TestDecode_DeepNestBounded(t *testing.T) {
	const depth = 5000
	elem := "[Ljava.lang.Object;"
	var b []byte
	b = append(b, 0xAC, 0xED, 0x00, 0x05)
	// Outermost array defines the class desc.
	b = append(b, tcArray, tcClassDesc)
	b = append(b, byte(len(elem)>>8), byte(len(elem)))
	b = append(b, []byte(elem)...)
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // suid
	b = append(b, scSerializable, 0, 0)   // flags, 0 fields
	b = append(b, tcEndBlockData, tcNull) // annotations end, null super
	b = append(b, 0, 0, 0, 1)             // size = 1
	// Each deeper array references the class desc and holds one element.
	for i := 1; i < depth; i++ {
		b = append(b, tcArray, tcReference, 0x7E, 0x00, 0x00, 0x00)
		b = append(b, 0, 0, 0, 1) // size = 1
	}
	// Innermost: an empty array (size 0).
	b = append(b, tcArray, tcReference, 0x7E, 0x00, 0x00, 0x00, 0, 0, 0, 0)

	r, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Truncated {
		t.Errorf("expected truncation on a %d-deep nest", depth)
	}
}
