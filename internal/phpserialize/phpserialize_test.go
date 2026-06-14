package phpserialize

import (
	"reflect"
	"testing"
)

func decode(t *testing.T, in string) *Result {
	t.Helper()
	r, err := Decode([]byte(in))
	if err != nil {
		t.Fatalf("Decode(%q): %v", in, err)
	}
	return r
}

func TestScalars(t *testing.T) {
	cases := []struct {
		in   string
		want any
		typ  string
	}{
		{"N;", nil, "null"},
		{"b:1;", true, "bool"},
		{"b:0;", false, "bool"},
		{"i:42;", int64(42), "int"},
		{"i:-7;", int64(-7), "int"},
		{"d:3.5;", 3.5, "double"},
		{`s:5:"hello";`, "hello", "string"},
		{`s:0:"";`, "", "string"},
		// Byte-length-prefixed: the string itself contains ';' and '"'.
		{`s:5:"a;b\"";`, `a;b\"`, "string"},
	}
	for _, c := range cases {
		r := decode(t, c.in)
		if !reflect.DeepEqual(r.Value, c.want) {
			t.Errorf("%q -> %#v, want %#v", c.in, r.Value, c.want)
		}
		if r.Type != c.typ {
			t.Errorf("%q type = %q, want %q", c.in, r.Type, c.typ)
		}
	}
}

func TestArrayList(t *testing.T) {
	r := decode(t, `a:2:{i:0;s:1:"a";i:1;s:1:"b";}`)
	if r.Type != "array" {
		t.Fatalf("type = %q", r.Type)
	}
	want := []any{"a", "b"}
	if !reflect.DeepEqual(r.Value, want) {
		t.Errorf("value = %#v, want %#v", r.Value, want)
	}
}

func TestArrayAssoc(t *testing.T) {
	r := decode(t, `a:2:{s:4:"user";s:5:"admin";s:5:"level";i:7;}`)
	m, ok := r.Value.(map[string]any)
	if !ok {
		t.Fatalf("value type %T", r.Value)
	}
	if m["user"] != "admin" || m["level"] != int64(7) {
		t.Errorf("value = %#v", m)
	}
}

func TestObject(t *testing.T) {
	r := decode(t, `O:4:"User":2:{s:4:"name";s:3:"bob";s:3:"age";i:30;}`)
	if r.Type != "object" || !r.ObjectInjection {
		t.Fatalf("type=%q inj=%v", r.Type, r.ObjectInjection)
	}
	if !contains(r.Classes, "User") {
		t.Errorf("classes = %v", r.Classes)
	}
	m := r.Value.(map[string]any)
	if m["__class"] != "User" || m["name"] != "bob" || m["age"] != int64(30) {
		t.Errorf("value = %#v", m)
	}
}

func TestObject_MangledKeys(t *testing.T) {
	// \0Foo\0id (private, 7 bytes) and \0*\0name (protected, 7 bytes).
	in := "O:3:\"Foo\":2:{s:7:\"\x00Foo\x00id\";i:1;s:7:\"\x00*\x00name\";s:1:\"x\";}"
	r := decode(t, in)
	m := r.Value.(map[string]any)
	if _, ok := m["id (private:Foo)"]; !ok {
		t.Errorf("missing demangled private key: %#v", m)
	}
	if _, ok := m["name (protected)"]; !ok {
		t.Errorf("missing demangled protected key: %#v", m)
	}
}

func TestGadget_Monolog(t *testing.T) {
	// Monolog\Handler\SyslogUdpHandler is 32 bytes.
	r := decode(t, `O:32:"Monolog\Handler\SyslogUdpHandler":0:{}`)
	if !r.Suspicious || len(r.GadgetClasses) == 0 {
		t.Fatalf("expected gadget flag: %+v", r)
	}
	if !containsSub(r.GadgetClasses, "Monolog") {
		t.Errorf("gadget = %v", r.GadgetClasses)
	}
	if !containsSub([]string{r.Note}, "DANGEROUS") {
		t.Errorf("note = %q", r.Note)
	}
}

func TestCustomSerializable(t *testing.T) {
	r := decode(t, `C:3:"Foo":5:{hello}`)
	if !contains(r.Classes, "Foo") {
		t.Errorf("classes = %v", r.Classes)
	}
	m := r.Value.(map[string]any)
	if m["__serializable"] != true || m["__data_len"] != 5 {
		t.Errorf("value = %#v", m)
	}
}

func TestEnum(t *testing.T) {
	r := decode(t, `E:11:"Suit:Hearts";`)
	if !contains(r.Classes, "Suit") {
		t.Errorf("classes = %v", r.Classes)
	}
	if r.Type != "enum" {
		t.Errorf("type = %q", r.Type)
	}
}

func TestReference(t *testing.T) {
	r := decode(t, `a:1:{i:0;r:1;}`)
	list := r.Value.([]any)
	m := list[0].(map[string]any)
	if m["__ref"] != "1" {
		t.Errorf("ref = %#v", m)
	}
}

func TestNestedObjectInArray(t *testing.T) {
	r := decode(t, `a:1:{s:3:"obj";O:4:"Evil":0:{}}`)
	if !r.ObjectInjection || !contains(r.Classes, "Evil") {
		t.Errorf("expected nested object: %+v", r)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "   ", "xyz", "z:1;"} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestTruncatedString(t *testing.T) {
	// Length claims 5 but only 2 bytes follow → graceful truncation.
	r, err := Decode([]byte(`a:1:{i:0;s:5:"ab";}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Truncated {
		t.Errorf("expected truncation, note=%q", r.Note)
	}
}

func TestDeepNestBounded(t *testing.T) {
	// Build a 5000-deep nested-array bomb; must truncate, not overflow.
	var b []byte
	for i := 0; i < 5000; i++ {
		b = append(b, []byte("a:1:{i:0;")...)
	}
	b = append(b, []byte("N;")...)
	for i := 0; i < 5000; i++ {
		b = append(b, '}')
	}
	r, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Truncated {
		t.Errorf("expected depth truncation on a 5000-deep nest")
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		`O:4:"User":1:{s:4:"name";s:3:"bob";}`,
		`a:2:{i:0;s:1:"a";i:1;b:1;}`,
		`C:3:"Foo":5:{hello}`,
		"N;", "i:1;", "",
	} {
		f.Add([]byte(s))
	}
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

func containsSub(xs []string, sub string) bool {
	for _, x := range xs {
		for i := 0; i+len(sub) <= len(x); i++ {
			if x[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
