package nskeyed

import (
	"encoding/base64"
	"reflect"
	"testing"
)

// Vectors are real NSKeyedArchiver blobs produced by bpylist2.archiver.archive
// (the venv oracle); the expected resolution matches bpylist2.unarchive (dates
// rendered as RFC 3339, NSData as hex).
const (
	vDictArchive = "YnBsaXN0MDDUAQIDBAUGLTBZJGFyY2hpdmVyWCRvYmplY3RzVCR0b3BYJHZlcnNpb25fEA9OU0tleWVkQXJjaGl2ZXKuBwgXHB0eHyAhJikqKyxVJG51bGzTCQoLDA0SViRjbGFzc1dOUy5rZXlzWk5TLm9iamVjdHOAAqQODxARgAOABYAHgAykExQVFoAEgAaACIAN0hgZGhtYJGNsYXNzZXNaJGNsYXNzbmFtZaEbXE5TRGljdGlvbmFyeVh1c2VybmFtZVVhbGljZVVjb3VudBAqVHRhZ3PSCQsiI4AJoiQlgAqAC9IYGScooShXTlNBcnJheVVhZG1pblN2cG5WYWN0aXZlCdEuL1Ryb290gAESAAGGoAAIABEAGwAkACkAMgBEAFMAWQBgAGcAbwB6AHwAgQCDAIUAhwCJAI4AkACSAJQAlgCbAKQArwCxAL4AxwDNANMA1QDaAN8A4QDkAOYA6ADtAO8A9wD9AQEBCAEJAQwBEQETAAAAAAAAAgEAAAAAAAAAMQAAAAAAAAAAAAAAAAAAARg="
	vDateData    = "YnBsaXN0MDDUAQIDBAUGOTxZJGFyY2hpdmVyWCRvYmplY3RzVCR0b3BYJHZlcnNpb25fEA9OU0tleWVkQXJjaGl2ZXKvEBAHCBUaGx8iIyQlKi0yMzQ4VSRudWxs0wkKCwwNEVYkY2xhc3NXTlMua2V5c1pOUy5vYmplY3RzgAKjDg8QgAOABoAIoxITFIAEgAeACdIWFxgZWCRjbGFzc2VzWiRjbGFzc25hbWWhGVxOU0RpY3Rpb25hcnlXY3JlYXRlZNIJHB0eV05TLnRpbWWABSNBwzMsYAAAANIWFyAhoSFWTlNEYXRlVGJsb2JDAQL/VWl0ZW1z0gkLJieACqIoKYALgA7SFhcrLKEsV05TQXJyYXnTCQoLDC4woS+ADKExgA1RaxAB0wkKCww1NqEvoTeADxAC0To7VHJvb3SAARIAAYagAAgAEQAbACQAKQAyAEQAVwBdAGQAawBzAH4AgACEAIYAiACKAI4AkACSAJQAmQCiAK0ArwC8AMQAyQDRANMA3ADhAOMA6gDvAPMA+QD+AQABAwEFAQcBDAEOARYBHQEfASEBIwElAScBKQEwATIBNAE2ATgBOwFAAUIAAAAAAAACAQAAAAAAAAA9AAAAAAAAAAAAAAAAAAABRw=="
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
	return r
}

func TestDecode_DictArchive(t *testing.T) {
	r := decode(t, vDictArchive)
	if r.Archiver != "NSKeyedArchiver" || r.Version != 100000 {
		t.Errorf("archiver=%q version=%d", r.Archiver, r.Version)
	}
	want := map[string]any{
		"username": "alice",
		"count":    int64(42),
		"tags":     []any{"admin", "vpn"},
		"active":   true,
	}
	if !reflect.DeepEqual(r.Root, want) {
		t.Errorf("root =\n %#v\nwant\n %#v", r.Root, want)
	}
}

func TestDecode_DateDataNested(t *testing.T) {
	r := decode(t, vDateData)
	m, ok := r.Root.(map[string]any)
	if !ok {
		t.Fatalf("root = %T", r.Root)
	}
	if m["created"] != "2021-06-01T12:00:00Z" {
		t.Errorf("created = %v, want 2021-06-01T12:00:00Z", m["created"])
	}
	if m["blob"] != "0102ff" {
		t.Errorf("blob = %v, want 0102ff", m["blob"])
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("items = %+v", m["items"])
	}
	if !reflect.DeepEqual(items, []any{map[string]any{"k": int64(1)}, map[string]any{"k": int64(2)}}) {
		t.Errorf("items = %#v", items)
	}
}

func TestDecode_Errors(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"plain bplist": mustB64(t, "YnBsaXN0MDDRAQJUYmxvYkQBAgP/CAsQAAAAAAAAAQEAAAAAAAAAAwAAAAAAAAAAAAAAAAAAABU="), // a non-archiver bplist
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{vDictArchive, vDateData} {
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Decode(in)
	})
}
