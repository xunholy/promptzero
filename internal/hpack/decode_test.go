package hpack

import (
	"strings"
	"testing"
)

// TestRFC7541_C21_LiteralWithIndexing pins RFC 7541 §C.2.1:
// "custom-key: custom-header" via literal with incremental
// indexing, name + value both literal (no Huffman).
func TestRFC7541_C21_LiteralWithIndexing(t *testing.T) {
	in := "400a 637573 746f6d 2d6b 6579 0d63 7573 746f6d 2d68 6561 6465 72"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.HeaderCount != 1 {
		t.Fatalf("expected 1 header, got %d", r.HeaderCount)
	}
	h := r.Headers[0]
	if h.Name != "custom-key" || h.Value != "custom-header" {
		t.Errorf("got %q: %q", h.Name, h.Value)
	}
	if h.Representation != "literal_incremental" {
		t.Errorf("representation: %q", h.Representation)
	}
}

// TestRFC7541_C22_LiteralWithoutIndexing pins §C.2.2:
// ":path: /sample/path".
func TestRFC7541_C22_LiteralWithoutIndexing(t *testing.T) {
	in := "040c 2f73616d706c652f70617468"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	h := r.Headers[0]
	if h.Name != ":path" || h.Value != "/sample/path" {
		t.Errorf("got %q: %q", h.Name, h.Value)
	}
	if h.Representation != "literal_without_indexing" {
		t.Errorf("representation: %q", h.Representation)
	}
}

// TestRFC7541_C24_Indexed pins §C.2.4: :method: GET via index 2.
func TestRFC7541_C24_Indexed(t *testing.T) {
	in := "82"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	h := r.Headers[0]
	if h.Name != ":method" || h.Value != "GET" {
		t.Errorf("got %q: %q", h.Name, h.Value)
	}
}

// TestRFC7541_C31_FirstRequest pins §C.3.1 (no Huffman): a
// 4-header GET to www.example.com.
func TestRFC7541_C31_FirstRequest(t *testing.T) {
	in := "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := []struct{ name, value string }{
		{":method", "GET"},
		{":scheme", "http"},
		{":path", "/"},
		{":authority", "www.example.com"},
	}
	if len(r.Headers) != 4 {
		t.Fatalf("expected 4 headers, got %d", len(r.Headers))
	}
	for i, w := range want {
		if r.Headers[i].Name != w.name || r.Headers[i].Value != w.value {
			t.Errorf("header %d: got %q=%q, want %q=%q",
				i, r.Headers[i].Name, r.Headers[i].Value, w.name, w.value)
		}
	}
}

// TestRFC7541_C41_FirstRequestHuffman pins §C.4.1: same 4
// headers but :authority value is Huffman-encoded.
func TestRFC7541_C41_FirstRequestHuffman(t *testing.T) {
	in := "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Headers) != 4 {
		t.Fatalf("expected 4 headers, got %d", len(r.Headers))
	}
	if r.Headers[3].Name != ":authority" ||
		r.Headers[3].Value != "www.example.com" {
		t.Errorf("Huffman-decoded authority: %q=%q",
			r.Headers[3].Name, r.Headers[3].Value)
	}
}

// TestHuffmanRoundTrip exercises a non-trivial Huffman string.
// "no-cache" is encoded per RFC 7541 §C.4.2 as
// 0xa8 0xeb 0x10 0x64 0x9c 0xbf.
func TestHuffmanRoundTrip(t *testing.T) {
	got, err := huffmanDecode([]byte{0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf})
	if err != nil {
		t.Fatalf("huffmanDecode: %v", err)
	}
	if got != "no-cache" {
		t.Errorf("got %q, want 'no-cache'", got)
	}
}

func TestDecode_DynamicTableSizeUpdate(t *testing.T) {
	// 0x20 = 001 00000 = size update to 0; means evict everything.
	in := "20"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.HeaderCount != 0 {
		t.Errorf("expected 0 headers, got %d", r.HeaderCount)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "table size update") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected size-update note in: %v", r.Notes)
	}
}

func TestDecode_LargeIntegerEncoding(t *testing.T) {
	// 7-bit prefix integer encoding example from RFC 7541
	// §5.1.1: 1337 = 0x539 encoded with 5-bit prefix as
	// 0x1F 0x9A 0x0A.
	v, used, err := readInt([]byte{0x1F, 0x9A, 0x0A}, 5)
	if err != nil {
		t.Fatalf("readInt: %v", err)
	}
	if v != 1337 {
		t.Errorf("value: %d", v)
	}
	if used != 3 {
		t.Errorf("used: %d", used)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"odd hex":          "82B",
		"truncated lit":    "400a 6375",
		"truncated string": "82 40",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
