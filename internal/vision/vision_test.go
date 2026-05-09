package vision

import "testing"

// TestDetectMediaType pins the path-extension routing the
// Analyzer uses to decide which media type to send to the
// Anthropic vision API.
func TestDetectMediaType(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"foo.png", "image/png"},
		{"foo.PNG", "image/png"},
		{"path/to/foo.png", "image/png"},
		{"foo.gif", "image/gif"},
		{"foo.GIF", "image/gif"},
		{"foo.webp", "image/webp"},
		{"foo.WEBP", "image/webp"},
		{"foo.jpg", "image/jpeg"},
		{"foo.jpeg", "image/jpeg"},
		{"foo.bin", "image/jpeg"}, // unknown → jpeg fallback
		{"", "image/jpeg"},        // empty → jpeg fallback
	}
	for _, c := range cases {
		if got := detectMediaType(c.path); got != c.want {
			t.Errorf("detectMediaType(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// TestParseDataURL_ValidPNG covers the canonical happy path:
// a well-formed data URL is split into media type and payload.
func TestParseDataURL_ValidPNG(t *testing.T) {
	mt, payload, ok := parseDataURL("data:image/png;base64,iVBORw0KGgo=")
	if !ok {
		t.Fatal("ok = false, want true for valid data URL")
	}
	if mt != "image/png" {
		t.Errorf("media type = %q, want image/png", mt)
	}
	if payload != "iVBORw0KGgo=" {
		t.Errorf("payload = %q, want iVBORw0KGgo=", payload)
	}
}

// TestParseDataURL_ValidJPEG covers a different media type to
// confirm the parser doesn't hardcode image/png.
func TestParseDataURL_ValidJPEG(t *testing.T) {
	mt, payload, ok := parseDataURL("data:image/jpeg;base64,/9j/4AAQ")
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if mt != "image/jpeg" {
		t.Errorf("media type = %q, want image/jpeg", mt)
	}
	if payload != "/9j/4AAQ" {
		t.Errorf("payload = %q, want /9j/4AAQ", payload)
	}
}

// TestParseDataURL_NoPrefix pins the fallback contract: raw base64
// without the "data:" prefix is rejected so callers default to
// treating the input as a raw payload.
func TestParseDataURL_NoPrefix(t *testing.T) {
	_, _, ok := parseDataURL("iVBORw0KGgo=")
	if ok {
		t.Error("ok = true for raw base64 without data: prefix, want false")
	}
}

// TestParseDataURL_NoDelimiter pins the rejection of inputs that
// have a "data:" prefix but no ";base64," delimiter.
func TestParseDataURL_NoDelimiter(t *testing.T) {
	_, _, ok := parseDataURL("data:image/png,raw")
	if ok {
		t.Error("ok = true for data URL without ;base64, delimiter, want false")
	}
}

// TestParseDataURL_PanicSlicePathRegression is the regression
// pin for the bug this commit fixes. The previous implementation
// ran `b64data[5:idx]` unconditionally; an input where idx<5
// (i.e. ";base64," appears in the first five bytes) would slice-
// bounds-panic. Confirm parseDataURL returns ok=false instead.
func TestParseDataURL_PanicSlicePathRegression(t *testing.T) {
	// Crafted to put ";base64," at index 1, so the old code's
	// b64data[5:1] would have panicked.
	_, _, ok := parseDataURL("X;base64,real_data")
	if ok {
		t.Error("ok = true for malformed prefix, want false (regression)")
	}
}

// TestParseDataURL_EmptyPayload covers the boundary where the
// data URL is well-formed but the payload is empty. parseDataURL
// returns ok=true with an empty payload — the caller is responsible
// for further validation.
func TestParseDataURL_EmptyPayload(t *testing.T) {
	mt, payload, ok := parseDataURL("data:image/png;base64,")
	if !ok {
		t.Fatal("ok = false, want true even for empty payload")
	}
	if mt != "image/png" {
		t.Errorf("media type = %q, want image/png", mt)
	}
	if payload != "" {
		t.Errorf("payload = %q, want empty", payload)
	}
}

// TestParseDataURL_Empty covers the edge case of an empty input.
// The "data:" prefix check fails, so ok=false.
func TestParseDataURL_Empty(t *testing.T) {
	_, _, ok := parseDataURL("")
	if ok {
		t.Error("ok = true for empty string, want false")
	}
}

// FuzzParseDataURL is a no-panic guarantee over arbitrary input.
// The original bug this helper fixes (b64data[5:idx] with idx<5)
// was a slice-bounds panic on attacker-shaped input. Run with
// `go test -fuzz=FuzzParseDataURL ./internal/vision/` to extend
// coverage; the corpus seeds cover the boundaries the unit tests
// already pin (data: prefix, ;base64, delim, off-by-N positions).
func FuzzParseDataURL(f *testing.F) {
	for _, seed := range []string{
		"",                          // empty
		"data:",                     // prefix only
		"data:;base64,",             // empty mediatype + payload
		"data:image/png;base64,abc", // canonical
		"X;base64,real_data",        // regression: idx<len("data:")
		";base64,",                  // delim at start
		"data:image/png",            // no delim
		":base64,",                  // close-but-not-prefix
		"data",                      // truncated prefix
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		mt, payload, ok := parseDataURL(s)
		// Contract: ok=false implies both returns are empty; the
		// caller treats malformed inputs as raw base64 and ignores
		// the (mt, payload) pair entirely.
		if !ok && (mt != "" || payload != "") {
			t.Errorf("parseDataURL(%q) ok=false but mt=%q payload=%q (must both be empty)",
				s, mt, payload)
		}
		// Implicit assertion: the call returned without panicking.
	})
}
