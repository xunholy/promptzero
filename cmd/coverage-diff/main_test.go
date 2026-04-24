package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// canonicalize
// ---------------------------------------------------------------------------

func TestCanonicalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"nfc-magic", "nfcmagic"},
		{"nfc_magic", "nfcmagic"},
		{"NFC Magic", "nfcmagic"},
		{"NFC_MAGIC", "nfcmagic"},
		{"SubGHz-Rx", "subghzrx"},
		{"wifi_port_scan", "wifiportscan"},
		{"already", "already"},
		{"", ""},
	}
	for _, tc := range cases {
		got := canonicalize(tc.in)
		if got != tc.want {
			t.Errorf("canonicalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ExtractTokens
// ---------------------------------------------------------------------------

func TestExtractTokens_LinkTexts(t *testing.T) {
	md := []byte(`
# Test
- [device_info](https://example.com) - Known tool
- [nfc_magic](https://example.com) - NFC Magic FAP
- [SubGHz Bruteforcer](https://example.com) - Brute force
`)
	toks := ExtractTokens(md)
	want := map[string]bool{
		"deviceinfo":        true,
		"nfcmagic":          true,
		"subghzbruteforcer": true,
	}
	got := make(map[string]bool)
	for _, tok := range toks {
		got[tok] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("ExtractTokens: expected token %q, got %v", w, toks)
		}
	}
}

func TestExtractTokens_FencedCode(t *testing.T) {
	md := []byte("# Code\n\n```bash\nnfc_read_tag\nstorage_list /ext\n```\n")
	toks := ExtractTokens(md)
	tokenSet := make(map[string]bool)
	for _, tok := range toks {
		tokenSet[tok] = true
	}
	if !tokenSet["nfcreadtag"] {
		t.Errorf("ExtractTokens: expected 'nfcreadtag' from fenced code, got %v", toks)
	}
	if !tokenSet["storagelist"] {
		t.Errorf("ExtractTokens: expected 'storagelist' from fenced code, got %v", toks)
	}
}

func TestExtractTokens_InlineCode(t *testing.T) {
	md := []byte("Use `ble_spam` to spam BLE. Also try `wifi_scan_ap`.")
	toks := ExtractTokens(md)
	tokenSet := make(map[string]bool)
	for _, tok := range toks {
		tokenSet[tok] = true
	}
	if !tokenSet["blespam"] {
		t.Errorf("ExtractTokens: expected 'blespam' from inline code, got %v", toks)
	}
	if !tokenSet["wifiscanap"] {
		t.Errorf("ExtractTokens: expected 'wifiscanap' from inline code, got %v", toks)
	}
}

func TestExtractTokens_StopwordsAndShortDropped(t *testing.T) {
	// "this" is a stopword; "go" is < 4 chars; both must be absent.
	md := []byte("[this](https://example.com) [go](https://example.com)")
	toks := ExtractTokens(md)
	for _, tok := range toks {
		if tok == "this" {
			t.Errorf("stopword 'this' should have been filtered, got %v", toks)
		}
		if tok == "go" {
			t.Errorf("short token 'go' (< 4 chars) should have been filtered, got %v", toks)
		}
	}
}

func TestExtractTokens_Deduplication(t *testing.T) {
	md := []byte(`
- [nfc_magic](https://a.com) first mention
- [nfc_magic](https://b.com) second mention (should dedup)
`)
	toks := ExtractTokens(md)
	count := 0
	for _, tok := range toks {
		if tok == "nfcmagic" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("ExtractTokens: expected 'nfcmagic' exactly once, got %d times in %v",
			count, toks)
	}
}

// TestExtractTokens_Fixtures runs each frozen testdata README through the
// tokenizer and checks structural invariants (present vs. empty token sets).
func TestExtractTokens_Fixtures(t *testing.T) {
	cases := []struct {
		file      string
		wantEmpty bool
	}{
		{"testdata/perfect.md", false},
		{"testdata/partial.md", false},
		{"testdata/empty.md", true},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		toks := ExtractTokens(data)
		if tc.wantEmpty && len(toks) != 0 {
			t.Errorf("%s: expected 0 tokens, got %d: %v", tc.file, len(toks), toks)
		}
		if !tc.wantEmpty && len(toks) == 0 {
			t.Errorf("%s: expected >0 tokens, got 0", tc.file)
		}
	}
}

// ---------------------------------------------------------------------------
// matchesAnyTool
// ---------------------------------------------------------------------------

func TestMatchesAnyTool(t *testing.T) {
	canonTools := []string{"deviceinfo", "nfcread", "storagelist", "subghzrx"}

	cases := []struct {
		token string
		want  bool
	}{
		{"deviceinfo", true},    // exact match
		{"nfcread", true},       // exact match
		{"storagelist", true},   // exact match
		{"device", true},        // substring of "deviceinfo"
		{"alienscanner", false}, // no match
		{"quantumleap", false},  // no match
	}
	for _, tc := range cases {
		got := matchesAnyTool(tc.token, canonTools)
		if got != tc.want {
			t.Errorf("matchesAnyTool(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// classify
// ---------------------------------------------------------------------------

// mockToolNames is the frozen tool list used in classify tests so they do not
// depend on the live registry (which would import hardware packages).
var mockToolNames = []string{
	"device_info", "device_reboot",
	"nfc_read", "nfc_write",
	"storage_list", "storage_read",
	"subghz_rx", "subghz_tx",
}

func TestClassify_PerfectFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/perfect.md")
	if err != nil {
		t.Fatal(err)
	}
	toks := ExtractTokens(data)
	matched, _ := classify(toks, mockToolNames, nil)

	matchedSet := make(map[string]bool)
	for _, m := range matched {
		matchedSet[m] = true
	}
	for _, want := range []string{"deviceinfo", "nfcread", "subghzrx", "storagelist"} {
		if !matchedSet[want] {
			t.Errorf("classify/perfect: expected %q in matched, got matched=%v",
				want, matched)
		}
	}
}

func TestClassify_PartialFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/partial.md")
	if err != nil {
		t.Fatal(err)
	}
	toks := ExtractTokens(data)
	matched, gaps := classify(toks, mockToolNames, nil)

	matchedSet := make(map[string]bool)
	for _, m := range matched {
		matchedSet[m] = true
	}
	gapSet := make(map[string]bool)
	for _, g := range gaps {
		gapSet[g] = true
	}

	// Known tools present in the fixture.
	for _, want := range []string{"deviceinfo", "nfcread"} {
		if !matchedSet[want] {
			t.Errorf("classify/partial: expected %q in matched, got %v", want, matched)
		}
	}
	// Gap candidates that appear in the fixture.
	for _, want := range []string{"magicwand", "alienscanner", "quantumleap"} {
		if !gapSet[want] {
			t.Errorf("classify/partial: expected %q in gaps, got %v", want, gaps)
		}
	}
}

func TestClassify_EmptyFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/empty.md")
	if err != nil {
		t.Fatal(err)
	}
	toks := ExtractTokens(data)
	matched, gaps := classify(toks, mockToolNames, nil)
	if len(matched) != 0 || len(gaps) != 0 {
		t.Errorf("classify/empty: want 0 matched+gaps, got matched=%v gaps=%v",
			matched, gaps)
	}
}

func TestClassify_BlockedAllowlist(t *testing.T) {
	tokens := []string{"alienscanner", "magicwand", "deviceinfo"}
	blocked := map[string]struct{}{"alienscanner": {}}
	_, gaps := classify(tokens, mockToolNames, blocked)
	for _, g := range gaps {
		if g == "alienscanner" {
			t.Errorf("classify: blocked token 'alienscanner' must not appear in gaps")
		}
	}
}

func TestClassify_OutputIsSorted(t *testing.T) {
	tokens := []string{"zebra", "alpha", "mango", "deviceinfo"}
	_, gaps := classify(tokens, mockToolNames, nil)
	if !sort.StringsAreSorted(gaps) {
		t.Errorf("classify: gaps are not sorted: %v", gaps)
	}
}

// ---------------------------------------------------------------------------
// loadOutOfScope
// ---------------------------------------------------------------------------

func TestLoadOutOfScope_AbsentFile(t *testing.T) {
	m := loadOutOfScope("/nonexistent/path/out-of-scope.yaml")
	if len(m) != 0 {
		t.Errorf("loadOutOfScope: absent file should return empty map, got %v", m)
	}
}

func TestLoadOutOfScope_ValidFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "oos-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("tokens:\n  - nfc_magic\n  - ble_spam\n")
	f.Close()

	m := loadOutOfScope(f.Name())
	if _, ok := m["nfcmagic"]; !ok {
		t.Errorf("loadOutOfScope: expected 'nfcmagic' in map, got %v", m)
	}
	if _, ok := m["blespam"]; !ok {
		t.Errorf("loadOutOfScope: expected 'blespam' in map, got %v", m)
	}
}

// ---------------------------------------------------------------------------
// FetchContent (uses httptest to avoid real network calls)
// ---------------------------------------------------------------------------

func TestFetchContent_Success(t *testing.T) {
	const body = "# Test README\n\n- [nfc_magic](https://example.com)\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := FetchContent(srv.URL, false)
	if err != nil {
		t.Fatalf("FetchContent: unexpected error: %v", err)
	}
	if got != body {
		t.Errorf("FetchContent: got %q, want %q", got, body)
	}
}

func TestFetchContent_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := FetchContent(srv.URL, false)
	if err == nil {
		t.Error("FetchContent: expected error for HTTP 404, got nil")
	}
}

func TestFetchContent_Cache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte("cached content"))
	}))
	defer srv.Close()

	// Point the OS temp dir at a test-scoped directory so the cache file
	// is cleaned up automatically and doesn't bleed between runs.
	t.Setenv("TMPDIR", t.TempDir())

	c1, err := FetchContent(srv.URL, true)
	if err != nil {
		t.Fatalf("first FetchContent: %v", err)
	}
	c2, err := FetchContent(srv.URL, true)
	if err != nil {
		t.Fatalf("second FetchContent (cache hit): %v", err)
	}
	if c1 != c2 {
		t.Errorf("cached content mismatch: %q vs %q", c1, c2)
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 HTTP call (cache hit on second), got %d", calls)
	}
}

// ---------------------------------------------------------------------------
// RenderMarkdown
// ---------------------------------------------------------------------------

func TestRenderMarkdown_ContainsSummaryTable(t *testing.T) {
	results := []RepoResult{
		{
			Source:  Source{Name: "test/repo-a", URL: "https://example.com/a"},
			Tokens:  []string{"tok1", "tok2", "tok3"},
			Matched: []string{"tok1"},
			Gaps:    []string{"tok2", "tok3"},
		},
		{
			Source: Source{Name: "test/repo-b", URL: "https://example.com/b"},
			Err:    fmt.Errorf("simulated fetch failure"),
		},
	}
	out := RenderMarkdown(results, "2026-04-24")

	checks := []string{
		"## Summary",
		"test/repo-a",
		"test/repo-b",
		"fetch error",
		"## Gap candidates by repository",
		"`tok2`",
		"`tok3`",
		"2026-04-24",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("RenderMarkdown missing %q\n\nFull output:\n%s", want, out)
		}
	}
}

func TestRenderMarkdown_NoGaps(t *testing.T) {
	results := []RepoResult{
		{
			Source:  Source{Name: "test/perfect", URL: "https://example.com"},
			Tokens:  []string{"tok1"},
			Matched: []string{"tok1"},
			Gaps:    nil,
		},
	}
	out := RenderMarkdown(results, "2026-04-24")
	if !strings.Contains(out, "No gaps") {
		t.Errorf("RenderMarkdown: expected 'No gaps' for empty gap list\n\nOutput:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// cacheKey
// ---------------------------------------------------------------------------

func TestCacheKey_Deterministic(t *testing.T) {
	url := "https://raw.githubusercontent.com/djsime1/awesome-flipperzero/main/README.md"
	k1 := cacheKey(url)
	k2 := cacheKey(url)
	if k1 != k2 {
		t.Errorf("cacheKey not deterministic: got %q then %q", k1, k2)
	}
}

func TestCacheKey_Unique(t *testing.T) {
	k1 := cacheKey("https://example.com/a")
	k2 := cacheKey("https://example.com/b")
	if k1 == k2 {
		t.Errorf("cacheKey collision for different URLs: %q", k1)
	}
}
