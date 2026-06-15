package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// TestSignalLibrarySearch_RegisteredAtInit pins that the spec is in the
// registry under its canonical name with the right risk + group.
func TestSignalLibrarySearch_RegisteredAtInit(t *testing.T) {
	spec, ok := Get("signal_library_search")
	if !ok {
		t.Fatal("signal_library_search not registered")
	}
	if spec.Risk != risk.Low {
		t.Errorf("Risk = %s, want Low", spec.Risk)
	}
	if spec.Group != GroupMetaUtil {
		t.Errorf("Group = %s, want %s", spec.Group, GroupMetaUtil)
	}
	if spec.AgentOnly {
		t.Error("AgentOnly = true; this tool only walks the host filesystem — it needs no LLM/session and should not carry the advisory flag")
	}
}

// TestSignalLibrarySearch_HandlerReturnsMatchesFromHomeOverride feeds a
// synthetic HOME so the handler walks a temp dir instead of the operator's
// real ~/.promptzero/freqman. This confirms the handler's plumbing —
// query resolution, JSON envelope shape, limit defaulting — without
// depending on the search algorithm itself (which is exercised against the
// fileformat package's own tests).
func TestSignalLibrarySearch_HandlerReturnsMatchesFromHomeOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	libDir := filepath.Join(home, ".promptzero", "freqman")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "f=433920000,m=AM_DSB,d=Garage door, blue button\nf=315000000,d=Car fob\n"
	if err := os.WriteFile(filepath.Join(libDir, "lib.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	spec, ok := Get("signal_library_search")
	if !ok {
		t.Fatal("signal_library_search not registered")
	}

	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"query": "garage"})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	var env struct {
		Root          string `json:"root"`
		Query         string `json:"query"`
		MatchCount    int    `json:"match_count"`
		Limit         int    `json:"limit"`
		ParseWarnings []any  `json:"parse_warnings"`
		Matches       []struct {
			File  string `json:"file"`
			Line  int    `json:"line"`
			Entry struct {
				Frequency   uint64 `json:"Frequency"`
				Description string `json:"Description"`
			} `json:"entry"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("envelope JSON: %v\nout=%s", err, out)
	}
	if env.MatchCount != 1 {
		t.Errorf("match_count = %d, want 1; got %s", env.MatchCount, out)
	}
	if env.Limit != 50 {
		t.Errorf("limit default = %d, want 50", env.Limit)
	}
	if !strings.HasSuffix(env.Root, filepath.Join(".promptzero", "freqman")) {
		t.Errorf("root = %q; want path ending in .promptzero/freqman", env.Root)
	}
	if env.Matches[0].Entry.Frequency != 433920000 {
		t.Errorf("matched freq = %d, want 433920000", env.Matches[0].Entry.Frequency)
	}
	if env.Matches[0].Entry.Description != "Garage door, blue button" {
		t.Errorf("matched description = %q", env.Matches[0].Entry.Description)
	}
}

func TestSignalLibrarySearch_EmptyQueryRejected(t *testing.T) {
	spec, ok := Get("signal_library_search")
	if !ok {
		t.Fatal("signal_library_search not registered")
	}
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"query": ""})
	if err == nil {
		t.Error("empty query: expected error")
	}
}

func TestSignalLibrarySearch_LimitClampedToMax(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	libDir := filepath.Join(home, ".promptzero", "freqman")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "x.txt"), []byte("f=1,d=A\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	spec, ok := Get("signal_library_search")
	if !ok {
		t.Fatal("signal_library_search not registered")
	}
	// JSON-parsed numbers arrive as float64; that's the shape intOr was
	// built for. Use that directly here so we exercise the real path.
	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"query": "1",
		"limit": float64(9999),
	})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	var env struct {
		Limit int `json:"limit"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatal(err)
	}
	if env.Limit != 500 {
		t.Errorf("limit = %d, want 500 (clamped)", env.Limit)
	}
}

func TestSignalLibrarySearch_LimitZeroFallsBackToDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	libDir := filepath.Join(home, ".promptzero", "freqman")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "x.txt"), []byte("f=1,d=A\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	spec, ok := Get("signal_library_search")
	if !ok {
		t.Fatal("signal_library_search not registered")
	}
	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"query": "1",
		"limit": float64(0),
	})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	var env struct {
		Limit int `json:"limit"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatal(err)
	}
	if env.Limit != 50 {
		t.Errorf("limit = %d, want 50 (default)", env.Limit)
	}
}

// --- signal_import ---

// signalImportRedirectClient swaps the package-level HTTP client to a
// version that follows redirects without enforcing the allowlist (the
// tool does that itself), and rewrites the request to point at the
// httptest server. We can't change net.LookupHost, so the test feeds
// the server's URL directly via a "URL rewrite" RoundTripper.
type signalImportRewriteTransport struct {
	target string // e.g. "http://127.0.0.1:12345"
}

func (t *signalImportRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tu, err := url.Parse(t.target)
	if err != nil {
		return nil, err
	}
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = tu.Scheme
	req2.URL.Host = tu.Host
	return http.DefaultTransport.RoundTrip(req2)
}

func swapImportClient(t *testing.T, server *httptest.Server) {
	t.Helper()
	prev := signalImportClient
	signalImportClient = &http.Client{
		Transport:     &signalImportRewriteTransport{target: server.URL},
		Timeout:       signalImportFetchTimeout,
		CheckRedirect: prev.CheckRedirect,
	}
	t.Cleanup(func() { signalImportClient = prev })
}

func TestSignalImport_RegisteredAtInit(t *testing.T) {
	spec, ok := Get("signal_import")
	if !ok {
		t.Fatal("signal_import not registered")
	}
	if spec.Risk != risk.Medium {
		t.Errorf("Risk = %s, want Medium", spec.Risk)
	}
	if spec.Group != GroupMetaUtil {
		t.Errorf("Group = %s, want %s", spec.Group, GroupMetaUtil)
	}
}

func TestSignalImport_RejectsNonHTTPS(t *testing.T) {
	spec, _ := Get("signal_import")
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url": "http://lab.flipper.net/x.txt",
	})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("non-https: expected scheme error, got %v", err)
	}
}

func TestSignalImport_RejectsDisallowedHost(t *testing.T) {
	spec, _ := Get("signal_import")
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url": "https://attacker.example.com/x.txt",
	})
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("bad host: expected allowlist error, got %v", err)
	}
}

func TestSignalImport_RejectsPathTraversalFilename(t *testing.T) {
	spec, _ := Get("signal_import")
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":      "https://lab.flipper.net/lib.txt",
		"filename": "../../escape.txt",
	})
	if err == nil || !strings.Contains(err.Error(), "basename") {
		t.Errorf("path traversal: expected basename error, got %v", err)
	}
}

func TestSignalImport_RejectsNonTxtFilename(t *testing.T) {
	spec, _ := Get("signal_import")
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":      "https://lab.flipper.net/lib.txt",
		"filename": "shellcode.exe",
	})
	if err == nil || !strings.Contains(err.Error(), ".txt") {
		t.Errorf("non-txt filename: expected error, got %v", err)
	}
}

func TestSignalImport_RejectsBadExpectedHash(t *testing.T) {
	spec, _ := Get("signal_import")
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":             "https://lab.flipper.net/lib.txt",
		"expected_sha256": "not-a-hash",
	})
	if err == nil || !strings.Contains(err.Error(), "expected_sha256") {
		t.Errorf("bad hash: expected error, got %v", err)
	}
}

func TestSignalImport_HappyPath_SavesAndReportsHash(t *testing.T) {
	body := []byte("f=433920000,m=AM_DSB,d=Garage A\nf=315000000,d=Car fob\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	swapImportClient(t, srv)

	home := t.TempDir()
	t.Setenv("HOME", home)

	spec, _ := Get("signal_import")
	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":      "https://lab.flipper.net/test.txt",
		"filename": "test.txt",
	})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	var env struct {
		URL            string `json:"url"`
		SavedTo        string `json:"saved_to"`
		SHA256         string `json:"sha256"`
		Bytes          int    `json:"bytes"`
		EntryCount     int    `json:"entry_count"`
		VerifiedPinned bool   `json:"verified_pinned"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("envelope: %v\n%s", err, out)
	}
	wantSum := sha256.Sum256(body)
	if env.SHA256 != hex.EncodeToString(wantSum[:]) {
		t.Errorf("sha256 = %q, want %q", env.SHA256, hex.EncodeToString(wantSum[:]))
	}
	if env.Bytes != len(body) {
		t.Errorf("bytes = %d, want %d", env.Bytes, len(body))
	}
	if env.EntryCount != 2 {
		t.Errorf("entry_count = %d, want 2", env.EntryCount)
	}
	if env.VerifiedPinned {
		t.Error("verified_pinned = true; no expected_sha256 was supplied")
	}
	// File should be on disk and parseable on next call.
	saved, err := os.ReadFile(env.SavedTo)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if string(saved) != string(body) {
		t.Errorf("saved bytes mismatch: got %q, want %q", saved, body)
	}
}

// TestSignalImport_FilePermissionsLockedDown pins the security fix:
// ~/.promptzero/freqman/ was created at 0o755 and freqman files at
// 0o644 — the directory listing leaks which catalogues the operator
// has imported, and any custom file an operator drops in by hand
// can carry engagement-specific notes. Every other operator-data
// store under ~/.promptzero/ (audit, session, snapshot, semcache,
// targetmem) already runs at 0o600/0o700; signal_library had
// drifted out of step. The fix mirrors the v0.124 semcache + v0.125
// targetmem fixes.
func TestSignalImport_FilePermissionsLockedDown(t *testing.T) {
	body := []byte("f=433920000,d=Garage\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	swapImportClient(t, srv)

	home := t.TempDir()
	t.Setenv("HOME", home)

	spec, _ := Get("signal_import")
	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":      "https://lab.flipper.net/cat.txt",
		"filename": "cat.txt",
	})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	var env struct {
		SavedTo string `json:"saved_to"`
	}
	if jerr := json.Unmarshal([]byte(out), &env); jerr != nil {
		t.Fatalf("envelope: %v", jerr)
	}

	// File mode 0o600 — operator-only read+write. Pre-fix 0o644 was
	// world-readable, leaking the catalogue's contents to local users.
	fi, err := os.Stat(env.SavedTo)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("freqman file mode = %#o, want 0o600", mode)
	}

	// Parent dir 0o700 — operator-only traversal. Pre-fix 0o755
	// leaked the listing of imported catalogues.
	dir := filepath.Dir(env.SavedTo)
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if mode := di.Mode().Perm(); mode != 0o700 {
		t.Errorf("freqman dir mode = %#o, want 0o700", mode)
	}
}

func TestSignalImport_HashMismatchIsRejected(t *testing.T) {
	body := []byte("f=433920000,d=Real\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	swapImportClient(t, srv)
	t.Setenv("HOME", t.TempDir())

	spec, _ := Get("signal_import")
	bogus := strings.Repeat("0", 64)
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":             "https://lab.flipper.net/x.txt",
		"filename":        "x.txt",
		"expected_sha256": bogus,
	})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("hash mismatch: expected mismatch error, got %v", err)
	}
}

func TestSignalImport_HashPinSucceedsWhenCorrect(t *testing.T) {
	body := []byte("f=433920000,d=A\n")
	wantSum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	swapImportClient(t, srv)
	t.Setenv("HOME", t.TempDir())

	spec, _ := Get("signal_import")
	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":             "https://lab.flipper.net/x.txt",
		"filename":        "x.txt",
		"expected_sha256": hex.EncodeToString(wantSum[:]),
	})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	if !strings.Contains(out, `"verified_pinned": true`) {
		t.Errorf("verified_pinned should be true in envelope: %s", out)
	}
}

func TestSignalImport_RejectsResponseLargerThanCap(t *testing.T) {
	huge := make([]byte, signalImportMaxBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(huge)
	}))
	t.Cleanup(srv.Close)
	swapImportClient(t, srv)
	t.Setenv("HOME", t.TempDir())

	spec, _ := Get("signal_import")
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":      "https://lab.flipper.net/big.txt",
		"filename": "big.txt",
	})
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Errorf("oversize: expected cap error, got %v", err)
	}
}

func TestSignalImport_RejectsServerErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	swapImportClient(t, srv)
	t.Setenv("HOME", t.TempDir())

	spec, _ := Get("signal_import")
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":      "https://lab.flipper.net/missing.txt",
		"filename": "missing.txt",
	})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("404: expected error, got %v", err)
	}
}

func TestSignalImport_RejectsBytesThatDontParseAsFreqman(t *testing.T) {
	body := []byte("This is not a freqman list, just plain prose\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	swapImportClient(t, srv)
	t.Setenv("HOME", t.TempDir())

	spec, _ := Get("signal_import")
	_, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url":      "https://lab.flipper.net/bad.txt",
		"filename": "bad.txt",
	})
	if err == nil || !strings.Contains(err.Error(), "Freqman") {
		t.Errorf("non-freqman bytes: expected error, got %v", err)
	}
}

func TestSignalImport_RedirectToDisallowedHostRefused(t *testing.T) {
	// Direct CheckRedirect-hook test: we don't need a live server because
	// the hook is invoked by net/http on each redirect step. Construct a
	// fake request to the off-allowlist host and call the hook.
	req, _ := http.NewRequest(http.MethodGet, "https://attacker.example.com/x.txt", nil)
	via := []*http.Request{}
	if err := signalImportClient.CheckRedirect(req, via); err == nil ||
		!strings.Contains(err.Error(), "disallowed host") {
		t.Errorf("CheckRedirect to off-allowlist host: expected refusal, got %v", err)
	}
	// Sanity: a redirect to an allowlisted host is permitted.
	req2, _ := http.NewRequest(http.MethodGet, "https://lab.flipper.net/x.txt", nil)
	if err := signalImportClient.CheckRedirect(req2, via); err != nil {
		t.Errorf("CheckRedirect to allowlisted host: unexpected error %v", err)
	}
}

func TestSignalImport_FilenameDefaultsToURLBasename(t *testing.T) {
	body := []byte("f=433920000,d=A\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	swapImportClient(t, srv)
	home := t.TempDir()
	t.Setenv("HOME", home)

	spec, _ := Get("signal_import")
	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{
		"url": "https://lab.flipper.net/region-eu.txt",
	})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	if !strings.Contains(out, "region-eu.txt") {
		t.Errorf("expected default filename region-eu.txt in envelope: %s", out)
	}
}

// TestSignalLibrarySearch_NonExistentLibraryDirReturnsZeroMatches confirms
// the friendly degradation: an operator who hasn't yet populated
// ~/.promptzero/freqman/ gets an empty matches[] back, not an error.
func TestSignalLibrarySearch_NonExistentLibraryDirReturnsZeroMatches(t *testing.T) {
	home := t.TempDir() // no .promptzero/freqman/ created
	t.Setenv("HOME", home)

	spec, ok := Get("signal_library_search")
	if !ok {
		t.Fatal("signal_library_search not registered")
	}
	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"query": "anything"})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	var env struct {
		MatchCount int `json:"match_count"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatal(err)
	}
	if env.MatchCount != 0 {
		t.Errorf("match_count = %d, want 0 (library dir missing)", env.MatchCount)
	}
	// Belt-and-braces: cover the "errors as JSON" path.
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("non-existent library should not surface ErrNotExist: %v", err)
	}
}

// TestSignalLibrarySearch_EmptyMatchesIsJSONArray pins the v0.165
// contract: when SearchFreqmanDir returns nil (missing library dir,
// no .txt files, etc.), the envelope's `matches` field must be the
// JSON array `[]`, not the literal `null` that json.Marshal of a
// nil slice produces inside a map. The LLM iterates this field to
// list candidate captures; having to special-case `null` vs `[]`
// is a defect, same as v0.163 / v0.164 fixed for audit_export and
// audit_query.
func TestSignalLibrarySearch_EmptyMatchesIsJSONArray(t *testing.T) {
	home := t.TempDir() // no .promptzero/freqman/ — SearchFreqmanDir returns nil
	t.Setenv("HOME", home)

	spec, ok := Get("signal_library_search")
	if !ok {
		t.Fatal("signal_library_search not registered")
	}
	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"query": "garage"})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	// Parse generically and verify matches is a JSON array (non-nil),
	// not the JSON null literal.
	var parsed map[string]any
	if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
		t.Fatalf("output not parseable JSON: %v\nbody: %s", jerr, out)
	}
	m, hasMatches := parsed["matches"]
	if !hasMatches {
		t.Fatalf("matches field absent; body: %s", out)
	}
	if m == nil {
		t.Errorf("matches = nil (JSON null); want empty array []. body: %s", out)
	}
	// Cross-check by deserialising into a concrete slice — null
	// would land as a nil-slice; []any stays non-nil here.
	arr, isSlice := m.([]any)
	if !isSlice {
		t.Errorf("matches is not a slice (got %T); body: %s", m, out)
	}
	if arr == nil {
		t.Errorf("matches is a nil-slice (JSON null shape); body: %s", out)
	}
}
