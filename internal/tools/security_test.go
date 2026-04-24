package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/xunholy/promptzero/internal/tools"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// secSpecIndex is a name→Spec map built lazily from initialSpecs (the
// pre-init registry snapshot captured in TestMain before any resetForTest()
// call can clear the global registry). Using this snapshot ensures that
// security tests work regardless of test execution order.
var secSpecIndex map[string]tools.Spec

// secSpec returns the Spec for name from the pre-init snapshot. It fails
// the test if the spec is not found. Using the snapshot (not tools.Get)
// means the tests are immune to resetForTest() calls in spec_test.go.
func secSpec(t *testing.T, name string) tools.Spec {
	t.Helper()
	if secSpecIndex == nil {
		secSpecIndex = make(map[string]tools.Spec, len(initialSpecs))
		for _, s := range initialSpecs {
			secSpecIndex[s.Name] = s
		}
	}
	s, ok := secSpecIndex[name]
	if !ok {
		t.Fatalf("spec %q not in pre-init registry snapshot — did init() register it?", name)
	}
	return s
}

// invokeSpec calls a Spec handler by name with the given args map.
// Uses the pre-init registry snapshot so it is immune to resetForTest().
func invokeSpec(t *testing.T, name string, args map[string]any) (string, error) {
	t.Helper()
	s := secSpec(t, name)
	return s.Handler(context.Background(), nil, args)
}

// invokeSpecCtx is like invokeSpec but with a caller-supplied context.
func invokeSpecCtx(ctx context.Context, t *testing.T, name string, args map[string]any) (string, error) {
	t.Helper()
	s := secSpec(t, name)
	return s.Handler(ctx, nil, args)
}

// mustJSON unmarshals JSON into a map; fails the test on parse error.
func mustJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("JSON parse error: %v\nraw: %s", err, s)
	}
	return m
}

// writeTempWordlist writes lines to a temp file and returns its path.
func writeTempWordlist(t *testing.T, lines ...string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "wordlist-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
	f.Close()
	return f.Name()
}

// ─────────────────────────────────────────────────────────────────────────────
// TestHashIdentify — unit tests for the hash_identify spec
// ─────────────────────────────────────────────────────────────────────────────

func TestHashIdentify_MD5_Password(t *testing.T) {
	// MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
	out, err := invokeSpec(t, "hash_identify", map[string]any{
		"hash": "5f4dcc3b5aa765d61d8327deb882cf99",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	candidates, _ := m["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate")
	}
	top, _ := candidates[0].(map[string]any)
	name, _ := top["name"].(string)
	if name != "MD5" {
		t.Errorf("top candidate = %q, want %q", name, "MD5")
	}
	conf, _ := top["confidence"].(float64)
	if conf < 0.5 {
		t.Errorf("MD5 confidence = %.2f, want >= 0.50", conf)
	}
}

func TestHashIdentify_MD5_123456(t *testing.T) {
	// MD5("123456") = e10adc3949ba59abbe56e057f20f883e
	out, err := invokeSpec(t, "hash_identify", map[string]any{
		"hash": "e10adc3949ba59abbe56e057f20f883e",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	candidates, _ := m["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
	top, _ := candidates[0].(map[string]any)
	name, _ := top["name"].(string)
	// Lower-case hex → top candidate should be MD5
	if name != "MD5" {
		t.Errorf("top candidate = %q, want MD5 (lowercase hex bias)", name)
	}
}

func TestHashIdentify_NTLM_Password(t *testing.T) {
	// NTLM("password") = 8846F7EAEE8FB117AD06BDD830B7586C (uppercase)
	out, err := invokeSpec(t, "hash_identify", map[string]any{
		"hash": "8846F7EAEE8FB117AD06BDD830B7586C",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	candidates, _ := m["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
	top, _ := candidates[0].(map[string]any)
	name, _ := top["name"].(string)
	// Upper-case hex → top candidate should be NTLM
	if name != "NTLM" {
		t.Errorf("top candidate = %q, want NTLM (uppercase hex bias)", name)
	}
}

func TestHashIdentify_SHA1_Hello(t *testing.T) {
	// SHA-1("hello") = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
	out, err := invokeSpec(t, "hash_identify", map[string]any{
		"hash": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	candidates, _ := m["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
	top, _ := candidates[0].(map[string]any)
	name, _ := top["name"].(string)
	if name != "SHA-1" {
		t.Errorf("top candidate = %q, want SHA-1", name)
	}
	conf, _ := top["confidence"].(float64)
	if conf < 0.8 {
		t.Errorf("SHA-1 confidence = %.2f, want >= 0.80", conf)
	}
}

func TestHashIdentify_SHA256(t *testing.T) {
	// SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	out, err := invokeSpec(t, "hash_identify", map[string]any{
		"hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	candidates, _ := m["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
	top, _ := candidates[0].(map[string]any)
	name, _ := top["name"].(string)
	if name != "SHA-256" {
		t.Errorf("top candidate = %q, want SHA-256", name)
	}
}

func TestHashIdentify_SHA512(t *testing.T) {
	// 128 lowercase hex chars → SHA-512.
	// SHA-512("hello") — verified against Go's crypto/sha512.
	const sha512Hello = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7" +
		"2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
	out, err := invokeSpec(t, "hash_identify", map[string]any{"hash": sha512Hello})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	candidates, _ := m["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
	top, _ := candidates[0].(map[string]any)
	name, _ := top["name"].(string)
	if name != "SHA-512" {
		t.Errorf("top candidate = %q, want SHA-512", name)
	}
}

func TestHashIdentify_Bcrypt(t *testing.T) {
	// bcrypt hash — structural prefix check, no cracking needed.
	// Generate a real bcrypt hash at minimum cost for speed.
	bh, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate bcrypt: %v", err)
	}
	out, err2 := invokeSpec(t, "hash_identify", map[string]any{"hash": string(bh)})
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}
	m := mustJSON(t, out)
	candidates, _ := m["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
	top, _ := candidates[0].(map[string]any)
	name, _ := top["name"].(string)
	if name != "bcrypt" {
		t.Errorf("top candidate = %q, want bcrypt", name)
	}
	conf, _ := top["confidence"].(float64)
	if conf < 0.9 {
		t.Errorf("bcrypt confidence = %.2f, want >= 0.90", conf)
	}
}

func TestHashIdentify_Sha512crypt(t *testing.T) {
	// Prefix check for sha512crypt ($6$).
	out, err := invokeSpec(t, "hash_identify", map[string]any{"hash": "$6$saltsalt$lDjgtCdjy..."})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	candidates, _ := m["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
	top, _ := candidates[0].(map[string]any)
	name, _ := top["name"].(string)
	if name != "sha512crypt" {
		t.Errorf("top candidate = %q, want sha512crypt", name)
	}
}

func TestHashIdentify_ColonSeparated(t *testing.T) {
	// user:hash format — should strip the user prefix.
	// SHA-1("hello") with user prefix.
	out, err := invokeSpec(t, "hash_identify", map[string]any{
		"hash": "user:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	candidates, _ := m["candidates"].([]any)
	top, _ := candidates[0].(map[string]any)
	name, _ := top["name"].(string)
	if name != "SHA-1" {
		t.Errorf("top candidate after colon strip = %q, want SHA-1", name)
	}
}

func TestHashIdentify_EmptyHash_Error(t *testing.T) {
	_, err := invokeSpec(t, "hash_identify", map[string]any{"hash": ""})
	if err == nil {
		t.Error("expected error for empty hash, got nil")
	}
}

func TestHashIdentify_MissingHash_Error(t *testing.T) {
	_, err := invokeSpec(t, "hash_identify", map[string]any{})
	if err == nil {
		t.Error("expected error for missing hash arg, got nil")
	}
}

func TestHashIdentify_InputLengthField(t *testing.T) {
	// Verify the input_length field is correct.
	hash := "5f4dcc3b5aa765d61d8327deb882cf99" // 32 chars
	out, err := invokeSpec(t, "hash_identify", map[string]any{"hash": hash})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	inputLen, _ := m["input_length"].(float64)
	if int(inputLen) != 32 {
		t.Errorf("input_length = %v, want 32", inputLen)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestHashCrack — unit tests for the hash_crack_dictionary spec
// ─────────────────────────────────────────────────────────────────────────────

func TestHashCrack_MD5_Password(t *testing.T) {
	// MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
	wl := writeTempWordlist(t, "wrong", "also_wrong", "password", "notthis")
	out, err := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{"5f4dcc3b5aa765d61d8327deb882cf99"},
		"algorithm": "md5",
		"wordlist":  wl,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	cracked, _ := m["cracked"].([]any)
	if len(cracked) != 1 {
		t.Fatalf("cracked count = %d, want 1; full output: %s", len(cracked), out)
	}
	entry, _ := cracked[0].(map[string]any)
	if entry["plaintext"] != "password" {
		t.Errorf("plaintext = %q, want %q", entry["plaintext"], "password")
	}
}

func TestHashCrack_SHA1_Hello(t *testing.T) {
	// SHA-1("hello") = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
	wl := writeTempWordlist(t, "world", "hello", "foo")
	out, err := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
		"algorithm": "sha1",
		"wordlist":  wl,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	cracked, _ := m["cracked"].([]any)
	if len(cracked) != 1 {
		t.Fatalf("cracked = %d, want 1; output: %s", len(cracked), out)
	}
	entry, _ := cracked[0].(map[string]any)
	if entry["plaintext"] != "hello" {
		t.Errorf("plaintext = %q, want hello", entry["plaintext"])
	}
}

func TestHashCrack_SHA256_Hello(t *testing.T) {
	// SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	wl := writeTempWordlist(t, "world", "hello")
	out, err := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		"algorithm": "sha256",
		"wordlist":  wl,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	cracked, _ := m["cracked"].([]any)
	if len(cracked) != 1 {
		t.Fatalf("cracked = %d, want 1; output: %s", len(cracked), out)
	}
	entry, _ := cracked[0].(map[string]any)
	if entry["plaintext"] != "hello" {
		t.Errorf("plaintext = %q, want hello", entry["plaintext"])
	}
}

func TestHashCrack_SHA512_Hello(t *testing.T) {
	// SHA-512("hello") — two 64-char hex halves concatenated.
	const sha512Hello = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7" +
		"2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
	wl := writeTempWordlist(t, "world", "hello")
	out, err := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{sha512Hello},
		"algorithm": "sha512",
		"wordlist":  wl,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	cracked, _ := m["cracked"].([]any)
	if len(cracked) != 1 {
		t.Fatalf("cracked = %d, want 1; output: %s", len(cracked), out)
	}
	entry, _ := cracked[0].(map[string]any)
	if entry["plaintext"] != "hello" {
		t.Errorf("plaintext = %q, want hello", entry["plaintext"])
	}
}

func TestHashCrack_NTLM_Password(t *testing.T) {
	// NTLM("password") = 8846f7eaee8fb117ad06bdd830b7586c (lowercase)
	wl := writeTempWordlist(t, "wrong", "password", "other")
	out, err := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{"8846f7eaee8fb117ad06bdd830b7586c"},
		"algorithm": "ntlm",
		"wordlist":  wl,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	cracked, _ := m["cracked"].([]any)
	if len(cracked) != 1 {
		t.Fatalf("cracked = %d, want 1; output: %s", len(cracked), out)
	}
	entry, _ := cracked[0].(map[string]any)
	if entry["plaintext"] != "password" {
		t.Errorf("plaintext = %q, want password", entry["plaintext"])
	}
}

func TestHashCrack_Bcrypt_Password(t *testing.T) {
	if testing.Short() {
		t.Skip("bcrypt test is slow; skipping in short mode")
	}
	// Generate a real bcrypt hash for "password" at minimum cost (4) for speed.
	bh, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate bcrypt: %v", err)
	}
	wl := writeTempWordlist(t, "wrong", "password", "other")
	out, err2 := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{string(bh)},
		"algorithm": "bcrypt",
		"wordlist":  wl,
	})
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}
	m := mustJSON(t, out)
	cracked, _ := m["cracked"].([]any)
	if len(cracked) != 1 {
		t.Fatalf("cracked = %d, want 1; output: %s", len(cracked), out)
	}
	entry, _ := cracked[0].(map[string]any)
	if entry["plaintext"] != "password" {
		t.Errorf("plaintext = %q, want password", entry["plaintext"])
	}
}

func TestHashCrack_Uncracked(t *testing.T) {
	// MD5("notinthelist") is not in the tiny wordlist.
	// Pre-computed: echo -n "notinthelist" | md5sum
	// = 9d2df879e3e82a5e30de8d9c5ee36c73
	wl := writeTempWordlist(t, "password", "hello", "admin")
	out, err := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{"9d2df879e3e82a5e30de8d9c5ee36c73"},
		"algorithm": "md5",
		"wordlist":  wl,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	cracked, _ := m["cracked"].([]any)
	uncracked, _ := m["uncracked"].([]any)
	if len(cracked) != 0 {
		t.Errorf("cracked = %d, want 0", len(cracked))
	}
	if len(uncracked) != 1 {
		t.Errorf("uncracked = %d, want 1", len(uncracked))
	}
}

func TestHashCrack_BuiltinWordlist(t *testing.T) {
	// MD5("password") should be found in the built-in passwords.txt.
	out, err := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{"5f4dcc3b5aa765d61d8327deb882cf99"},
		"algorithm": "md5",
		"wordlist":  "promptzero://wordlists/passwords.txt",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	cracked, _ := m["cracked"].([]any)
	if len(cracked) != 1 {
		t.Fatalf("cracked = %d, want 1 (password should be in built-in list); output: %s", len(cracked), out)
	}
}

func TestHashCrack_UnsupportedAlgo_Error(t *testing.T) {
	wl := writeTempWordlist(t, "word")
	_, err := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{"abc"},
		"algorithm": "md6",
		"wordlist":  wl,
	})
	if err == nil {
		t.Error("expected error for unsupported algorithm, got nil")
	}
}

func TestHashCrack_OutputShape(t *testing.T) {
	// Verify all required JSON fields are present.
	wl := writeTempWordlist(t, "hello")
	out, err := invokeSpec(t, "hash_crack_dictionary", map[string]any{
		"hashes":    []any{"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
		"algorithm": "sha1",
		"wordlist":  wl,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	for _, key := range []string{"cracked", "uncracked", "algorithm", "words_tried", "duration_ms", "wordlist"} {
		if _, ok := m[key]; !ok {
			t.Errorf("output missing key %q", key)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestPortScan — unit tests for the port_scan_tcp spec
// ─────────────────────────────────────────────────────────────────────────────

func TestPortScan_OpenPort(t *testing.T) {
	// Spin up an httptest server; its port should appear as open.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	out, err := invokeSpec(t, "port_scan_tcp", map[string]any{
		"target":          host,
		"ports":           portStr,
		"timeout_ms":      500,
		"wall_timeout_ms": 5000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	openRaw, _ := m["open"].([]any)
	found := false
	for _, v := range openRaw {
		if int(v.(float64)) == port {
			found = true
		}
	}
	if !found {
		t.Errorf("port %d not found in open list; output: %s", port, out)
	}
}

func TestPortScan_ClosedPort(t *testing.T) {
	// Allocate-then-close a listener; that port should be closed (not open).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close() // Close before the scan so connections are refused.

	// Give the OS a moment to reclaim the port.
	time.Sleep(20 * time.Millisecond)

	out, err := invokeSpec(t, "port_scan_tcp", map[string]any{
		"target":          "127.0.0.1",
		"ports":           portStr,
		"timeout_ms":      200,
		"wall_timeout_ms": 3000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	openRaw, _ := m["open"].([]any)
	if len(openRaw) != 0 {
		t.Errorf("expected open=[], got %v", openRaw)
	}
	portsScanned, _ := m["ports_scanned"].(float64)
	if int(portsScanned) != 1 {
		t.Errorf("ports_scanned = %v, want 1", portsScanned)
	}
}

func TestPortScan_WallTimeout(t *testing.T) {
	// Scan with a tight wall timeout; verify the call doesn't hang.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := invokeSpecCtx(ctx, t, "port_scan_tcp", map[string]any{
		"target":          "127.0.0.1",
		"ports":           "1,2,3",
		"timeout_ms":      50,
		"wall_timeout_ms": 200,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Wall timeout is 200 ms; add generous headroom for scheduling.
	if elapsed > 3*time.Second {
		t.Errorf("scan ran for %v; wall_timeout_ms=200 should have bounded it", elapsed)
	}
}

func TestPortScan_OutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())

	out, err := invokeSpec(t, "port_scan_tcp", map[string]any{
		"target":          "127.0.0.1",
		"ports":           portStr,
		"timeout_ms":      500,
		"wall_timeout_ms": 5000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	for _, key := range []string{"target", "open", "closed", "filtered", "duration_ms", "ports_scanned"} {
		if _, ok := m[key]; !ok {
			t.Errorf("output missing key %q", key)
		}
	}
}

func TestPortScan_InvalidTarget_Error(t *testing.T) {
	_, err := invokeSpec(t, "port_scan_tcp", map[string]any{
		"target": "this.hostname.does.not.exist.invalid",
		"ports":  "80",
	})
	if err == nil {
		t.Error("expected DNS error for invalid target, got nil")
	}
}

func TestPortScan_InvalidPortSpec_Error(t *testing.T) {
	_, err := invokeSpec(t, "port_scan_tcp", map[string]any{
		"target": "127.0.0.1",
		"ports":  "notaport",
	})
	if err == nil {
		t.Error("expected parse error for invalid port spec, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestHTTPEnum — unit tests for the http_enum_common spec
// ─────────────────────────────────────────────────────────────────────────────

func TestHTTPEnum_FindsAdmin(t *testing.T) {
	// Server that returns 200 for /admin and 404 for everything else.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// Use a tiny wordlist containing "admin" so the test is fast.
	wl := writeTempWordlist(t, "admin", "login", "test")
	out, err := invokeSpec(t, "http_enum_common", map[string]any{
		"base_url":        srv.URL,
		"wordlist":        wl,
		"timeout_ms":      1000,
		"wall_timeout_ms": 10000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	found, _ := m["found"].([]any)
	for _, f := range found {
		entry, _ := f.(map[string]any)
		if entry["path"] == "/admin" {
			return
		}
	}
	t.Errorf("/admin not found in results; output: %s", out)
}

func TestHTTPEnum_Soft404Filter(t *testing.T) {
	// Server that returns 200 with a constant-size body for ALL paths
	// (including the canary). The soft-404 filter should suppress everything.
	body := strings.Repeat("x", 500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	wl := writeTempWordlist(t, "admin", "login", "test")
	out, err := invokeSpec(t, "http_enum_common", map[string]any{
		"base_url":        srv.URL,
		"wordlist":        wl,
		"timeout_ms":      1000,
		"wall_timeout_ms": 10000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	found, _ := m["found"].([]any)
	if len(found) != 0 {
		t.Errorf("soft-404 filter should remove all findings, got %d; output: %s", len(found), out)
	}
}

func TestHTTPEnum_BuiltinWordlist(t *testing.T) {
	if testing.Short() {
		t.Skip("full built-in wordlist scan is slow; skipping in short mode")
	}
	// Server that returns 200 for /robots.txt (present in built-in common.txt).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.Header().Set("Content-Length", "50")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	out, err := invokeSpec(t, "http_enum_common", map[string]any{
		"base_url":        srv.URL,
		"wordlist":        "builtin:common.txt",
		"timeout_ms":      500,
		"wall_timeout_ms": 30000,
		"concurrency":     10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	found, _ := m["found"].([]any)
	for _, f := range found {
		entry, _ := f.(map[string]any)
		if entry["path"] == "/robots.txt" {
			return
		}
	}
	t.Errorf("/robots.txt not found in results; output: %s", out)
}

func TestHTTPEnum_MissingBaseURL_Error(t *testing.T) {
	_, err := invokeSpec(t, "http_enum_common", map[string]any{})
	if err == nil {
		t.Error("expected error for missing base_url, got nil")
	}
}

func TestHTTPEnum_OutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	wl := writeTempWordlist(t, "nonexistent")
	out, err := invokeSpec(t, "http_enum_common", map[string]any{
		"base_url":        srv.URL,
		"wordlist":        wl,
		"timeout_ms":      500,
		"wall_timeout_ms": 5000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	for _, key := range []string{"base_url", "found", "requests_made", "duration_ms", "wordlist", "extensions"} {
		if _, ok := m[key]; !ok {
			t.Errorf("output missing key %q", key)
		}
	}
}

func TestHTTPEnum_Extensions(t *testing.T) {
	// Server returns 200 for /admin.php only.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin.php" {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	wl := writeTempWordlist(t, "admin")
	out, err := invokeSpec(t, "http_enum_common", map[string]any{
		"base_url":        srv.URL,
		"wordlist":        wl,
		"extensions":      []any{"php", "html"},
		"timeout_ms":      500,
		"wall_timeout_ms": 5000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := mustJSON(t, out)
	found, _ := m["found"].([]any)
	for _, f := range found {
		entry, _ := f.(map[string]any)
		if entry["path"] == "/admin.php" {
			return
		}
	}
	t.Errorf("/admin.php not found in results; output: %s", out)
}

// ─────────────────────────────────────────────────────────────────────────────
// TestSecuritySpecRegistration — verify all 4 Tier-1 specs are in the snapshot
// ─────────────────────────────────────────────────────────────────────────────

// TestSecuritySpecRegistration verifies that all 4 Tier-1 security Specs were
// registered at init() time and are present in the pre-test snapshot. It does
// NOT call tools.Get() (which would fail if resetForTest() was called first)
// but reads from initialSpecs captured by TestMain.
func TestSecuritySpecRegistration(t *testing.T) {
	names := []string{
		"hash_identify",
		"hash_crack_dictionary",
		"port_scan_tcp",
		"http_enum_common",
	}
	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			s := secSpec(t, name) // uses snapshot, not live registry
			if s.Handler == nil {
				t.Errorf("spec %q has nil Handler", name)
			}
			if s.Description == "" {
				t.Errorf("spec %q has empty Description", name)
			}
			if len(s.Schema) == 0 {
				t.Errorf("spec %q has empty Schema", name)
			}
		})
	}
}
