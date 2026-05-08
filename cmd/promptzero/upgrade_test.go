package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNormaliseTag locks the leading-v normalisation so callers can
// pass either "0.36.0" or "v0.36.0" and reach the same release URL.
func TestNormaliseTag(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"0.36.0", "v0.36.0"},
		{"v0.36.0", "v0.36.0"},
		{"v1.0", "v1.0"},
		{"", "v"}, // empty stays empty + prefix; semver.IsValid catches it later
	}
	for _, tc := range cases {
		if got := normaliseTag(tc.in); got != tc.want {
			t.Errorf("normaliseTag(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestLookupChecksum drives the GNU sha256sum-output parser. The format
// is `<hex>  <filename>` per line; blank lines and short lines must be
// tolerated, the asset name match must be exact, and the star-prefixed
// "binary mode" filename variant should resolve to the same row.
func TestLookupChecksum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checksums.txt")
	body := strings.Join([]string{
		"abc123  promptzero-linux-amd64.tar.gz",
		"def456  promptzero-linux-arm64.tar.gz",
		"",
		"   ", // whitespace-only
		"badline-no-fields",
		"99feed *promptzero-darwin-amd64.tar.gz", // GNU "binary" prefix
		"trailing newline below",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cases := []struct {
		asset string
		want  string
		ok    bool
	}{
		{"promptzero-linux-amd64.tar.gz", "abc123", true},
		{"promptzero-linux-arm64.tar.gz", "def456", true},
		{"promptzero-darwin-amd64.tar.gz", "99feed", true}, // *-prefix stripped
		{"promptzero-windows-amd64.zip", "", false},
	}
	for _, tc := range cases {
		got, err := lookupChecksum(path, tc.asset)
		if tc.ok && err != nil {
			t.Errorf("lookupChecksum(%q) errored: %v", tc.asset, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("lookupChecksum(%q) should have errored on missing entry", tc.asset)
		}
		if got != tc.want {
			t.Errorf("lookupChecksum(%q) = %q, want %q", tc.asset, got, tc.want)
		}
	}
}

// TestSha256File round-trips a known small payload through the streaming
// hasher and compares against the known hex digest of "hello\n".
func TestSha256File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x")
	if err := os.WriteFile(path, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := sha256File(path)
	if err != nil {
		t.Fatalf("sha256File: %v", err)
	}
	const want = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	if got != want {
		t.Errorf("sha256(\"hello\\n\") = %q, want %q", got, want)
	}
}

// TestExtractTarGzEntryHappyPath builds a tarball in-memory with a
// flattened binary, extracts it, and verifies the bytes round-trip.
func TestExtractTarGzEntryHappyPath(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "release.tar.gz")
	const entry = "promptzero-linux-amd64"
	const payload = "fake-elf-bytes"
	makeTarGz(t, tarPath, []tarMember{{Name: entry, Body: []byte(payload)}})

	dst := filepath.Join(dir, "out")
	if err := extractTarGzEntry(tarPath, entry, dst); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

// TestExtractTarGzEntryRejectsAbsPath confirms the zip-slip guard fires
// on archives that smuggle absolute paths. Real GitHub release tarballs
// never contain absolute paths but a tampered archive easily could.
func TestExtractTarGzEntryRejectsAbsPath(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "evil.tar.gz")
	makeTarGz(t, tarPath, []tarMember{{Name: "/etc/passwd", Body: []byte("root:x:0:0:")}})
	err := extractTarGzEntry(tarPath, "passwd", filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected unsafe-path error, got nil")
	}
	if !strings.Contains(err.Error(), "unsafe path") {
		t.Errorf("error %q does not mention unsafe path", err)
	}
}

// TestExtractTarGzEntryRejectsTraversal is the matching guard for
// "..", which would let an entry escape the destination directory if
// the caller didn't immediately rename to a fixed dst path.
func TestExtractTarGzEntryRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "evil2.tar.gz")
	makeTarGz(t, tarPath, []tarMember{{Name: "../escapee", Body: []byte("nope")}})
	err := extractTarGzEntry(tarPath, "escapee", filepath.Join(dir, "out"))
	if err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Errorf("expected unsafe-path error on traversal, got %v", err)
	}
}

// TestExtractTarGzEntryMissing ensures a clean error fires when the
// requested entry isn't in the archive — gives the upgrade flow a
// distinct signal from "extraction failed for an IO reason".
func TestExtractTarGzEntryMissing(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "noentry.tar.gz")
	makeTarGz(t, tarPath, []tarMember{{Name: "other-binary", Body: []byte("x")}})
	err := extractTarGzEntry(tarPath, "promptzero-linux-amd64", filepath.Join(dir, "out"))
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got %v", err)
	}
}

// tarMember is a light tuple for makeTarGz — keeps the helper signature
// readable when a test seeds multiple files.
type tarMember struct {
	Name string
	Body []byte
}

// makeTarGz writes a gzip-wrapped tar with the given members at path.
// Headers are minimal (regular files, mode 0644) — enough for
// extractTarGzEntry to walk and match by basename.
func makeTarGz(t *testing.T, path string, members []tarMember) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name:     m.Name,
			Mode:     0o644,
			Size:     int64(len(m.Body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write(m.Body); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
}
