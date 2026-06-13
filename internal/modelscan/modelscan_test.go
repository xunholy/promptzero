package modelscan

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// Pickle vectors shared with internal/pickle (pickletools-anchored):
//
//	maliciousP4 — os.system('id') __reduce__ gadget, protocol 4
//	benignP4    — {"user":"admin","id":7,"ok":True}, protocol 4
const (
	maliciousP4 = "gASVHQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg=="
	benignP4    = "gASVIQAAAAAAAAB9lCiMBHVzZXKUjAVhZG1pbpSMAmlklEsHjAJva5SIdS4="
)

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}

// zipModel builds a PyTorch-style ZIP from name→content members.
func zipModel(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range members {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScan_MaliciousPyTorch(t *testing.T) {
	model := zipModel(t, map[string][]byte{
		"archive/data.pkl": b64(t, maliciousP4),
		"archive/data/0":   {0x01, 0x02, 0x03, 0x04}, // a "tensor" blob
		"archive/version":  []byte("3\n"),
	})
	r, err := Scan(model)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.Format != "pytorch-zip" || !r.Dangerous || !r.ExecutesCode {
		t.Fatalf("got format=%s dangerous=%v exec=%v", r.Format, r.Dangerous, r.ExecutesCode)
	}
	if len(r.AllDangerousImports) != 1 || r.AllDangerousImports[0] != "posix.system" {
		t.Errorf("all_dangerous_imports = %v, want [posix.system]", r.AllDangerousImports)
	}
	if r.PickleCount != 1 {
		t.Errorf("pickle_count = %d, want 1 (only data.pkl)", r.PickleCount)
	}
	if !strings.Contains(r.Note, "DANGEROUS") {
		t.Errorf("note: %q", r.Note)
	}
	var found bool
	for _, e := range r.Entries {
		if e.Path == "archive/data.pkl" && e.ExecutesCode {
			found = true
		}
	}
	if !found {
		t.Errorf("data.pkl entry not flagged: %+v", r.Entries)
	}
}

func TestScan_BenignPyTorch(t *testing.T) {
	model := zipModel(t, map[string][]byte{
		"archive/data.pkl": b64(t, benignP4),
		"archive/version":  []byte("3\n"),
	})
	r, err := Scan(model)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.Dangerous || r.ExecutesCode || len(r.AllDangerousImports) != 0 {
		t.Errorf("benign model flagged: %+v", r)
	}
	if r.PickleCount != 1 {
		t.Errorf("pickle_count = %d, want 1", r.PickleCount)
	}
}

func TestScan_RawPickle(t *testing.T) {
	r, err := Scan(b64(t, maliciousP4))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.Format != "raw-pickle" || !r.Dangerous || r.Entries[0].Path != "<root>" {
		t.Errorf("raw pickle scan: %+v", r)
	}
}

func TestScan_RenamedPickleByMagic(t *testing.T) {
	// A pickle hidden under a non-.pkl name is still caught by the 0x80 prefix.
	model := zipModel(t, map[string][]byte{
		"weights.bin":     b64(t, maliciousP4), // 0x80-prefixed, not .pkl
		"archive/version": []byte("3\n"),
	})
	r, err := Scan(model)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !r.Dangerous || r.PickleCount != 1 {
		t.Errorf("renamed pickle not caught: %+v", r)
	}
}

func TestScan_NoPickle(t *testing.T) {
	model := zipModel(t, map[string][]byte{
		"readme.txt":     []byte("just text"),
		"archive/data/0": {0x01, 0x02, 0x03},
	})
	r, err := Scan(model)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.PickleCount != 0 || r.Dangerous {
		t.Errorf("expected no pickles found: %+v", r)
	}
	if !strings.Contains(r.Note, "No embedded pickle") {
		t.Errorf("note: %q", r.Note)
	}
}

func TestScan_Empty(t *testing.T) {
	if _, err := Scan(nil); err == nil {
		t.Error("empty input should error")
	}
}

func FuzzScan(f *testing.F) {
	if b, err := base64.StdEncoding.DecodeString(maliciousP4); err == nil {
		f.Add(b)
	}
	f.Add([]byte("PK\x03\x04 not really a zip"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Scan(in)
	})
}
