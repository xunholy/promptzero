package tools

import (
	"context"
	"encoding/json"
	"errors"
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
		t.Error("AgentOnly = true; this tool only walks the host filesystem and should be MCP-visible")
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
