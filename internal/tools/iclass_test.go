package tools_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/tools"
)

// iclassSpec returns the iclass_loclass_recover Spec from the pre-init
// registry snapshot (immune to resetForTest() calls in spec_test.go).
func iclassSpec(t *testing.T) tools.Spec {
	t.Helper()
	for _, s := range initialSpecs {
		if s.Name == "iclass_loclass_recover" {
			return s
		}
	}
	t.Fatal("iclass_loclass_recover not in pre-init registry snapshot — did init() register it?")
	return tools.Spec{}
}

// TestIClassLoclassRecoverSpec verifies the iclass_loclass_recover Spec is
// registered with the correct shape.
func TestIClassLoclassRecoverSpec(t *testing.T) {
	spec := iclassSpec(t)

	if spec.Handler == nil {
		t.Fatal("iclass_loclass_recover Handler is nil")
	}
	if spec.Description == "" {
		t.Fatal("iclass_loclass_recover Description is empty")
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(spec.Schema, &schema); err != nil {
		t.Fatalf("iclass_loclass_recover Schema is not valid JSON: %v", err)
	}
	if len(spec.Required) == 0 || spec.Required[0] != "captures" {
		t.Errorf("iclass_loclass_recover Required = %v, want [captures]", spec.Required)
	}
}

// TestIClassHandlerMissingCaptures verifies the handler returns an error when
// the captures file does not exist.
func TestIClassHandlerMissingCaptures(t *testing.T) {
	spec := iclassSpec(t)
	_, err := spec.Handler(context.Background(), nil, map[string]any{
		"captures": "/nonexistent/path/captures.bin",
	})
	if err == nil {
		t.Fatal("expected error for missing captures file, got nil")
	}
}

// TestIClassHandlerEmptyCaptures verifies the handler returns an error for an
// empty capture file.
func TestIClassHandlerEmptyCaptures(t *testing.T) {
	spec := iclassSpec(t)

	f, err := os.CreateTemp(t.TempDir(), "empty_captures_*.bin")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	f.Close()

	_, err = spec.Handler(context.Background(), nil, map[string]any{
		"captures": f.Name(),
	})
	if err == nil {
		t.Fatal("expected error for empty captures file, got nil")
	}
}

// TestIClassHandlerDumpFile exercises the handler against the real dump file
// if it is available in the iclass testdata directory.
func TestIClassHandlerDumpFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping iclass_loclass_recover handler brute-force in -short mode")
	}

	dumpPath := filepath.Join("..", "iclass", "testdata", "iclass_dump.bin")
	if _, err := os.Stat(dumpPath); err != nil {
		t.Skipf("testdata dump file unavailable: %v", err)
	}

	spec := iclassSpec(t)

	// 300s gives ~2.5× headroom for race-overhead on CI; under -short the
	// test is skipped entirely above.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	result, err := spec.Handler(ctx, nil, map[string]any{
		"captures":   dumpPath,
		"timeout_ms": float64(120000),
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	var out struct {
		Key        string `json:"key"`
		Format     string `json:"format"`
		DurationMS int64  `json:"duration_ms"`
	}
	if err := json.Unmarshal([]byte(result), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.Key != "5b7c62c491c11b39" {
		t.Errorf("recovered key = %q, want 5b7c62c491c11b39", out.Key)
	}
	if out.Format != "iclass-elite-master" {
		t.Errorf("format = %q, want iclass-elite-master", out.Format)
	}
	t.Logf("recovered Kcus = %s in %d ms", out.Key, out.DurationMS)
}
