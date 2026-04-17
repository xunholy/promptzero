package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithTrace_FreshThenStable(t *testing.T) {
	ctx1, id1 := WithTrace(context.Background())
	if id1 == "" || len(id1) != 16 {
		t.Fatalf("expected 16-hex trace id, got %q", id1)
	}
	ctx2, id2 := WithTrace(ctx1)
	if id2 != id1 {
		t.Fatalf("WithTrace should preserve an existing trace id: first=%s second=%s", id1, id2)
	}
	if TraceID(ctx2) != id1 {
		t.Fatalf("TraceID(ctx2)=%s want %s", TraceID(ctx2), id1)
	}
}

func TestWithTrace_NilCtx(t *testing.T) {
	// Intentional nil-ctx test; funnel through a typed variable so
	// staticcheck SA1012 doesn't flag the literal-nil call site.
	var nilCtx context.Context
	ctx, id := WithTrace(nilCtx)
	if ctx == nil || id == "" {
		t.Fatalf("WithTrace(nil) should return a usable ctx+id, got ctx=%v id=%q", ctx, id)
	}
}

func TestFromCtx_EmitsTraceID(t *testing.T) {
	var buf bytes.Buffer
	old := Default()
	t.Cleanup(func() { slog.SetDefault(old); setGlobal(old) })

	setGlobal(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	ctx, id := WithTrace(context.Background())
	FromCtx(ctx).Info("unit", "k", "v")

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("parse json log: %v (raw=%s)", err, buf.String())
	}
	if got := payload["trace_id"]; got != id {
		t.Fatalf("trace_id in log = %v; want %s", got, id)
	}
	if got := payload["k"]; got != "v" {
		t.Fatalf("custom attr missing (got k=%v)", got)
	}
}

func TestFromCtx_FallbackWhenNoTrace(t *testing.T) {
	lg := FromCtx(context.Background())
	if lg == nil {
		t.Fatal("FromCtx fallback returned nil")
	}
	var nilCtx context.Context
	lg2 := FromCtx(nilCtx)
	if lg2 == nil {
		t.Fatal("FromCtx(nil) fallback returned nil")
	}
}

func TestSetup_JSONFormat(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "log.json")
	lg := Setup(LogConfig{Level: "debug", Format: "json", File: path})
	if lg == nil {
		t.Fatal("Setup returned nil logger")
	}
	lg.Info("hello", "world", 1)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("log file not written: %v", err)
	}
	var payload map[string]any
	first := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)[0]
	if err := json.Unmarshal([]byte(first), &payload); err != nil {
		t.Fatalf("log is not JSON (%s): %v", first, err)
	}
	if payload["msg"] != "hello" {
		t.Fatalf("json msg=%v want hello", payload["msg"])
	}
}

func TestSetup_UnknownLevelFallsBack(t *testing.T) {
	lg := Setup(LogConfig{Level: "bogus", Format: "text"})
	if lg == nil {
		t.Fatal("Setup returned nil")
	}
}

// setGlobal is a test-only helper so tests can restore the global logger
// without reaching into the private field directly from a sibling file.
func setGlobal(l *slog.Logger) {
	globalMu.Lock()
	global = l
	globalMu.Unlock()
}
