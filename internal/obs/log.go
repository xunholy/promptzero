// Package obs ("observability") is the cross-cutting layer that wires
// structured logging, Prometheus metrics, and the /debug snapshot view
// into the rest of PromptZero.
//
// The log surface is a thin wrapper around log/slog: every REPL turn
// (and every --watch-triggered or workflow-invoked turn) is wrapped in
// WithTrace so a correlation ID threads through every downstream log
// line, audit entry, and Prom label. FromCtx resolves the logger the
// caller should use; it falls back to the global handler when the
// context was not derived from WithTrace.
package obs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// LogConfig is the user-visible slice of observability configuration that
// affects log output. YAML tags match the on-disk shape under
// `observability:` — see internal/config for the round-trip.
type LogConfig struct {
	Level  string `yaml:"log_level,omitempty"`
	Format string `yaml:"log_format,omitempty"`
	File   string `yaml:"log_file,omitempty"`
}

// traceKey is the context.WithValue key for the trace ID attached by
// WithTrace. Unexported so outside packages cannot construct a fake
// carrier that leaks the trace into the logger.
type traceKey struct{}

// loggerKey carries a slog.Logger pre-bound with the trace attribute so
// FromCtx does not re-derive the logger on every call.
type loggerKey struct{}

// global holds the process-wide slog handler. Setup replaces it; callers
// with no ctx should read through Default().
var (
	globalMu sync.RWMutex
	global   = slog.Default()
)

// Setup installs a slog.Logger built from cfg as the global default and
// returns it so tests can attach their own consumers. Levels outside the
// known set fall back to info with a warning. When Format is "json" the
// handler emits newline-delimited JSON; otherwise the text handler is
// used. File, when non-empty, opens (or creates) that path in append
// mode and mirrors every record to both stderr and the file so operators
// keep local tailing while still emitting to disk.
func Setup(cfg LogConfig) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(cfg.Level)}

	var dest io.Writer = os.Stderr
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "obs: log_file %q unavailable: %v (logging to stderr only)\n", cfg.File, err)
		} else {
			dest = io.MultiWriter(os.Stderr, f)
		}
	}

	var handler slog.Handler
	if strings.EqualFold(cfg.Format, "json") {
		handler = slog.NewJSONHandler(dest, opts)
	} else {
		handler = slog.NewTextHandler(dest, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	globalMu.Lock()
	global = logger
	globalMu.Unlock()
	return logger
}

// Default returns the globally installed logger. Prefer FromCtx when a
// context is in scope — the ctx-bound logger carries trace_id for free.
func Default() *slog.Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

// WithTrace returns a context carrying a fresh 16-hex trace ID and a
// slog.Logger bound to that ID. If ctx already carries a trace the
// existing value is preserved — this makes WithTrace safe to call at
// nested boundaries (workflow phases, validator gate, rules dispatch)
// without silently discarding the turn's correlation ID.
func WithTrace(ctx context.Context) (context.Context, string) {
	if ctx == nil {
		ctx = context.Background()
	}
	if existing, ok := ctx.Value(traceKey{}).(string); ok && existing != "" {
		return ctx, existing
	}
	tid := newTraceID()
	ctx = context.WithValue(ctx, traceKey{}, tid)
	ctx = context.WithValue(ctx, loggerKey{}, Default().With("trace_id", tid))
	return ctx, tid
}

// TraceID returns the trace attached to ctx, or "" when none was set.
// Callers that need to round-trip the trace ID into a downstream system
// (audit row, webhook payload, Prom label) read it here.
func TraceID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(traceKey{}).(string)
	return v
}

// FromCtx returns the logger bound to ctx (with trace_id attached when
// WithTrace was used). Falls back to the globally installed handler
// when ctx has no trace — callers never need to nil-check.
func FromCtx(ctx context.Context) *slog.Logger {
	if ctx != nil {
		if lg, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && lg != nil {
			return lg
		}
	}
	return Default()
}

// newTraceID returns a 16-hex-char trace ID (8 bytes of crypto/rand).
// Short enough to prefix a TUI line without wrapping, long enough to
// avoid collisions across the homelab's session lifetime.
func newTraceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// parseLevel maps the user-facing level string to a slog.Level. Empty
// and unknown values fall back to info.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	case "", "info":
		return slog.LevelInfo
	default:
		fmt.Fprintf(os.Stderr, "obs: unknown log_level %q, defaulting to info\n", s)
		return slog.LevelInfo
	}
}
