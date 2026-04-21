package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestMaybeAppendReflection_HappyPath(t *testing.T) {
	counter := 0
	fn := func(ctx context.Context, _ string, _ json.RawMessage, _ string) string {
		return "NFC card not positioned; reposition and retry with timeout_seconds=10."
	}
	got := maybeAppendReflection(context.Background(), "nfc_detect", json.RawMessage(`{}`), "error: timeout", &counter, fn)
	if !strings.Contains(got, "<reflection>") {
		t.Fatalf("reflection not appended: %q", got)
	}
	if !strings.Contains(got, "reposition") {
		t.Fatalf("reflection body missing: %q", got)
	}
	if !strings.HasPrefix(got, "error: timeout") {
		t.Fatalf("original output mangled: %q", got)
	}
	if counter != 1 {
		t.Fatalf("counter = %d, want 1", counter)
	}
}

func TestMaybeAppendReflection_HonoursTurnCap(t *testing.T) {
	counter := maxReflectionsPerTurn // already at cap
	calls := 0
	fn := func(ctx context.Context, _ string, _ json.RawMessage, _ string) string {
		calls++
		return "should not be called"
	}
	got := maybeAppendReflection(context.Background(), "rfid_read", json.RawMessage(`{}`), "err", &counter, fn)
	if strings.Contains(got, "<reflection>") {
		t.Fatalf("reflection appended past cap: %q", got)
	}
	if calls != 0 {
		t.Fatalf("reflectFn was called while at cap: %d", calls)
	}
	if counter != maxReflectionsPerTurn {
		t.Fatalf("counter changed at cap: %d", counter)
	}
}

func TestMaybeAppendReflection_EmptyResultNoAppend(t *testing.T) {
	counter := 0
	fn := func(ctx context.Context, _ string, _ json.RawMessage, _ string) string { return "" }
	got := maybeAppendReflection(context.Background(), "subghz_receive", nil, "err", &counter, fn)
	if strings.Contains(got, "<reflection>") {
		t.Fatalf("empty reflection should not be appended: %q", got)
	}
	if counter != 0 {
		t.Fatalf("counter incremented on empty reflection: %d", counter)
	}
}

func TestMaybeAppendReflection_NilReflectFn(t *testing.T) {
	// Safety valve: if the fn is nil we must not panic.
	counter := 0
	got := maybeAppendReflection(context.Background(), "x", nil, "err", &counter, nil)
	if got != "err" {
		t.Fatalf("nil fn should be no-op: %q", got)
	}
}

func TestMaybeAppendReflection_NilCounter(t *testing.T) {
	// Defensive: nil counter means "no budget tracking". Treat as cap
	// hit so the call is skipped.
	called := false
	fn := func(context.Context, string, json.RawMessage, string) string {
		called = true
		return "x"
	}
	got := maybeAppendReflection(context.Background(), "x", nil, "err", nil, fn)
	if called {
		t.Fatalf("fn called with nil counter")
	}
	if got != "err" {
		t.Fatalf("output mutated: %q", got)
	}
}

// TestMaybeAppendReflection_MultipleFailures walks up to the cap with
// real-looking failures and verifies each one gets a reflection until
// the cap trips.
func TestMaybeAppendReflection_MultipleFailures(t *testing.T) {
	counter := 0
	fn := func(context.Context, string, json.RawMessage, string) string { return "diagnosis" }
	for i := 0; i < maxReflectionsPerTurn; i++ {
		out := maybeAppendReflection(context.Background(), "x", nil, "err", &counter, fn)
		if !strings.Contains(out, "<reflection>") {
			t.Fatalf("iteration %d: reflection missing", i)
		}
	}
	if counter != maxReflectionsPerTurn {
		t.Fatalf("counter = %d, want %d", counter, maxReflectionsPerTurn)
	}
	// One more — must be blocked.
	out := maybeAppendReflection(context.Background(), "x", nil, "err", &counter, fn)
	if strings.Contains(out, "<reflection>") {
		t.Fatalf("reflection leaked past cap: %q", out)
	}
}
