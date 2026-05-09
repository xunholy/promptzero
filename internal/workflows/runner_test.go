package workflows

import (
	"errors"
	"strings"
	"testing"
)

func TestRunPhase_HappyPath(t *testing.T) {
	got := runPhase("phase_a", "test_tool", func() (string, error) {
		return "  ok output\n", nil
	})
	if !got.OK {
		t.Errorf("OK = false, want true")
	}
	if got.Output != "ok output" {
		t.Errorf("Output = %q, want %q (TrimSpace applied)", got.Output, "ok output")
	}
	if got.Phase != "phase_a" || got.Tool != "test_tool" {
		t.Errorf("phase/tool fields = %q/%q", got.Phase, got.Tool)
	}
}

func TestRunPhase_ReturnsErrorAsFailedPhase(t *testing.T) {
	got := runPhase("phase_b", "test_tool", func() (string, error) {
		return "partial output", errors.New("boom")
	})
	if got.OK {
		t.Errorf("OK = true after error, want false")
	}
	if !strings.Contains(got.Output, "partial output") {
		t.Errorf("Output should preserve partial output: %q", got.Output)
	}
	if !strings.Contains(got.Output, "boom") {
		t.Errorf("Output should include error text: %q", got.Output)
	}
}

// TestRunPhase_RecoversPanic pins the safety guarantee for
// workflow phases: a panicking fn must not crash the agent. The
// phase result is structured (OK=false, Output names the panic)
// so the workflow's caller can decide whether to bail or
// continue without loss-of-process.
func TestRunPhase_RecoversPanic(t *testing.T) {
	got := runPhase("phase_panic", "buggy_tool", func() (string, error) {
		panic("test-panic-marker-w7q")
	})
	if got.OK {
		t.Errorf("OK = true after panic, want false")
	}
	if !strings.Contains(got.Output, "panicked") {
		t.Errorf("Output should mention 'panicked': %q", got.Output)
	}
	if !strings.Contains(got.Output, "test-panic-marker-w7q") {
		t.Errorf("Output should include the recovered value: %q", got.Output)
	}
	if got.Phase != "phase_panic" {
		t.Errorf("Phase field lost on panic recovery: %q", got.Phase)
	}
	// ElapsedMs is set in the deferred block so it's still
	// populated even when the fn panicked.
	if got.ElapsedMs < 0 {
		t.Errorf("ElapsedMs = %d, want >= 0 even on panic", got.ElapsedMs)
	}
}
