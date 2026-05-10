package rpc

import (
	"testing"
	"time"
)

// options_test.go covers the OpenOption helpers
// (WithSkipStartRPCSession, WithPipeline) that the Open path uses
// to tune handshake behaviour per transport. Both are pure config
// mutators with no I/O — direct testing is the cheapest insurance
// against a regression that silently flips the wrong field or
// ignores the override.

func TestWithSkipStartRPCSession(t *testing.T) {
	cfg := openConfig{}
	if cfg.skipStartRPCSession {
		t.Fatal("default openConfig has skipStartRPCSession=true; want false")
	}
	WithSkipStartRPCSession()(&cfg)
	if !cfg.skipStartRPCSession {
		t.Errorf("WithSkipStartRPCSession() did not set skipStartRPCSession")
	}
	// Idempotent: calling it twice stays true.
	WithSkipStartRPCSession()(&cfg)
	if !cfg.skipStartRPCSession {
		t.Errorf("WithSkipStartRPCSession is not idempotent")
	}
}

// TestWithPipeline_PositiveValuesOverride pins the override
// semantics: positive Attempts and PingTimeout values must
// land in the resolved openConfig. The Open path consults
// retryAttempts and retryDelay so a regression that drops the
// override would silently revert to legacy 5/500ms timing.
func TestWithPipeline_PositiveValuesOverride(t *testing.T) {
	cfg := openConfig{}
	WithPipeline(HandshakePolicy{
		Attempts:    10,
		PingTimeout: 2 * time.Second,
	})(&cfg)
	if cfg.retryAttempts != 10 {
		t.Errorf("retryAttempts = %d, want 10", cfg.retryAttempts)
	}
	if cfg.retryDelay != 2*time.Second {
		t.Errorf("retryDelay = %v, want 2s", cfg.retryDelay)
	}
}

// TestWithPipeline_ZeroValuesPreserveExisting pins the
// "<=0 means use the legacy default" contract: a zero / negative
// HandshakePolicy field must NOT clobber whatever was already
// in the openConfig. This lets callers compose options safely
// (e.g. WithPipeline(p1) then WithPipeline(p2) where p2 has
// only Attempts set won't reset PingTimeout to zero).
func TestWithPipeline_ZeroValuesPreserveExisting(t *testing.T) {
	cfg := openConfig{retryAttempts: 7, retryDelay: 1500 * time.Millisecond}
	// Zero policy: nothing should change.
	WithPipeline(HandshakePolicy{})(&cfg)
	if cfg.retryAttempts != 7 {
		t.Errorf("retryAttempts = %d, want 7 (zero policy must not clobber)", cfg.retryAttempts)
	}
	if cfg.retryDelay != 1500*time.Millisecond {
		t.Errorf("retryDelay = %v, want 1.5s (zero policy must not clobber)", cfg.retryDelay)
	}

	// Negative values are also rejected.
	WithPipeline(HandshakePolicy{Attempts: -1, PingTimeout: -1})(&cfg)
	if cfg.retryAttempts != 7 || cfg.retryDelay != 1500*time.Millisecond {
		t.Errorf("negative policy clobbered cfg: %+v", cfg)
	}

	// Partial override: only Attempts set.
	WithPipeline(HandshakePolicy{Attempts: 12})(&cfg)
	if cfg.retryAttempts != 12 {
		t.Errorf("retryAttempts override failed: %d, want 12", cfg.retryAttempts)
	}
	if cfg.retryDelay != 1500*time.Millisecond {
		t.Errorf("PingTimeout=0 should preserve retryDelay; got %v", cfg.retryDelay)
	}
}

// TestOpenOptions_ComposeOrder pins that successive options apply
// in order, the way Open's for-range over the opts slice expects.
// A pipeline applied first followed by SkipStartRPCSession should
// retain both effects.
func TestOpenOptions_ComposeOrder(t *testing.T) {
	cfg := openConfig{}
	opts := []OpenOption{
		WithPipeline(HandshakePolicy{Attempts: 3, PingTimeout: 400 * time.Millisecond}),
		WithSkipStartRPCSession(),
	}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.retryAttempts != 3 || cfg.retryDelay != 400*time.Millisecond {
		t.Errorf("pipeline values not retained after second option: %+v", cfg)
	}
	if !cfg.skipStartRPCSession {
		t.Errorf("SkipStartRPCSession not applied after pipeline")
	}
}
