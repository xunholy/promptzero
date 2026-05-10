package tools

import (
	"strings"
	"testing"
)

// require_test.go pins the dependency-gate helpers every
// hardware-touching Handler calls before dereferencing its
// transport. Returning an error early means the LLM-facing tool
// result is a clear "X not connected" string instead of a nil-
// pointer panic. nil receivers must be safe; non-nil with nil
// hardware must return an error; both nil-deps and a wired
// transport must return nil.

func TestRequireMarauder(t *testing.T) {
	// Nil receiver.
	var nilDeps *Deps
	if err := nilDeps.RequireMarauder(); err == nil {
		t.Error("RequireMarauder on nil Deps: want error, got nil")
	}
	// Non-nil Deps, nil Marauder.
	d := &Deps{}
	err := d.RequireMarauder()
	if err == nil {
		t.Error("RequireMarauder with nil Marauder: want error, got nil")
	}
	if !strings.Contains(err.Error(), "WiFi") || !strings.Contains(err.Error(), "--wifi") {
		t.Errorf("RequireMarauder error = %q, want mention of WiFi / --wifi", err)
	}
}

func TestRequireBruce(t *testing.T) {
	var nilDeps *Deps
	if err := nilDeps.RequireBruce(); err == nil {
		t.Error("RequireBruce on nil Deps: want error")
	}
	d := &Deps{}
	err := d.RequireBruce()
	if err == nil {
		t.Error("RequireBruce with nil Bruce: want error")
	}
	if !strings.Contains(err.Error(), "bruce") || !strings.Contains(err.Error(), "--bruce") {
		t.Errorf("RequireBruce error = %q, want mention of bruce / --bruce", err)
	}
}

func TestRequireBusPirate(t *testing.T) {
	var nilDeps *Deps
	if err := nilDeps.RequireBusPirate(); err == nil {
		t.Error("RequireBusPirate on nil Deps: want error")
	}
	d := &Deps{}
	err := d.RequireBusPirate()
	if err == nil {
		t.Error("RequireBusPirate with nil BusPirate: want error")
	}
	if !strings.Contains(err.Error(), "bus pirate") || !strings.Contains(err.Error(), "buspirate.port") {
		t.Errorf("RequireBusPirate error = %q, want mention of bus pirate / buspirate.port", err)
	}
}

func TestRequireFaultier(t *testing.T) {
	var nilDeps *Deps
	if err := nilDeps.RequireFaultier(); err == nil {
		t.Error("RequireFaultier on nil Deps: want error")
	}
	d := &Deps{}
	err := d.RequireFaultier()
	if err == nil {
		t.Error("RequireFaultier with nil Faultier: want error")
	}
	if !strings.Contains(err.Error(), "faultier") {
		t.Errorf("RequireFaultier error = %q, want mention of faultier", err)
	}
}
