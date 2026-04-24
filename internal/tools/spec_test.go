package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// fakeHandler is a trivial Handler used to exercise the registry without
// depending on any of the internal/* transport layers. The registry is
// name/metadata-centric — the handler only needs to be non-nil and
// deterministic for these tests.
func fakeHandler(_ context.Context, _ *Deps, _ map[string]any) (string, error) {
	return "ok", nil
}

func newSpec(name string, aliases ...string) Spec {
	return Spec{
		Name:        name,
		Aliases:     aliases,
		Description: name + " description",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Risk:        risk.Low,
		Group:       GroupMetaUtil,
		Handler:     fakeHandler,
	}
}

func TestRegister_And_Get_HappyPath(t *testing.T) {
	resetForTest()

	Register(newSpec("alpha"))
	Register(newSpec("beta", "bravo", "b2"))

	// Canonical lookup works.
	got, ok := Get("alpha")
	if !ok || got.Name != "alpha" {
		t.Fatalf("Get(alpha) = %+v, ok=%v; want name=alpha, ok=true", got, ok)
	}

	// Alias lookup resolves to the canonical Spec.
	for _, alias := range []string{"bravo", "b2"} {
		got, ok := Get(alias)
		if !ok {
			t.Fatalf("Get(%q) missing", alias)
		}
		if got.Name != "beta" {
			t.Fatalf("Get(%q).Name = %q; want beta", alias, got.Name)
		}
	}

	// Miss returns zero-value + false.
	if _, ok := Get("ghost"); ok {
		t.Fatalf("Get(ghost) should miss")
	}
}

func TestAll_RegistrationOrderStable(t *testing.T) {
	resetForTest()

	want := []string{"first", "second", "third", "fourth"}
	for _, n := range want {
		Register(newSpec(n))
	}

	all := All()
	if len(all) != len(want) {
		t.Fatalf("All() returned %d specs; want %d", len(all), len(want))
	}
	for i, s := range all {
		if s.Name != want[i] {
			t.Errorf("All()[%d].Name = %q; want %q", i, s.Name, want[i])
		}
	}

	// Mutating the returned slice must not affect subsequent calls.
	all[0].Name = "mutated"
	second := All()
	if second[0].Name != "first" {
		t.Fatalf("All() leaked mutation: got %q; want first", second[0].Name)
	}
}

func TestRegister_PanicsOnDuplicateName(t *testing.T) {
	resetForTest()
	Register(newSpec("dup"))

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on duplicate Name")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "duplicate tool name") || !strings.Contains(msg, "dup") {
			t.Fatalf("panic message missing context: %v", r)
		}
	}()
	Register(newSpec("dup"))
}

func TestRegister_PanicsOnDuplicateAlias(t *testing.T) {
	resetForTest()
	Register(newSpec("alpha", "a1"))

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on duplicate alias")
		}
	}()
	Register(newSpec("beta", "a1"))
}

func TestRegister_PanicsWhenAliasCollidesWithName(t *testing.T) {
	resetForTest()
	Register(newSpec("alpha"))

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when alias collides with a registered name")
		}
	}()
	Register(newSpec("beta", "alpha"))
}

func TestRegister_PanicsWhenNameCollidesWithAlias(t *testing.T) {
	resetForTest()
	Register(newSpec("alpha", "shared"))

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when a subsequent Name collides with a prior alias")
		}
	}()
	Register(newSpec("shared"))
}

func TestRegister_PanicsOnEmptyName(t *testing.T) {
	resetForTest()

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on empty Name")
		}
	}()
	Register(Spec{Handler: fakeHandler})
}

func TestRegister_PanicsOnNilHandler(t *testing.T) {
	resetForTest()

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil Handler")
		}
	}()
	Register(Spec{Name: "handlerless"})
}

func TestRegister_PanicsOnSelfAlias(t *testing.T) {
	resetForTest()

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when a tool lists itself as an alias")
		}
	}()
	Register(newSpec("alpha", "alpha"))
}

func TestNames_IncludesAliases(t *testing.T) {
	resetForTest()

	Register(newSpec("device_info"))
	Register(newSpec("power_info"))
	// Simulate the canonical "primary + synonym" registration shape
	// that the system_info / device_info migration uses — different
	// canonical name here to keep the table clean.
	Register(newSpec("reboot", "device_reboot_alias"))

	got := Names()
	want := map[string]bool{
		"device_info":         true,
		"power_info":          true,
		"reboot":              true,
		"device_reboot_alias": true,
	}
	if len(got) != len(want) {
		t.Fatalf("Names() = %v; want %d entries", got, len(want))
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("Names() contains unexpected %q", n)
		}
	}
}

func TestSnapshotBeforeWrite_NoOpOnNilDeps(t *testing.T) {
	// Exercises the nil-safe early returns: a handler in MCP mode (no
	// Snapshot, no SessionID) must not panic when it calls
	// d.SnapshotBeforeWrite on its way to a write path.
	var d *Deps
	d.SnapshotBeforeWrite(context.Background(), "/ext/any")

	empty := &Deps{}
	empty.SnapshotBeforeWrite(context.Background(), "/ext/any")
	empty.SnapshotBeforeWrite(context.Background(), "")
}
