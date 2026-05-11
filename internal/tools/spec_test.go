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
	resetForTest(t)

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
	resetForTest(t)

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
	resetForTest(t)
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
	resetForTest(t)
	Register(newSpec("alpha", "a1"))

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on duplicate alias")
		}
	}()
	Register(newSpec("beta", "a1"))
}

// TestRegister_PanicsOnIntraSpecDuplicateAlias pins the v0.168
// contract gap closure: an Aliases list with a repeated entry
// (e.g. `[]string{"foo", "foo"}`) must surface as a panic at
// registration time, matching the package docstring's "fail loudly
// at init" promise. Pre-fix only the byName / byAlias global-state
// checks fired, but those maps didn't yet contain THIS Spec's
// aliases when validation ran, so the second occurrence passed
// silently — programming error landed in the registry without a
// signal.
func TestRegister_PanicsOnIntraSpecDuplicateAlias(t *testing.T) {
	resetForTest(t)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on intra-Spec duplicate alias")
		}
	}()
	Register(Spec{
		Name:        "intra_dup",
		Description: "test",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Aliases:     []string{"shared", "shared"},
		Handler: func(_ context.Context, _ *Deps, _ map[string]any) (string, error) {
			return "", nil
		},
	})
}

func TestRegister_PanicsWhenAliasCollidesWithName(t *testing.T) {
	resetForTest(t)
	Register(newSpec("alpha"))

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when alias collides with a registered name")
		}
	}()
	Register(newSpec("beta", "alpha"))
}

func TestRegister_PanicsWhenNameCollidesWithAlias(t *testing.T) {
	resetForTest(t)
	Register(newSpec("alpha", "shared"))

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when a subsequent Name collides with a prior alias")
		}
	}()
	Register(newSpec("shared"))
}

func TestRegister_PanicsOnEmptyName(t *testing.T) {
	resetForTest(t)

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on empty Name")
		}
	}()
	Register(Spec{Handler: fakeHandler})
}

func TestRegister_PanicsOnNilHandler(t *testing.T) {
	resetForTest(t)

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil Handler")
		}
	}()
	Register(Spec{Name: "handlerless"})
}

func TestRegister_PanicsOnSelfAlias(t *testing.T) {
	resetForTest(t)

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when a tool lists itself as an alias")
		}
	}()
	Register(newSpec("alpha", "alpha"))
}

func TestNames_IncludesAliases(t *testing.T) {
	resetForTest(t)

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

// TestUnregisterForTest_RemovesToolAndAliases pins the contract on
// the public sibling of resetForTest: cross-package tests use it to
// scrub a fake tool they registered with t.Cleanup so the registry
// stays consistent under -count=N.
func TestUnregisterForTest_RemovesToolAndAliases(t *testing.T) {
	resetForTest(t)

	const canonical = "ufu_canonical"
	const alias1 = "ufu_alias_one"
	const alias2 = "ufu_alias_two"

	Register(newSpec(canonical, alias1, alias2))

	// All three names resolve before unregister.
	for _, n := range []string{canonical, alias1, alias2} {
		if _, ok := Get(n); !ok {
			t.Fatalf("Get(%q) before unregister: not found", n)
		}
	}

	UnregisterForTest(canonical)

	// All three names miss after unregister.
	for _, n := range []string{canonical, alias1, alias2} {
		if _, ok := Get(n); ok {
			t.Errorf("Get(%q) after unregister: still resolves; expected miss", n)
		}
	}

	// order slice no longer contains the canonical name (asserts via
	// Names which composes byName + byAlias keys).
	for _, n := range Names() {
		if n == canonical || n == alias1 || n == alias2 {
			t.Errorf("Names() still contains %q after unregister", n)
		}
	}

	// Re-Register works (would panic with "duplicate" if any of the
	// three keys leaked).
	Register(newSpec(canonical, alias1, alias2))
}

// TestUnregisterForTest_NoOpOnUnregistered confirms the documented
// "safe to call unconditionally" contract: passing an unknown name
// is a silent no-op so cleanup paths don't have to guard.
func TestUnregisterForTest_NoOpOnUnregistered(t *testing.T) {
	resetForTest(t)

	// Empty registry — must not panic.
	UnregisterForTest("does_not_exist")

	// Registry with one entry — unregistering an unrelated name must
	// not touch the existing entry.
	Register(newSpec("present"))
	UnregisterForTest("absent")
	if _, ok := Get("present"); !ok {
		t.Error("Get(present) after unregistering absent: missing; the unrelated entry was incorrectly removed")
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
