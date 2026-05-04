package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/risk"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
)

// TestReadOnly_BlocksAboveLow locks the v0.19.0 safety rail: every
// tool above risk.Low must be refused by dispatch when SetReadOnly is
// engaged. Without this the rail isn't a rail.
func TestReadOnly_BlocksAboveLow(t *testing.T) {
	a := NewForTest("test-model")
	a.SetReadOnly(true)

	// subghz_transmit is High; wifi_deauth is Critical; nfc_emulate is
	// Medium. Test all three so a future re-classification doesn't
	// quietly drop a tier from the test.
	cases := map[string]risk.Level{}
	for _, name := range []string{"subghz_transmit", "wifi_deauth", "nfc_emulate"} {
		spec, ok := toolsreg.Get(name)
		if !ok {
			t.Logf("skip: %s not registered in this build", name)
			continue
		}
		if spec.Risk == risk.Low {
			t.Errorf("%s is unexpectedly Low — read-only test needs higher-risk tools", name)
			continue
		}
		cases[name] = spec.Risk
	}
	if len(cases) == 0 {
		t.Skip("no above-Low tools registered to exercise read-only")
	}

	for name, lvl := range cases {
		_, err := a.dispatch(context.Background(), name, map[string]interface{}{})
		if err == nil {
			t.Errorf("%s (%s) must be refused under read-only", name, lvl)
			continue
		}
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s: error must wrap ErrReadOnly so callers can errors.Is; got: %v", name, err)
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%s: error message should name the tool; got: %v", name, err)
		}
	}
}

// TestReadOnly_AllowsLow verifies the read-only rail doesn't refuse
// the things it's supposed to permit — pure reads / inspections /
// queries.
func TestReadOnly_AllowsLow(t *testing.T) {
	a := NewForTest("test-model")
	a.SetReadOnly(true)

	// audit_query is the canonical Low-risk tool every build has.
	// Use it as a smoke test that the dispatch path doesn't refuse
	// Low-risk tools.
	if _, ok := toolsreg.Get("audit_query"); !ok {
		t.Skip("audit_query not registered")
	}

	// Pass an obviously-empty filter; we don't care if the handler
	// errors on its own logic — we only care that ErrReadOnly is NOT
	// returned. Wrapping the assertion this way means a handler
	// signature/contract change doesn't make the safety-rail test
	// flaky.
	_, err := a.dispatch(context.Background(), "audit_query", map[string]interface{}{
		"limit": float64(1),
	})
	if errors.Is(err, ErrReadOnly) {
		t.Fatalf("Low-risk audit_query was refused under read-only: %v", err)
	}
}

// TestReadOnly_DefaultIsOff guards against a future "make read-only
// the default" change that would silently break callers who never set
// the flag. SetReadOnly must be opt-in for one release minimum.
func TestReadOnly_DefaultIsOff(t *testing.T) {
	a := NewForTest("test-model")
	if a.ReadOnly() {
		t.Fatal("read-only must default to false to preserve historic CRUD behaviour")
	}
}

// TestReadOnly_ReadOnlyAccessor sanity-checks the getter.
func TestReadOnly_ReadOnlyAccessor(t *testing.T) {
	a := NewForTest("test-model")
	a.SetReadOnly(true)
	if !a.ReadOnly() {
		t.Fatal("ReadOnly() should return true after SetReadOnly(true)")
	}
	a.SetReadOnly(false)
	if a.ReadOnly() {
		t.Fatal("ReadOnly() should return false after SetReadOnly(false)")
	}
}

// TestFilterToolsToReadOnly_KeepsOnlyLow locks the catalog-narrowing
// contract used by the Run loop. Every retained spec must be
// risk.Low; every dropped spec must be > Low.
func TestFilterToolsToReadOnly_KeepsOnlyLow(t *testing.T) {
	all := buildTools()
	if len(all) == 0 {
		t.Fatal("buildTools returned empty catalog — registry not initialised?")
	}

	got := filterToolsToReadOnly(all)
	if len(got) == 0 {
		t.Fatal("filtered catalog is empty — read-only mode would have no tools at all")
	}
	if len(got) >= len(all) {
		t.Errorf("filtered catalog should be smaller than full; got %d of %d", len(got), len(all))
	}

	for _, tu := range got {
		if tu.OfTool == nil {
			continue
		}
		spec, ok := toolsreg.Get(tu.OfTool.Name)
		if !ok {
			continue // unregistered passthrough — documented behaviour
		}
		if spec.Risk != risk.Low {
			t.Errorf("filtered catalog kept %s (risk=%s); read-only must keep only Low", tu.OfTool.Name, spec.Risk)
		}
	}
}

// TestFilterToolsToReadOnly_NilToolPassesThrough exercises the
// defensive branch: ToolUnionParam variants with nil OfTool (future
// non-tool blocks) must not be silently dropped.
func TestFilterToolsToReadOnly_NilToolPassesThrough(t *testing.T) {
	in := []anthropic.ToolUnionParam{{}}
	got := filterToolsToReadOnly(in)
	if len(got) != 1 {
		t.Errorf("nil-OfTool entry must pass through; got %d entries", len(got))
	}
}
