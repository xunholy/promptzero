package attack

import (
	"sort"
	"strings"
	"testing"
)

func TestDefaultRegistry_KnownTechniques(t *testing.T) {
	r := NewDefaultRegistry()
	for _, id := range []string{"T1040", "T1200", "T1499", "T1552.004", "T1557.004"} {
		if _, ok := r.Lookup(id); !ok {
			t.Errorf("built-in technique %s missing from default registry", id)
		}
	}
}

func TestRegistry_Tactics(t *testing.T) {
	r := NewDefaultRegistry()
	tactics := r.Tactics()
	if len(tactics) == 0 {
		t.Fatal("expected non-empty tactic list")
	}
	// Tactics must be sorted.
	if !sort.StringsAreSorted(tactics) {
		t.Errorf("tactics not sorted: %v", tactics)
	}
	// Spot-check: the tactics we care about for the heatmap must show.
	seen := map[string]bool{}
	for _, tac := range tactics {
		seen[tac] = true
	}
	for _, need := range []string{"Credential Access", "Discovery", "Impact", "Initial Access"} {
		if !seen[need] {
			t.Errorf("tactic %q missing from registry", need)
		}
	}
}

func TestRegistry_SubtechniqueParentLinks(t *testing.T) {
	// Sub-technique IDs (with a dot) must carry a non-empty Parent
	// pointing back at the root technique, which itself must be
	// registered.
	r := NewDefaultRegistry()
	for _, id := range []string{"T1552.004", "T1557.004"} {
		sub, ok := r.Lookup(id)
		if !ok {
			t.Errorf("%s not registered", id)
			continue
		}
		if sub.Parent == "" {
			t.Errorf("%s missing Parent", id)
			continue
		}
		if _, ok := r.Lookup(sub.Parent); !ok {
			t.Errorf("parent %q of %s not registered", sub.Parent, id)
		}
	}
}

func TestIndex_TechniquesForTool(t *testing.T) {
	idx := NewDefaultIndex()
	cases := map[string][]string{
		"wifi_evil_portal_start": {"T1557.004"},
		"wifi_sniff_pmkid":       {"T1040", "T1552.004"},
		"nfc_emulate":            {"T1078", "T1556"}, // sorted output
		"badusb_run":             {"T1059", "T1200"}, // sorted output
	}
	for tool, want := range cases {
		got := idx.TechniquesForTool(tool)
		if !stringSlicesEqual(got, want) {
			t.Errorf("TechniquesForTool(%q) = %v, want %v", tool, got, want)
		}
	}
}

func TestIndex_ToolsForTechnique(t *testing.T) {
	idx := NewDefaultIndex()
	// T1557.004 (Evil Twin) should map to the evil-portal tools.
	tools := idx.ToolsForTechnique("T1557.004")
	seen := map[string]bool{}
	for _, tool := range tools {
		seen[tool] = true
	}
	for _, want := range []string{"wifi_evil_portal_start", "generate_evil_portal", "wifi_beacon_clone"} {
		if !seen[want] {
			t.Errorf("T1557.004 should include %q, got %v", want, tools)
		}
	}
}

func TestIndex_UntaggedToolReturnsEmpty(t *testing.T) {
	idx := NewDefaultIndex()
	// audit_query has no attack tag — should return empty.
	if tags := idx.TechniquesForTool("audit_query"); len(tags) != 0 {
		t.Errorf("audit_query should have no tags, got %v", tags)
	}
	if tags := idx.TechniquesForTool("completely_unknown_tool"); len(tags) != 0 {
		t.Errorf("unknown tool should return empty, got %v", tags)
	}
}

func TestIndex_TechniquesList(t *testing.T) {
	idx := NewDefaultIndex()
	ids := idx.Techniques()
	if !sort.StringsAreSorted(ids) {
		t.Errorf("Techniques list should be sorted: %v", ids)
	}
	// Every ID returned must be in the registry — otherwise we'd be
	// reporting coverage on techniques nobody can look up.
	for _, id := range ids {
		if _, ok := idx.Registry().Lookup(id); !ok {
			t.Errorf("Techniques() returned %q but registry doesn't know it", id)
		}
	}
}

func TestIndex_DropsUnknownTechniquesFromMapping(t *testing.T) {
	// A misconfigured mapping (typo in technique ID) must not crash
	// the index — the unknown ID is silently dropped and a Registered
	// ID in the same entry still lands.
	r := NewDefaultRegistry()
	mapping := map[string][]string{
		"some_tool": {"T1040", "T9999"}, // T9999 does not exist
	}
	idx := NewIndex(r, mapping)
	if got := idx.TechniquesForTool("some_tool"); !stringSlicesEqual(got, []string{"T1040"}) {
		t.Errorf("unknown technique was not dropped: got %v", got)
	}
}

func TestBuiltinMapping_NoDanglingTechniques(t *testing.T) {
	// Every ID referenced in builtinToolMap must exist in the default
	// registry — otherwise the default index silently drops it.
	r := NewDefaultRegistry()
	for tool, ids := range builtinToolMap {
		for _, id := range ids {
			if _, ok := r.Lookup(id); !ok {
				t.Errorf("tool %s references unregistered technique %s", tool, id)
			}
		}
	}
}

func TestTechnique_IDFormat(t *testing.T) {
	// Every ID starts with "T" followed by digits, optionally with a
	// single dot-separated sub-technique suffix. A stray space or
	// wrong-case prefix would break MITRE deep-links in the report.
	r := NewDefaultRegistry()
	for _, tactic := range r.Tactics() {
		for _, id := range r.TechniquesForTactic(tactic) {
			if !strings.HasPrefix(id, "T") {
				t.Errorf("technique %q doesn't start with T", id)
			}
			if strings.Contains(id, " ") {
				t.Errorf("technique %q contains whitespace", id)
			}
			parts := strings.Split(id, ".")
			if len(parts) > 2 {
				t.Errorf("technique %q has more than one dot", id)
			}
		}
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
