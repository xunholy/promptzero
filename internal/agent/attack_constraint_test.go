package agent

import (
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/attack"
)

func TestNarrowToolsByAttack_EmptyConstraintPassThrough(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("wifi_scan_ap", "x", nil),
		tool("nfc_emulate", "x", nil),
	}
	got := narrowToolsByAttack(tools, attack.NewDefaultIndex(), nil)
	if len(got) != len(tools) {
		t.Fatalf("empty constraint should pass through unchanged: got %d want %d", len(got), len(tools))
	}
}

func TestNarrowToolsByAttack_NilIndexPassThrough(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("wifi_scan_ap", "x", nil),
	}
	got := narrowToolsByAttack(tools, nil, []string{"T1040"})
	if len(got) != 1 {
		t.Fatalf("nil index should pass through unchanged: got %d", len(got))
	}
}

func TestNarrowToolsByAttack_FiltersByTechnique(t *testing.T) {
	// T1557.004 = Evil Twin. The built-in mapping assigns that to
	// wifi_evil_portal_start and wifi_beacon_clone. Unrelated tools
	// should be dropped.
	tools := []anthropic.ToolUnionParam{
		tool("subghz_transmit", "x", nil),        // tagged T1200
		tool("wifi_scan_ap", "x", nil),           // T1018
		tool("wifi_evil_portal_start", "x", nil), // T1557.004  — kept
		tool("wifi_beacon_clone", "x", nil),      // T1557.004  — kept
		tool("audit_query", "x", nil),            // meta.audit — always-on
		tool("list_devices", "x", nil),           // meta.util  — always-on
	}
	got := narrowToolsByAttack(tools, attack.NewDefaultIndex(), []string{"T1557.004"})

	names := map[string]bool{}
	for _, t := range got {
		if t.OfTool != nil {
			names[t.OfTool.Name] = true
		}
	}
	want := []string{"wifi_evil_portal_start", "wifi_beacon_clone", "audit_query", "list_devices"}
	if len(names) != len(want) {
		t.Fatalf("narrowed set size = %d, want %d (%v)", len(names), len(want), names)
	}
	for _, n := range want {
		if !names[n] {
			t.Errorf("narrowed set missing %q: %v", n, names)
		}
	}
	if names["subghz_transmit"] {
		t.Errorf("subghz_transmit should be dropped (T1200 not in constraint): %v", names)
	}
	if names["wifi_scan_ap"] {
		t.Errorf("wifi_scan_ap should be dropped (T1018 not in constraint): %v", names)
	}
}

func TestNarrowToolsByAttack_MultipleTechniques(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("wifi_scan_ap", "x", nil),     // T1018
		tool("wifi_sniff_pmkid", "x", nil), // T1040, T1552.004
		tool("subghz_transmit", "x", nil),  // T1200
		tool("audit_query", "x", nil),      // meta.audit
	}
	got := narrowToolsByAttack(tools, attack.NewDefaultIndex(), []string{"T1018", "T1552.004"})
	names := toolNameSet(got)
	for _, want := range []string{"wifi_scan_ap", "wifi_sniff_pmkid", "audit_query"} {
		if !names[want] {
			t.Errorf("narrowed set missing %q: %v", want, names)
		}
	}
	if names["subghz_transmit"] {
		t.Errorf("subghz_transmit should be dropped: %v", names)
	}
}

func TestNarrowToolsByAttack_BelowFloorFallsBack(t *testing.T) {
	// A constraint that would leave fewer than minNarrowedTools must
	// fall back to the input unchanged.
	tools := []anthropic.ToolUnionParam{
		tool("subghz_transmit", "x", nil), // T1200
		tool("ir_transmit", "x", nil),     // T1200
		tool("wifi_scan_ap", "x", nil),    // T1018
	}
	// Constrain to a technique no tool satisfies — filter would yield 0.
	got := narrowToolsByAttack(tools, attack.NewDefaultIndex(), []string{"T9999"})
	if len(got) != len(tools) {
		t.Errorf("unmatched constraint should fall back to full catalog; got %d, want %d", len(got), len(tools))
	}
}

func TestNarrowToolsByAttack_IgnoresEmptyTechniqueStrings(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("wifi_scan_ap", "x", nil),
	}
	// Mixed blank + real entries — blanks should be discarded.
	got := narrowToolsByAttack(tools, attack.NewDefaultIndex(), []string{"", "   ", ""})
	if len(got) != len(tools) {
		t.Errorf("all-blank constraint should pass through: got %d", len(got))
	}
}

func TestAgent_AttackConstraintRoundTrip(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.SetAttackConstraint([]string{"T1557.004", "T1499", "T1557.004"})
	got := a.AttackConstraint()
	// Duplicates removed, order preserved.
	if len(got) != 2 {
		t.Fatalf("expected 2 unique techniques, got %v", got)
	}
	if got[0] != "T1557.004" || got[1] != "T1499" {
		t.Errorf("unexpected order: %v", got)
	}

	// Empty slice clears.
	a.SetAttackConstraint(nil)
	if got := a.AttackConstraint(); len(got) != 0 {
		t.Errorf("clear should empty the constraint; got %v", got)
	}
}

func TestAgent_AttackIndexSetGet(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	if got := a.AttackIndex(); got != nil {
		t.Errorf("fresh agent should have no attack index, got %+v", got)
	}
	idx := attack.NewDefaultIndex()
	a.SetAttackIndex(idx)
	if a.AttackIndex() != idx {
		t.Errorf("SetAttackIndex did not install the index")
	}
	a.SetAttackIndex(nil)
	if a.AttackIndex() != nil {
		t.Errorf("SetAttackIndex(nil) did not clear the index")
	}
}
