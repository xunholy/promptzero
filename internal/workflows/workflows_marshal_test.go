package workflows

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestResultMarshalJSON_StableFieldsWinOverExtra pins the docstring
// contract: "Collisions with the stable fields are dropped in favour
// of the stable field." Pre-fix the collision check used `_, exists
// := base[k]` which only matched keys ALREADY in the base map. When
// NextSteps was empty, base didn't include "next_steps" — so an
// Extra map carrying a "next_steps" key (typo, copy-paste from
// another workflow, a sub-workflow proxy) slipped through and
// surfaced as the top-level next_steps value despite the stable
// field being explicitly empty.
//
// The fix uses an unconditional stable-field name set so even empty
// stable fields shadow Extra collisions, matching the docstring.
func TestResultMarshalJSON_StableFieldsWinOverExtra(t *testing.T) {
	r := Result{
		Summary:   "captured handshake",
		Phases:    []PhaseResult{},
		NextSteps: nil, // explicitly empty — should still shadow Extra
		Extra: map[string]interface{}{
			"next_steps":   []string{"smuggled from extra"},
			"summary":      "ALSO smuggled", // collision with always-set stable field
			"phases":       "ALSO smuggled", // ditto
			"pmkid_hex":    "abc123",        // legitimate Extra key, should pass through
			"hashcat_mode": 22000,           // ditto
		},
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]interface{}
	if jerr := json.Unmarshal(raw, &got); jerr != nil {
		t.Fatalf("Unmarshal: %v", jerr)
	}

	// next_steps must not appear at all when NextSteps is empty AND
	// Extra contains "next_steps" — the docstring says stable fields
	// win. Pre-fix, Extra's "next_steps" took over.
	if _, present := got["next_steps"]; present {
		t.Errorf("next_steps slipped in from Extra despite the stable field being empty: %v", got["next_steps"])
	}

	// summary + phases must reflect the stable field values, not
	// Extra's collisions. These already worked pre-fix (because base
	// always populates them) but assert here to lock the contract.
	if got["summary"] != "captured handshake" {
		t.Errorf("summary collided: got %v, want %q", got["summary"], "captured handshake")
	}
	if got["summary"] == "ALSO smuggled" {
		t.Errorf("summary was overwritten by Extra")
	}

	// Legitimate Extra keys still flatten through.
	if got["pmkid_hex"] != "abc123" {
		t.Errorf("legitimate Extra key missing: pmkid_hex=%v", got["pmkid_hex"])
	}
}

// TestResultMarshalJSON_NextStepsPopulatedWinsToo covers the
// already-working side of the contract: when NextSteps is non-empty,
// it shadows any Extra["next_steps"] collision. The pre-fix code
// happened to handle this correctly (because base["next_steps"]
// was populated before the loop), but pin it so a future refactor
// that simplifies the stable-field set doesn't regress this case.
func TestResultMarshalJSON_NextStepsPopulatedWinsToo(t *testing.T) {
	r := Result{
		Summary:   "test",
		NextSteps: []string{"the real next step"},
		Extra: map[string]interface{}{
			"next_steps": []string{"smuggled"},
		},
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Cheaper than full unmarshal: assert the smuggled string isn't in
	// the output anywhere.
	if strings.Contains(string(raw), "smuggled") {
		t.Errorf("Extra's next_steps overwrote the populated stable field: %s", raw)
	}
	if !strings.Contains(string(raw), "the real next step") {
		t.Errorf("stable NextSteps missing from output: %s", raw)
	}
}
