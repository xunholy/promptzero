package agent

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/persona"
)

func TestBuildSystemPrompt_Base(t *testing.T) {
	got := BuildSystemPrompt(nil, false, false)
	if !strings.Contains(got, "PromptZero") {
		t.Fatalf("base prompt missing identity line: %q", got)
	}
	if strings.Contains(got, "ESP32 Marauder WiFi devboard") {
		t.Fatalf("base prompt should not include WiFi section when hasWiFi=false:\n%s", got)
	}
	if strings.Contains(got, "COMPOSITE WORKFLOWS") {
		t.Fatalf("base prompt should not include workflows when hasWorkflows=false:\n%s", got)
	}
}

func TestBuildSystemPrompt_WiFiAppend(t *testing.T) {
	got := BuildSystemPrompt(nil, true, false)
	if !strings.Contains(got, "ESP32 Marauder WiFi devboard") {
		t.Fatalf("WiFi append missing when hasWiFi=true:\n%s", got)
	}
	if !strings.Contains(got, "PromptZero") {
		t.Fatalf("base prompt missing when WiFi appended:\n%s", got)
	}
}

func TestBuildSystemPrompt_WorkflowsAppend(t *testing.T) {
	got := BuildSystemPrompt(nil, false, true)
	if !strings.Contains(got, "COMPOSITE WORKFLOWS") {
		t.Fatalf("workflows append missing when hasWorkflows=true:\n%s", got)
	}
	if !strings.Contains(got, "workflow_nfc_badge_pipeline") {
		t.Fatalf("workflows append missing workflow catalogue:\n%s", got)
	}
}

func TestBuildSystemPrompt_PersonaOverride(t *testing.T) {
	p := &persona.Persona{Name: "test", SystemPrompt: "You are a custom persona. Do X only."}
	got := BuildSystemPrompt(p, false, false)
	if !strings.HasPrefix(got, "You are a custom persona.") {
		t.Fatalf("persona SystemPrompt did not replace base: %q", got)
	}
	if strings.Contains(got, "PromptZero") {
		t.Fatalf("base prompt leaked through persona override:\n%s", got)
	}
}

func TestBuildSystemPrompt_PersonaOverrideStillAppends(t *testing.T) {
	p := &persona.Persona{Name: "test", SystemPrompt: "Custom base."}
	got := BuildSystemPrompt(p, true, true)
	if !strings.Contains(got, "COMPOSITE WORKFLOWS") {
		t.Fatalf("workflows should append even when persona overrides the base:\n%s", got)
	}
	if !strings.Contains(got, "ESP32 Marauder WiFi devboard") {
		t.Fatalf("WiFi should append even when persona overrides the base:\n%s", got)
	}
}

// TestPromptTemplateHash_StableAndDistinct pins that each embedded
// template produces a deterministic 64-char hex hash and that the
// three known templates have distinct hashes (no accidental dupe).
func TestPromptTemplateHash_StableAndDistinct(t *testing.T) {
	names := []string{"wifi_append.tmpl", "workflows_append.tmpl", "trust_append.tmpl"}
	seen := make(map[string]string, len(names))
	for _, n := range names {
		h := PromptTemplateHash(n)
		if len(h) != 64 {
			t.Errorf("%s hash length = %d, want 64", n, len(h))
		}
		// Stable across calls.
		if PromptTemplateHash(n) != h {
			t.Errorf("%s hash unstable across calls", n)
		}
		if other, dup := seen[h]; dup {
			t.Errorf("%s hash collides with %s", n, other)
		}
		seen[h] = n
	}
}

func TestPromptTemplateHash_UnknownNameReturnsEmpty(t *testing.T) {
	if got := PromptTemplateHash("nonexistent.tmpl"); got != "" {
		t.Errorf("unknown template hash = %q, want empty", got)
	}
}

// TestSystemPromptHash_DistinctForDifferentInputs pins that the
// assembled-prompt hash changes when persona / hasWiFi / hasWorkflows
// changes — so audit-row regression analysis can group sessions by
// the *exact* prompt the model saw.
func TestSystemPromptHash_DistinctForDifferentInputs(t *testing.T) {
	base := SystemPromptHash(nil, false, false)
	withWiFi := SystemPromptHash(nil, true, false)
	withWorkflows := SystemPromptHash(nil, false, true)
	withCustom := SystemPromptHash(&persona.Persona{
		Name: "test", SystemPrompt: "I am a different system prompt entirely.",
	}, false, false)

	if base == withWiFi || base == withWorkflows || base == withCustom {
		t.Errorf("hashes collide:\n base=%s\n wifi=%s\n wf=%s\n custom=%s",
			base, withWiFi, withWorkflows, withCustom)
	}
	if len(base) != 64 {
		t.Errorf("hash length = %d", len(base))
	}
}

func TestSystemPromptHash_StableForSameInputs(t *testing.T) {
	a := SystemPromptHash(nil, true, true)
	b := SystemPromptHash(nil, true, true)
	if a != b {
		t.Errorf("hash unstable: %s vs %s", a, b)
	}
}

// TestBuildSystemPrompt_TrustClauseCoversGroundingBlocks pins that the trust
// clause names the <device-state> and <ui-context> grounding blocks as
// data-only. buildDeviceStateBlock embeds device-controllable strings (the
// dolphin name, firmware fork/version) into a user turn; JSON escaping prevents
// tag breakout, but the model must also be told to treat those values as
// context, not instructions — and buildDeviceStateBlock's docstring claims this
// clause exists. Guards that the claim stays true.
func TestBuildSystemPrompt_TrustClauseCoversGroundingBlocks(t *testing.T) {
	got := BuildSystemPrompt(nil, false, false)
	for _, want := range []string{"<device-state>", "<ui-context", "never as instructions"} {
		if !strings.Contains(got, want) {
			t.Errorf("trust clause does not cover grounding blocks — missing %q:\n%s", want, got)
		}
	}
}
