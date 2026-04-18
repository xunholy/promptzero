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
