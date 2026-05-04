package agent

import (
	"embed"
	"strings"

	"github.com/xunholy/promptzero/internal/persona"
)

//go:embed prompts/*.tmpl
var promptFS embed.FS

// mustReadPrompt returns the contents of a bundled prompt template, stripped
// of trailing whitespace. Panics at package init time if the file is absent
// — the embed directive guarantees it's present at build time.
func mustReadPrompt(name string) string {
	b, err := promptFS.ReadFile("prompts/" + name)
	if err != nil {
		panic("agent: embedded prompt missing: " + name + ": " + err.Error())
	}
	return strings.TrimRight(string(b), "\n")
}

var (
	wifiAppend      = mustReadPrompt("wifi_append.tmpl")
	workflowsAppend = mustReadPrompt("workflows_append.tmpl")
	trustAppend     = mustReadPrompt("trust_append.tmpl")
)

// defaultPersonaPrompt returns the canonical fallback system prompt — the
// "default" built-in persona's. v0.20.0 collapsed the formerly-separate
// system.tmpl into this single source of truth so test harnesses (pzrunner,
// eval) and the agent's own pre-persona window both pick up the same
// strengthened authorisation framing the CLI uses.
//
// Resolved lazily so the registry's init order doesn't constrain agent
// package init. The lookup is O(1) and the result is small; no caching is
// needed.
func defaultPersonaPrompt() string {
	reg := persona.NewRegistry()
	if p, ok := reg.Get("default"); ok && p.SystemPrompt != "" {
		return p.SystemPrompt
	}
	// Defensive: if someone removes the default builtin, fall back to a
	// minimal acknowledgement so the agent doesn't ship an empty
	// system block. Should never trigger in production.
	return "You are PromptZero — an operator-controlled tool layer for a Flipper Zero and an ESP32 Marauder."
}

// BuildSystemPrompt assembles the system prompt the agent hands to the
// model at the start of each turn. When a persona is supplied and sets its
// own SystemPrompt, that preamble replaces the default. The WiFi framing
// is appended only when the Marauder tool set is still present after
// persona filtering. The workflow section is appended when composite
// workflows are registered. The trust-boundary clause is always appended —
// it governs the <untrusted-hardware-output> wrappers that quarantine
// attacker-controllable content returned by hardware tools.
func BuildSystemPrompt(p *persona.Persona, hasWiFi, hasWorkflows bool) string {
	var b strings.Builder
	if p != nil && p.SystemPrompt != "" {
		b.WriteString(p.SystemPrompt)
	} else {
		b.WriteString(defaultPersonaPrompt())
	}
	if hasWorkflows {
		b.WriteString(workflowsAppend)
	}
	if hasWiFi {
		b.WriteString(wifiAppend)
	}
	b.WriteString(trustAppend)
	return b.String()
}
