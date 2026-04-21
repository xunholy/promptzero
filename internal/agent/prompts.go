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
	basePrompt      = mustReadPrompt("system.tmpl")
	wifiAppend      = mustReadPrompt("wifi_append.tmpl")
	workflowsAppend = mustReadPrompt("workflows_append.tmpl")
	trustAppend     = mustReadPrompt("trust_append.tmpl")
)

// BuildSystemPrompt assembles the system prompt the agent hands to the
// model at the start of each turn. When a persona is supplied and sets its
// own SystemPrompt, that preamble replaces the built-in base (matching the
// historical persona-override behaviour). The WiFi framing is appended only
// when the Marauder tool set is still present after persona filtering.
// The workflow section is appended when composite workflows are registered.
// The trust-boundary clause is always appended — it governs the
// <untrusted-hardware-output> wrappers that quarantine attacker-controllable
// content returned by hardware tools.
func BuildSystemPrompt(p *persona.Persona, hasWiFi, hasWorkflows bool) string {
	var b strings.Builder
	if p != nil && p.SystemPrompt != "" {
		b.WriteString(p.SystemPrompt)
	} else {
		b.WriteString(basePrompt)
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
