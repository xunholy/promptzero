package agent

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/toolctx"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
)

// builtToolsOnce caches the assembled tool catalog. The registry is
// read-only after package init() — every Spec is added exactly once
// via Register — so we can build the Anthropic ToolUnionParam list a
// single time and reuse it across every Run. Run was rebuilding all
// 274+ entries (each requiring a JSON unmarshal of the schema)
// per-turn before this cache.
var (
	builtToolsOnce  sync.Once
	builtToolsCache []anthropic.ToolUnionParam
)

func buildTools() []anthropic.ToolUnionParam {
	builtToolsOnce.Do(func() {
		// All tools are registered in the central registry. Emit one
		// entry per Spec (and per Alias) so the LLM sees every tool
		// name as a callable.
		regTools := make([]anthropic.ToolUnionParam, 0, len(toolsreg.All()))
		for _, spec := range toolsreg.All() {
			propsMap := schemaToProps(spec.Schema)
			regTools = append(regTools, tool(spec.Name, spec.Description, propsMap, spec.Required...))
			for _, alias := range spec.Aliases {
				regTools = append(regTools, tool(alias, spec.Description, propsMap, spec.Required...))
			}
		}
		builtToolsCache = regTools
	})
	return builtToolsCache
}

// filterToolsToReadOnly narrows a tool catalog to only those whose
// registered Spec.Risk is risk.Low. Used by the Run loop when the
// agent is in read-only mode so the LLM doesn't see tools it would
// only get refused at dispatch — saves tokens and avoids wasted
// reflexion turns on policy-walled writes/transmits.
//
// Tools whose Spec is not in the registry (defensive: should never
// happen since buildTools sources from the registry) pass through
// unchanged so a future code path adding non-registered tools does
// not silently disappear under read-only.
func filterToolsToReadOnly(in []anthropic.ToolUnionParam) []anthropic.ToolUnionParam {
	out := make([]anthropic.ToolUnionParam, 0, len(in))
	for _, t := range in {
		if t.OfTool == nil {
			out = append(out, t)
			continue
		}
		spec, ok := toolsreg.Get(t.OfTool.Name)
		if !ok {
			out = append(out, t)
			continue
		}
		if spec.Risk == risk.Low {
			out = append(out, t)
		}
	}
	return out
}

// schemaToProps converts the "properties" object from a JSON Schema into the
// map[string]interface{} that tool() / anthropic.ToolInputSchemaParam.Properties
// expects. Returns nil for an empty or unparseable schema.
func schemaToProps(schema json.RawMessage) map[string]interface{} {
	if len(schema) == 0 {
		return nil
	}
	var s struct {
		Properties map[string]interface{} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &s); err != nil || len(s.Properties) == 0 {
		return nil
	}
	return s.Properties
}

// Helper constructors for clean tool definitions.

// ToolExample is a single canonical input → outcome pair for a tool's
// description. Examples are rendered into the prompt-cached tool
// definition so the model sees concrete usage patterns without any
// per-turn cost. Keep each example short — two lines max — so the
// cumulative description stays under ~1 KB.
type ToolExample struct {
	Input string // JSON for the tool's input params, e.g. `{"file":"/ext/subghz/garage.sub"}`
	Note  string // short human-readable outcome, e.g. "replays a garage-door capture"
}

func tool(name, desc string, properties map[string]interface{}, required ...string) anthropic.ToolUnionParam {
	input := anthropic.ToolInputSchemaParam{
		Properties: properties,
	}
	if len(required) > 0 {
		input.Required = required
	}
	return anthropic.ToolUnionParam{
		OfTool: &anthropic.ToolParam{
			Name:        name,
			Description: anthropic.String(toolctx.EnrichDescription(name, desc)),
			InputSchema: input,
		},
	}
}

// toolEx is tool() with a few-shot examples block appended to the
// description. Literature (arXiv 2310.08540 and follow-ups) shows a
// single canonical example lifts tool-arg accuracy on rare tools by
// double-digit points; two examples cover the common / edge-case
// split. The block is deterministic, so the system+tools prompt-cache
// breakpoint placed in buildCachedRequest still hits on every turn.
func toolEx(name, desc string, properties map[string]interface{}, examples []ToolExample, required ...string) anthropic.ToolUnionParam {
	return tool(name, renderExamples(desc, examples), properties, required...)
}

// renderExamples appends a short "Examples:" section to the tool
// description. Exposed (package-private) so tests can exercise the
// rendering shape without reaching through tool().
func renderExamples(desc string, examples []ToolExample) string {
	if len(examples) == 0 {
		return desc
	}
	var b strings.Builder
	b.WriteString(desc)
	b.WriteString("\n\nExamples:")
	for _, ex := range examples {
		b.WriteString("\n- ")
		b.WriteString(ex.Input)
		if ex.Note != "" {
			b.WriteString("  — ")
			b.WriteString(ex.Note)
		}
	}
	return b.String()
}

func props(items ...map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{})
	for _, item := range items {
		for k, v := range item {
			merged[k] = v
		}
	}
	return merged
}

func reqProp(name, typ, desc string) map[string]interface{} {
	return map[string]interface{}{
		name: map[string]interface{}{
			"type":        typ,
			"description": desc,
		},
	}
}

// ToolCatalogEntry pairs a registered tool's name with its description and its
// advisory agent-only flag. Used by /tools (CLI) and /api/tools (Web) to render
// each entry. Every tool is exposed on every surface (CLI/Web/MCP) — the flag is
// NOT an exposure gate. AgentOnly=true is advisory: the tool needs agent-mode
// deps (an LLM generator / vision / target-memory store) to function fully, or
// drives an interactive device session the agent normally orchestrates; absent
// that dep it degrades to a clear "needs X" message. Surfacing the flag tells a
// user which tools need extra setup (e.g. an API key) to do more than report.
type ToolCatalogEntry struct {
	Name        string
	Description string
	AgentOnly   bool
	// Group and Aliases mirror the registry Spec so callers can rank/filter
	// the catalog (e.g. the web /api/tools?q= search) over the same fields the
	// tool_search tool uses, instead of only name + description.
	Group   string
	Aliases []string
}

// ToolCatalog returns every registered tool's name + description + agent-only
// flag + group + aliases, in the same builder order as ToolNames.
func ToolCatalog(hasMarauder bool) []ToolCatalogEntry {
	_ = hasMarauder // retained for API compatibility; all tools are now in the registry
	tools := buildTools()
	out := make([]ToolCatalogEntry, 0, len(tools))
	for _, t := range tools {
		if t.OfTool == nil {
			continue
		}
		desc := ""
		if t.OfTool.Description.Valid() {
			desc = t.OfTool.Description.Value
		}
		entry := ToolCatalogEntry{Name: t.OfTool.Name, Description: desc}
		if spec, ok := toolsreg.Get(t.OfTool.Name); ok {
			entry.AgentOnly = spec.AgentOnly
			entry.Group = string(spec.Group)
			entry.Aliases = spec.Aliases
		}
		out = append(out, entry)
	}
	return out
}
