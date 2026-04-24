package agent

import (
	"encoding/json"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/toolctx"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
)

func buildTools() []anthropic.ToolUnionParam {
	// All tools are registered in the central registry. Emit one entry per
	// Spec (and per Alias) so the LLM sees every tool name as a callable.
	var regTools []anthropic.ToolUnionParam
	for _, spec := range toolsreg.All() {
		propsMap := schemaToProps(spec.Schema)
		regTools = append(regTools, tool(spec.Name, spec.Description, propsMap, spec.Required...))
		for _, alias := range spec.Aliases {
			regTools = append(regTools, tool(alias, spec.Description, propsMap, spec.Required...))
		}
	}
	return regTools
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

// ToolCatalogEntry pairs a registered tool's name with its description.
// Used by /tools to render each entry with a short description alongside
// the name.
type ToolCatalogEntry struct {
	Name        string
	Description string
}

// ToolCatalog returns every registered tool's name + description, in the
// same builder order as ToolNames.
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
		out = append(out, ToolCatalogEntry{Name: t.OfTool.Name, Description: desc})
	}
	return out
}
