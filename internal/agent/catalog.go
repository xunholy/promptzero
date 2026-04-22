package agent

// ToolNames returns the names of every tool currently registered with the
// agent, in builder order. When hasMarauder is true the Marauder/WiFi tools
// are appended after the generation tools. Exposed so the CLI can render
// /tools without reaching into the private builder functions.
func ToolNames(hasMarauder bool) []string {
	tools := buildTools()
	tools = append(tools, buildGenTools()...)
	tools = append(tools, buildWorkflowTools()...)
	tools = append(tools, buildFileFormatTools()...)
	if hasMarauder {
		tools = append(tools, buildMarauderTools()...)
	}
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if t.OfTool == nil {
			continue
		}
		out = append(out, t.OfTool.Name)
	}
	return out
}

// requiredKeys returns the list of required JSON-schema keys declared
// by the tool named name, or nil if the tool is unknown. Used by the
// Batch E confidence check at dispatch time so it knows which keys
// have to be present-and-non-placeholder. Reads the catalog on every
// call; the lists are tiny (≤10 entries each) and the catalog is
// built from static literals, so the cost is negligible.
func requiredKeys(name string, hasMarauder bool) []string {
	tools := buildTools()
	tools = append(tools, buildGenTools()...)
	tools = append(tools, buildWorkflowTools()...)
	tools = append(tools, buildFileFormatTools()...)
	if hasMarauder {
		tools = append(tools, buildMarauderTools()...)
	}
	for _, t := range tools {
		if t.OfTool == nil || t.OfTool.Name != name {
			continue
		}
		return t.OfTool.InputSchema.Required
	}
	return nil
}
