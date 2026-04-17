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
