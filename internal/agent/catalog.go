package agent

import (
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
)

// ToolNames returns the names of every tool currently registered with the
// agent, in builder order. Exposed so the CLI can render /tools without
// reaching into the private builder functions.
func ToolNames(hasMarauder bool) []string {
	_ = hasMarauder // retained for API compatibility; all tools are now in the registry
	tools := buildTools()
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if t.OfTool == nil {
			continue
		}
		out = append(out, t.OfTool.Name)
	}
	return out
}

// requiredKeysCache holds the tool-name → required-keys mapping.
// Built lazily on first access via sync.Once so a Go-test agent that
// never runs the dispatch path doesn't pay the catalog-build cost.
var (
	requiredKeysOnce         sync.Once
	requiredKeysNoMarauder   map[string][]string
	requiredKeysWithMarauder map[string][]string
)

func initRequiredKeysCache() {
	extract := func(tools []anthropic.ToolUnionParam) map[string][]string {
		m := make(map[string][]string, len(tools))
		for _, t := range tools {
			if t.OfTool == nil {
				continue
			}
			m[t.OfTool.Name] = t.OfTool.InputSchema.Required
		}
		return m
	}
	// All tools are in the registry; buildTools() returns the full catalog.
	base := buildTools()
	requiredKeysNoMarauder = extract(base)
	// WiFi/Marauder tools are in the registry, so both maps are identical.
	requiredKeysWithMarauder = extract(base)
}

// requiredKeys returns the list of required JSON-schema keys declared
// by the tool named name, or nil if the tool is unknown. Used by the
// Batch E confidence check at dispatch time. O(1) after the first call.
func requiredKeys(name string, hasMarauder bool) []string {
	requiredKeysOnce.Do(initRequiredKeysCache)
	if hasMarauder {
		return requiredKeysWithMarauder[name]
	}
	return requiredKeysNoMarauder[name]
}
