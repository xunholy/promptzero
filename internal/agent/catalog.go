package agent

import (
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
)

// ToolNames returns the names of every tool currently registered with the
// agent, in builder order. When hasMarauder is true the Marauder/WiFi tools
// are appended after the generation tools. Exposed so the CLI can render
// /tools without reaching into the private builder functions.
func ToolNames(hasMarauder bool) []string {
	tools := buildTools()
	tools = append(tools, buildGenTools()...)
	tools = append(tools, buildWorkflowTools()...)
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

// requiredKeysCache holds the tool-name → required-keys mapping for
// both possible marauder-availability states. Built lazily on first
// access via sync.Once so a Go-test agent that never runs the
// dispatch path doesn't pay the catalog-build cost.
//
// The cache is complete because both builder sets are static (pure
// functions of literals). A tool added to the catalog without a
// cache reload would miss confidence checks — but tools are only
// registered via these two builder functions, so a refactor that
// adds a third would be caught by the risk-coverage test.
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
	base := buildTools()
	base = append(base, buildGenTools()...)
	base = append(base, buildWorkflowTools()...)
	requiredKeysNoMarauder = extract(base)
	withM := append([]anthropic.ToolUnionParam{}, base...)
	withM = append(withM, buildMarauderTools()...)
	requiredKeysWithMarauder = extract(withM)
}

// requiredKeys returns the list of required JSON-schema keys declared
// by the tool named name, or nil if the tool is unknown. Used by the
// Batch E confidence check at dispatch time so it knows which keys
// have to be present-and-non-placeholder. O(1) after the first call;
// the post-review audit flagged the previous implementation's full
// catalog rebuild per dispatch as a 2-5ms tax on every tool call.
func requiredKeys(name string, hasMarauder bool) []string {
	requiredKeysOnce.Do(initRequiredKeysCache)
	if hasMarauder {
		return requiredKeysWithMarauder[name]
	}
	return requiredKeysNoMarauder[name]
}
