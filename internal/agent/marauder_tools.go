package agent

import "github.com/anthropics/anthropic-sdk-go"

// buildMarauderTools returns the legacy WiFi/Marauder tool declarations for
// the agent's Anthropic schema. All tools have been migrated to the central
// registry (internal/tools/wifi.go, internal/tools/marauder.go) in Wave 3 —
// the registry-backed prepass in buildTools() now surfaces them automatically.
// This stub is retained for binary compatibility with callers such as
// internal/agent/catalog.go and the tools_examples_test.go harness that
// append its result; Wave 5 will remove it entirely.
func buildMarauderTools() []anthropic.ToolUnionParam {
	return nil
}
