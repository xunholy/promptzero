package agent

import "github.com/anthropics/anthropic-sdk-go"

// buildMarauderTools is a stub retained for the tools_examples_test.go
// harness. All WiFi/Marauder tools were migrated to the central registry
// (internal/tools/wifi.go, marauder.go) in Wave 3 and are surfaced
// automatically via buildTools(). Returns nil — no-op for callers.
func buildMarauderTools() []anthropic.ToolUnionParam {
	return nil
}
