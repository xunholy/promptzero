package campaign

import (
	"context"
	"fmt"
)

// ToolDispatcher is the narrow interface Campaigns asks of an agent-
// backed executor — one method that runs a named tool with params
// and returns (output, error). Mirrors the shape of the rules engine's
// RunTool callback so both surfaces can share an adapter.
type ToolDispatcher interface {
	RunTool(ctx context.Context, tool string, params map[string]interface{}) (string, error)
}

// AgentExecutor adapts a ToolDispatcher to the campaign StepExecutor
// interface. Production wiring passes the agent's dispatch (see
// cmd/promptzero). Keeping the adapter here avoids pulling the
// agent package into internal/campaign.
type AgentExecutor struct {
	Dispatcher ToolDispatcher
}

// Run implements StepExecutor. Empty tool name is rejected early
// because a misread YAML file is more recoverable with a clean
// error than with a deep dispatch failure.
func (a AgentExecutor) Run(ctx context.Context, tool string, params map[string]interface{}) (string, error) {
	if tool == "" {
		return "", fmt.Errorf("campaign: empty tool name")
	}
	if a.Dispatcher == nil {
		return "", fmt.Errorf("campaign: no dispatcher configured")
	}
	return a.Dispatcher.RunTool(ctx, tool, params)
}
