package workflows

import (
	"context"
	"fmt"
)

// These stubs exist so the agent dispatch compiles while subsequent
// commits land each real workflow. Each is replaced by the real
// implementation in its dedicated file as Phase 3 progresses. The
// function signatures are stable: callers (agent.dispatch) bind to
// them via name.

// RolljamLabDemo — placeholder until its commit. See rolljam.go.
func RolljamLabDemo(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	return "", fmt.Errorf("workflow_rolljam_lab_demo not yet implemented")
}

// WiFiTargetToHashcat — placeholder until its commit. See wifi_hashcat.go.
func WiFiTargetToHashcat(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	return "", fmt.Errorf("workflow_wifi_target_to_hashcat not yet implemented")
}
