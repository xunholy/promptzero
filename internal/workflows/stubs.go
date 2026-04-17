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

// GarageDoorTriage — placeholder until its commit. See garage_door.go.
func GarageDoorTriage(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	return "", fmt.Errorf("workflow_garage_door_triage not yet implemented")
}

// RolljamLabDemo — placeholder until its commit. See rolljam.go.
func RolljamLabDemo(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	return "", fmt.Errorf("workflow_rolljam_lab_demo not yet implemented")
}

// PhysPentestBadgeWalk — placeholder until its commit. See badge_walk.go.
func PhysPentestBadgeWalk(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	return "", fmt.Errorf("workflow_phys_pentest_badge_walk not yet implemented")
}

// BadUSBTargetProfile — placeholder until its commit. See badusb_profile.go.
func BadUSBTargetProfile(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	return "", fmt.Errorf("workflow_badusb_target_profile not yet implemented")
}

// WiFiTargetToHashcat — placeholder until its commit. See wifi_hashcat.go.
func WiFiTargetToHashcat(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	return "", fmt.Errorf("workflow_wifi_target_to_hashcat not yet implemented")
}
