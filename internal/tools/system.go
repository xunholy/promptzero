package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "device_info",
		Aliases:     []string{"system_info"}, // agent-side legacy synonym (§F.4)
		Description: "Get Flipper Zero device information: firmware version, hardware revision, uptime, etc.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.DeviceInfo()
		},
	})
}
