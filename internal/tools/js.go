package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "js_run",
		Description: "Execute a saved JavaScript file via the Flipper's JS runtime. Arbitrary code execution on the device. Fork-gated: only Xtreme, Momentum, and RogueMaster ship a JS runtime; returns a friendly-fork error on stock.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Absolute .js file path, e.g. /ext/apps/Scripts/foo.js"},"duration_seconds":{"type":"number","description":"Max runtime in seconds (default 60)"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Critical,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.JSRun(
				str(p, "path"),
				time.Duration(intOr(p, "duration_seconds", 60))*time.Second,
			)
		},
	})
}
