package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "loader_info",
		Description: "Return metadata about the currently running app (name, flags). Read-only; useful to verify a loader_open actually launched something before sending input_send events.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderInfo()
		},
	})

	Register(Spec{
		Name:        "loader_open",
		Description: "Open a Flipper application by name with optional arguments. Use to launch any built-in or FAP app. If you're unsure whether the app is installed, call list_apps first.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"app_name":{"type":"string","description":"Application name, e.g. NFC, SubGHz, iButton, Bad USB, GPIO"},"args":{"type":"string","description":"Optional arguments to pass to the app"}}}`),
		Required:    []string{"app_name"},
		Risk:        risk.High,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.LoaderOpen(str(p, "app_name"), str(p, "args"))
		},
	})

	Register(Spec{
		Name:        "loader_close",
		Description: "Close the currently running Flipper application.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderClose()
		},
	})

	Register(Spec{
		Name:        "loader_signal",
		Description: "Send a numeric signal to the currently running app. Signal meanings are app-specific; many apps document a small set of custom opcodes (pause, toggle, reset).",
		Schema:      json.RawMessage(`{"type":"object","properties":{"signal":{"type":"integer","description":"Signal number to deliver"},"arg_hex":{"type":"string","description":"Optional hex argument passed alongside the signal"}}}`),
		Required:    []string{"signal"},
		Risk:        risk.High,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.LoaderSignal(intOr(p, "signal", 0), str(p, "arg_hex"))
		},
	})

	Register(Spec{
		Name:        "list_apps",
		Description: "List every installed Flipper application plus the settings-menu entries. Call this BEFORE loader_open when the target app's availability is uncertain — avoids the silent-failure path where loader_open launches a missing FAP. Returns structured JSON: {apps: [...], settings: [...]}.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			apps, err := d.Flipper.LoaderListParsed()
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(apps)
			return string(b), nil
		},
	})
}
