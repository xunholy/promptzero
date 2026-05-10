package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "ibutton_read",
		Description: "Read an iButton key. Supports Dallas DS1990A, Cyfral, Metakom protocols. Hardware: touch the iButton contact pad on the top-left corner of the Flipper.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"timeout_seconds":{"type":"number","description":"How long to wait (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperIButton,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.IButtonReadCtx(ctx, time.Duration(intOr(p, "timeout_seconds", 30))*time.Second)
		},
	})

	Register(Spec{
		Name:        "ibutton_emulate",
		Description: "Emulate an iButton key by specifying protocol and hex data.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"protocol":{"type":"string","description":"iButton protocol: Dallas, Cyfral, Metakom"},"hex_data":{"type":"string","description":"Hex key data to emulate"},"duration_seconds":{"type":"number","description":"Emulation window (default 10)"}}}`),
		Required:    []string{"protocol", "hex_data"},
		Risk:        risk.High,
		Group:       GroupFlipperIButton,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.IButtonEmulateCtx(
				ctx,
				str(p, "protocol"),
				str(p, "hex_data"),
				time.Duration(intOr(p, "duration_seconds", 10))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "ibutton_write",
		Description: "Write/clone a Dallas iButton key to a writable blank.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"hex_data":{"type":"string","description":"Hex key data to write (Dallas protocol only)"}}}`),
		Required:    []string{"hex_data"},
		Risk:        risk.High,
		Group:       GroupFlipperIButton,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.IButtonWrite(str(p, "hex_data"))
		},
	})
}
