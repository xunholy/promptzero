package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "storage_write",
		Description: "Write content to a file on the Flipper SD card. Overwrites any existing file at path. Use the generate_* or *_build tools when you need a structured Flipper payload (.sub/.nfc/.ir/.rfid/BadUSB) — those build and validate; storage_write is the bare-bytes escape hatch when you already have the exact content.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Destination file path on the Flipper SD card (e.g. /ext/apps_data/notes.txt)"},"content":{"type":"string","description":"Exact bytes to write (UTF-8)"}}}`),
		Required:    []string{"path", "content"},
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			path, _ := p["path"].(string)
			content, _ := p["content"].(string)
			d.SnapshotBeforeWrite(ctx, path)
			if err := d.Flipper.StorageWriteCtx(ctx, path, content); err != nil {
				return "", err
			}
			return "ok", nil
		},
	})
}
