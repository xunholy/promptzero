package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/flipper"
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
		WriteIntent: func(args map[string]any) (string, string, bool) {
			path, _ := args["path"].(string)
			content, _ := args["content"].(string)
			if path == "" {
				return "", "", false
			}
			return path, content, true
		},
	})

	Register(Spec{
		Name:        "storage_list",
		Description: "List files and directories on the Flipper SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Directory path, e.g. /ext/subghz or /ext/nfc"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.StorageList(str(p, "path"))
		},
	})

	Register(Spec{
		Name:        "storage_read",
		Description: "Read the contents of a file on the Flipper SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"File path to read"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.StorageRead(str(p, "path"))
		},
	})

	Register(Spec{
		Name:        "storage_delete",
		Description: "Delete a file or directory from the Flipper SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Path to delete"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.StorageRemove(str(p, "path"))
		},
	})

	Register(Spec{
		Name:        "storage_mkdir",
		Description: "Create a directory on the Flipper SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Directory path to create"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.StorageMkdir(str(p, "path"))
		},
	})

	Register(Spec{
		Name:        "storage_info",
		Description: "Get file/directory info (size, type) from the Flipper SD card. Returns structured JSON.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Path to inspect"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			raw, err := d.Flipper.StorageStat(str(p, "path"))
			if err != nil {
				return raw, err
			}
			parsed := flipper.ParseStorageStat(raw)
			b, _ := json.Marshal(parsed)
			return string(b), nil
		},
	})

	Register(Spec{
		Name:        "storage_copy",
		Description: "Copy a file or directory on the Flipper SD card. Non-destructive to the source; overwrites the destination if it already exists.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"src":{"type":"string","description":"Source path, e.g. /ext/subghz/garage.sub"},"dst":{"type":"string","description":"Destination path"}}}`),
		Required:    []string{"src", "dst"},
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			// Snapshot the destination (if it already exists) before the
			// copy so /rewind can restore it — the source stays intact by
			// definition and doesn't need a snapshot.
			d.SnapshotBeforeWrite(ctx, str(p, "dst"))
			return d.Flipper.StorageCopy(str(p, "src"), str(p, "dst"))
		},
	})

	Register(Spec{
		Name:        "storage_rename",
		Description: "Rename or move a file/directory on the SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"src":{"type":"string","description":"Current path"},"dst":{"type":"string","description":"New path"}}}`),
		Required:    []string{"src", "dst"},
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			// Snapshot both ends: the destination might pre-exist (will
			// be clobbered) and so might the source (rename removes it
			// from its original path, so the user may want it back).
			d.SnapshotBeforeWrite(ctx, str(p, "src"))
			d.SnapshotBeforeWrite(ctx, str(p, "dst"))
			return d.Flipper.StorageRename(str(p, "src"), str(p, "dst"))
		},
	})

	Register(Spec{
		Name:        "storage_md5",
		Description: "Return the MD5 hash of a file on the SD card. Use to verify a deployment matches the expected bytes, or to compare two files quickly.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"File path to hash"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.StorageMD5(str(p, "path"))
		},
	})

	Register(Spec{
		Name:        "storage_tree",
		Description: "Recursively list a directory and its contents. Read-only; useful when the user asks 'what's in /ext/subghz?' and you want the full picture, not just the top level.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Directory path to walk"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.StorageTree(str(p, "path"))
		},
	})
}
