package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/fileformat"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "fileformat_read",
		Description: "Read a Flipper file from the SD card, parse it according to its extension (.sub/.nfc/.ir/.rfid), and return structural JSON (fields, blocks, signals). Read-only.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"SD-card path, e.g. /ext/subghz/garage.sub"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Low,
		Group:       GroupMetaUtil,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "path")
			if path == "" {
				return "", fmt.Errorf("path required")
			}
			raw, err := d.Flipper.StorageRead(path)
			if err != nil {
				return "", fmt.Errorf("storage read %s: %w", path, err)
			}
			model, format, err := fileformat.LoadFile(path, []byte(raw))
			if err != nil {
				return "", fmt.Errorf("parse %s: %w", path, err)
			}
			envelope := map[string]interface{}{
				"path":   path,
				"format": string(format),
				"file":   model,
			}
			b, err := json.MarshalIndent(envelope, "", "  ")
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
	})

	Register(Spec{
		Name:        "fileformat_edit",
		Description: "Parse a Flipper file, apply a top-level edits map, re-serialize, and write back to the SD card (same path unless output_path is given). Snapshots the destination before writing for /rewind recovery.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"SD-card path to read + parse"},"edits":{"type":"object","description":"Top-level field overrides per the format's allowed keys"},"output_path":{"type":"string","description":"Optional alternate SD path to write to (defaults to input path)"}}}`),
		Required:    []string{"path", "edits"},
		Risk:        risk.Medium,
		Group:       GroupMetaUtil,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "path")
			if path == "" {
				return "", fmt.Errorf("path required")
			}
			edits, ok := p["edits"].(map[string]interface{})
			if !ok || len(edits) == 0 {
				return "", fmt.Errorf("edits must be a non-empty object")
			}
			raw, err := d.Flipper.StorageRead(path)
			if err != nil {
				return "", fmt.Errorf("storage read %s: %w", path, err)
			}
			model, format, err := fileformat.LoadFile(path, []byte(raw))
			if err != nil {
				return "", fmt.Errorf("parse %s: %w", path, err)
			}
			if err := fileformat.ApplyEdits(format, model, edits); err != nil {
				return "", fmt.Errorf("apply edits: %w", err)
			}
			out, err := fileformat.SaveFile(format, model)
			if err != nil {
				return "", fmt.Errorf("serialize: %w", err)
			}
			target := str(p, "output_path")
			if target == "" {
				target = path
			}
			// Snapshot the existing file before overwriting so /rewind can
			// restore it (§F.1). Errors are swallowed — snapshot is advisory.
			d.SnapshotBeforeWrite(ctx, target)
			if err := d.Flipper.StorageWriteCtx(ctx, target, string(out)); err != nil {
				return "", fmt.Errorf("write %s: %w", target, err)
			}
			return fmt.Sprintf("edited %s (format=%s, %d bytes) → %s", path, format, len(out), target), nil
		},
	})

	Register(Spec{
		Name:        "fileformat_diff",
		Description: "Parse two Flipper files and return a structural diff (per-field, per-block, per-signal). Read-only. Format mismatches return {same_format:false}.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path_a":{"type":"string","description":"First SD-card path"},"path_b":{"type":"string","description":"Second SD-card path"}}}`),
		Required:    []string{"path_a", "path_b"},
		Risk:        risk.Low,
		Group:       GroupMetaUtil,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			pathA := str(p, "path_a")
			pathB := str(p, "path_b")
			if pathA == "" || pathB == "" {
				return "", fmt.Errorf("path_a and path_b are both required")
			}
			rawA, err := d.Flipper.StorageRead(pathA)
			if err != nil {
				return "", fmt.Errorf("storage read %s: %w", pathA, err)
			}
			rawB, err := d.Flipper.StorageRead(pathB)
			if err != nil {
				return "", fmt.Errorf("storage read %s: %w", pathB, err)
			}
			modelA, formatA, err := fileformat.LoadFile(pathA, []byte(rawA))
			if err != nil {
				return "", fmt.Errorf("parse %s: %w", pathA, err)
			}
			modelB, formatB, err := fileformat.LoadFile(pathB, []byte(rawB))
			if err != nil {
				return "", fmt.Errorf("parse %s: %w", pathB, err)
			}
			result, err := fileformat.Diff(formatA, modelA, formatB, modelB)
			if err != nil {
				return "", err
			}
			b, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
	})
}
