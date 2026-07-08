// SPDX-License-Identifier: AGPL-3.0-or-later

// wigle_upload POSTs a wardrive CSV to wigle.net. It is the outward-egress
// counterpart to wigle_wardrive_export (which only formats data locally).
// Because it transmits captured location data off-box, it is High risk and
// gated twice: the operator must arm it via wigle.upload_enabled AND confirm
// each call. Credentials come from config/env, never from tool arguments.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wigle"
)

func init() { //nolint:gochecknoinits
	Register(wigleUploadSpec)
}

var wigleUploadSpec = Spec{
	Name: "wigle_upload",
	Description: "**Upload a wardrive CSV to wigle.net.** Takes a WiGLE `WigleWifi-1.4` CSV (the output of " +
		"`wigle_wardrive_export`) and POSTs it to the WiGLE file-upload API over an authenticated connection.\n\n" +
		"**Outward network egress of captured location data — High risk, off by default.** This tool refuses " +
		"unless the operator has set `wigle.upload_enabled: true` in config, and every call is confirmation-gated " +
		"and audited. Credentials come from `wigle.api_name`/`wigle.api_token` (or the `WIGLE_API_NAME` / " +
		"`WIGLE_API_TOKEN` environment variables), never from tool arguments.\n\n" +
		"`donate` defaults to false — the upload is NOT marked as donated/public unless you explicitly opt in.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"csv":{"type":"string","description":"WiGLE WigleWifi-1.4 CSV content (e.g. from wigle_wardrive_export)"},
			"donate":{"type":"boolean","description":"Mark the upload as donated/public on WiGLE (default false)"},
			"filename":{"type":"string","description":"Filename WiGLE records for the upload (default promptzero-wardrive.csv)"}
		},
		"required":["csv"]
	}`),
	Required:  []string{"csv"},
	Risk:      risk.High,
	Group:     GroupMetaUtil,
	AgentOnly: false,
	Handler:   wigleUploadHandler,
}

func wigleUploadHandler(ctx context.Context, deps *Deps, p map[string]any) (string, error) {
	if deps == nil || deps.Config == nil {
		return "", fmt.Errorf("wigle_upload: configuration unavailable")
	}
	cfg := deps.Config.Wigle

	// Gate 1 (config opt-in): live egress is off until the operator arms it.
	// This is independent of, and layered under, the High-risk confirmation
	// gate the dispatch path applies to every call.
	if !cfg.UploadEnabled {
		return "", fmt.Errorf("wigle_upload: uploads are disabled — set wigle.upload_enabled: true in config to arm " +
			"live uploads to wigle.net (this tool egresses captured location data off-box)")
	}
	// Credentials are merged from WIGLE_API_NAME / WIGLE_API_TOKEN at config
	// load, so env wins over any file value.
	if cfg.APIName == "" || cfg.APIToken == "" {
		return "", fmt.Errorf("wigle_upload: missing credentials — set WIGLE_API_NAME and WIGLE_API_TOKEN " +
			"(or wigle.api_name / wigle.api_token in config)")
	}

	csv := str(p, "csv")
	if strings.TrimSpace(csv) == "" {
		return "", fmt.Errorf("wigle_upload: csv is required and must be non-empty (a WigleWifi-1.4 CSV)")
	}
	if len(csv) > wigle.MaxUploadBytes {
		return "", fmt.Errorf("wigle_upload: csv too large (%d bytes, max %d)", len(csv), wigle.MaxUploadBytes)
	}
	donate := boolOr(p, "donate", false)

	filename := str(p, "filename")
	if filename == "" {
		filename = "promptzero-wardrive.csv"
	}
	// The filename is only a label WiGLE records; reduce it to a base name so a
	// value like "../x" can't be interpreted as a path anywhere downstream.
	filename = filepath.Base(filename)

	client := wigle.NewClient(cfg.APIName, cfg.APIToken, cfg.Endpoint)
	res, err := client.Upload(ctx, filename, []byte(csv), donate)
	if err != nil {
		return "", err
	}

	out := map[string]any{
		"success":  true,
		"donated":  donate,
		"filename": filename,
	}
	if ids := res.TransactionIDs(); len(ids) > 0 {
		out["transaction_ids"] = ids
	}
	if msg := strings.TrimSpace(res.Message); msg != "" {
		out["message"] = msg
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", fmt.Errorf("wigle_upload: marshal result: %w", err)
	}
	return string(b), nil
}
