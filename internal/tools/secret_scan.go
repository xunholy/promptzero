// secret_scan.go — host-side bulk secret scanner Spec, delegating to
// internal/secretid.Scan.
//
// Wrap-vs-native: native — extends the in-tree secret_identify suite from
// single-string classification to bulk extraction over arbitrary text, routing
// every candidate through the same in-tree decoders; stdlib regexp only, no new
// go.mod dep. The loot-triage workflow: scan a file / dump / config, not paste
// one string. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/secretid"
)

func init() { //nolint:gochecknoinits
	Register(secretScanSpec)
}

var secretScanSpec = Spec{
	Name: "secret_scan",
	Description: "Scan a **blob of text for secrets** — the bulk loot-triage entry point, the way `hash_identify` " +
		"/ `secret_identify` work on a single string but applied to a whole file. Paste a config, an `.env`, a " +
		"log, an `env` dump, a source file, or any captured text and it **extracts every candidate credential " +
		"and routes each through `secret_identify`**, reporting the type, the line it sits on, and — where the " +
		"format carries a checksum or structure — whether it **validates**. It is the in-tree analogue of a " +
		"secret scanner (trufflehog / gitleaks) built on the project's own decoders.\n\n" +
		"Extracts only **high-signal structural patterns** — PEM / OpenSSH / PGP key blocks, JWTs, AWS access " +
		"key IDs, GitHub tokens, Google API keys / OAuth tokens, and the documented vendor-token prefixes " +
		"(Slack, GitLab, Stripe, npm, OpenAI / Anthropic, SendGrid, DigitalOcean, Shopify, PyPI, …) — then " +
		"keeps a finding **only when `secret_identify` actually recognises the candidate**. **No " +
		"confidently-wrong output**: a reported finding is always a **format match**, never an entropy guess; " +
		"the **secret value is redacted** (prefix + length, never the full secret); findings carry their " +
		"`validated` status; and the result notes that absence of a finding is **not** proof a blob is clean " +
		"(only the high-signal patterns are extracted). Output is bounded with explicit `truncated` " +
		"signalling. No network, no device, transmits nothing — Low risk. Routes to the full credential " +
		"decoders (`aws_key_decode` / `github_token_decode` / `gcp_service_account_decode` / `jwt_decode` / " +
		"`pypi_token_decode` / …) for the per-secret deep decode.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential forensics — the bulk scanner over the decoder " +
		"suite). Wrap-vs-native: native — stdlib regexp extraction + the in-tree `secretid.Identify`, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"text":{"type":"string","description":"The text to scan (a config, .env, log, dump, or source blob)."}
		},
		"required":["text"]
	}`),
	Required:  []string{"text"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   secretScanHandler,
}

func secretScanHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	text := str(p, "text")
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("secret_scan: 'text' is required")
	}
	out, _ := json.MarshalIndent(secretid.Scan(text), "", "  ")
	return string(out), nil
}
