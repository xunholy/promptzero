// crack_triage.go — host-side unified crack-triage front-end, delegating to
// internal/cracktriage (which routes to kdbx / ziptriage / pdftriage).
//
// Wrap-vs-native: native orchestration — detects the encrypted artifact by its
// file magic and dispatches to the matching in-tree crack-triage decoder; no new
// go.mod dep. The crack-triage analogue of secret_identify / hash_identify: one
// entry point for "what is this encrypted file, and which hashcat mode cracks
// it?". Offline; no network or device. Reuses decodeBinaryInput (kdbx_decode.go).

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/cracktriage"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(crackTriageSpec)
}

var crackTriageSpec = Spec{
	Name: "crack_triage",
	Description: "Triage **any encrypted loot file** for cracking — the unified front-end over the crack-triage " +
		"decoders. Hand it a file of unknown type and it **detects the artifact by its magic bytes** and " +
		"routes to the matching in-tree decoder — **KeePass `.kdbx`** (→ `kdbx_decode`), **encrypted ZIP** (→ " +
		"`zip_crack_triage`), or **encrypted PDF** (→ `pdf_crack_triage`) — returning the artifact type, the " +
		"**hashcat mode** that cracks it, and the full per-format detail (cipher, KDF / key-derivation cost, " +
		"AES strength, …). This is the crack-triage analogue of `secret_identify` / `hash_identify`: a single " +
		"answer to *\"what is this, and how do I crack it?\"* without the operator pre-classifying the file.\n\n" +
		"Provide the file **base64-encoded** (or hex). **No confidently-wrong output**: detection is by the " +
		"unambiguous file-format magic, so a file is **never mis-routed**; a file that is not a recognised " +
		"encrypted-artifact type is **rejected**; and each routed decoder keeps its own *parameters-only* " +
		"guarantee — nothing is cracked, decrypted, or emitted as a `john`/`hashcat` hash. A `hashcat_mode` of " +
		"`0` means the file is not password-protected (nothing to crack). No network, no device, transmits " +
		"nothing — Low risk. Pairs with `hash_identify` and the hashcat tooling.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential forensics / crack triage). Wrap-vs-native: native " +
		"orchestration over internal/kdbx + internal/ziptriage + internal/pdftriage, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"The file contents, base64-encoded (or hex)."}
		},
		"required":["data"]
	}`),
	Required:  []string{"data"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   crackTriageHandler,
}

func crackTriageHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "data"))
	if in == "" {
		return "", fmt.Errorf("crack_triage: 'data' is required")
	}
	raw, err := decodeBinaryInput(in)
	if err != nil {
		return "", fmt.Errorf("crack_triage: %w", err)
	}
	res, err := cracktriage.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("crack_triage: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
