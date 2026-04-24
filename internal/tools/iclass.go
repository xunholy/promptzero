// Package tools — iclass_loclass_recover Spec (v0.5 task #8).
//
// Registers the iclass_loclass_recover Spec which invokes the loclass offline
// key-recovery attack against an HID iCLASS Elite / High Security reader.
// The attack is purely CPU-side (no Flipper hardware involved). The algorithm
// is derived from García, de Koning Gans, Verdult, Meriac — "Dismantling
// iClass and iClass Elite", ESORICS 2012. License posture: clean-reimpl.
//
// See docs/refactor/iclass-loclass-algorithm.md for full design context.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xunholy/promptzero/internal/iclass"
	"github.com/xunholy/promptzero/internal/risk"
)

//nolint:gochecknoinits
func init() {
	Register(iclassLoclassRecoverSpec)
}

var iclassLoclassRecoverSpec = Spec{
	Name: "iclass_loclass_recover",
	Description: "Recover an HID iCLASS Elite reader's custom master key (Kcus) from a set " +
		"of captured authenticated-read exchanges. Offline brute-force; no hardware required. " +
		"Requires captures whose CSN Hash1 outputs collectively cover all keytable indices 0–15 " +
		"(≥8 Swende-optimal captures or more arbitrary captures). " +
		"Input file format: proxmark3 binary — N × 24 bytes (CSN[8] ‖ CC[8] ‖ NR[4] ‖ MAC[4]). " +
		"Returns the 8-byte Kcus as a hex string. Runtime: seconds to minutes depending on CSN selection.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"captures":{"type":"string",
				"description":"Path to a binary loclass capture file in proxmark3 format (N×24 bytes: CSN[8]|CC[8]|NR[4]|MAC[4] per capture)"},
			"format":{"type":"string","enum":["pm3","raw"],
				"description":"Capture file format: pm3 = proxmark3 binary (default); raw = concatenated hex bytes"},
			"timeout_ms":{"type":"integer","minimum":1000,
				"description":"Wall-clock ceiling in ms for the brute-force phase (default 60000)"}
		},
		"required":["captures"]
	}`),
	Required:  []string{"captures"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   iclassLoclassRecoverHandler,
}

// loclassResult is the JSON output of iclass_loclass_recover.
type loclassResult struct {
	Key        string `json:"key"`         // 8-byte Kcus as uppercase hex
	Format     string `json:"format"`      // always "iclass-elite-master"
	DurationMS int64  `json:"duration_ms"` // wall-clock time of the brute-force
}

func iclassLoclassRecoverHandler(ctx context.Context, _ *Deps, p map[string]any) (string, error) {
	capturesPath := str(p, "captures")
	if capturesPath == "" {
		return "", fmt.Errorf("iclass_loclass_recover: 'captures' is required")
	}

	timeoutMS := intOr(p, "timeout_ms", 60000)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()

	caps, err := iclass.ParseCapturesFromFile(capturesPath)
	if err != nil {
		return "", fmt.Errorf("iclass_loclass_recover: parse captures: %w", err)
	}
	if len(caps) == 0 {
		return "", fmt.Errorf("iclass_loclass_recover: capture file is empty")
	}

	start := time.Now()
	_, hexKey, err := iclass.Recover(ctx, caps)
	if err != nil {
		return "", fmt.Errorf("iclass_loclass_recover: recovery failed: %w", err)
	}

	res := loclassResult{
		Key:        hexKey,
		Format:     "iclass-elite-master",
		DurationMS: time.Since(start).Milliseconds(),
	}
	b, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
