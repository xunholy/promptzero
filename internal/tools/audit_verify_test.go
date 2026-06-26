// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/xunholy/promptzero/internal/audit"
)

func TestAuditVerifyTool(t *testing.T) {
	spec, ok := Get("audit_verify")
	if !ok {
		t.Fatal("audit_verify not registered")
	}

	// Nil audit log → friendly message, not a panic.
	if out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{}); err != nil || out == "" {
		t.Errorf("nil audit: out=%q err=%v", out, err)
	}

	logPath := filepath.Join(t.TempDir(), "audit.db")
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer log.Close()
	for i := 0; i < 3; i++ {
		log.Record("nfc_detect", map[string]int{"i": i}, "ok", "low", audit.LevelAction, 0, true)
	}

	out, err := spec.Handler(context.Background(), &Deps{Audit: log}, map[string]any{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var res struct {
		Valid      bool `json:"valid"`
		HashedRows int  `json:"hashed_rows"`
	}
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil {
		t.Fatalf("unmarshal: %v\n%s", jerr, out)
	}
	if !res.Valid || res.HashedRows != 3 {
		t.Errorf("intact chain expected, got %+v", res)
	}
}

func TestAuditVerifyTool_Anchor(t *testing.T) {
	spec, _ := Get("audit_verify")
	logPath := filepath.Join(t.TempDir(), "audit.db")
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer log.Close()
	for i := 0; i < 3; i++ {
		log.Record("nfc_detect", map[string]int{"i": i}, "ok", "low", audit.LevelAction, 0, true)
	}

	// First verify yields the anchor (head_hash + hashed_rows).
	out, err := spec.Handler(context.Background(), &Deps{Audit: log}, map[string]any{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var first struct {
		HeadHash   string `json:"head_hash"`
		HashedRows int    `json:"hashed_rows"`
	}
	if jerr := json.Unmarshal([]byte(out), &first); jerr != nil {
		t.Fatalf("unmarshal: %v", jerr)
	}

	// Re-verify against the saved anchor → anchor_valid true.
	out2, err := spec.Handler(context.Background(), &Deps{Audit: log}, map[string]any{
		"expect_head_hash":   first.HeadHash,
		"expect_hashed_rows": first.HashedRows,
	})
	if err != nil {
		t.Fatalf("anchored verify: %v", err)
	}
	var r struct {
		AnchorChecked bool `json:"anchor_checked"`
		AnchorValid   bool `json:"anchor_valid"`
	}
	if jerr := json.Unmarshal([]byte(out2), &r); jerr != nil {
		t.Fatalf("unmarshal: %v", jerr)
	}
	if !r.AnchorChecked || !r.AnchorValid {
		t.Errorf("anchor should validate: %+v\n%s", r, out2)
	}

	// A wrong anchor hash → anchor_valid false. Use a fresh struct so an
	// omitted field can't carry a stale value from the prior unmarshal.
	out3, _ := spec.Handler(context.Background(), &Deps{Audit: log}, map[string]any{
		"expect_head_hash":   "deadbeef",
		"expect_hashed_rows": first.HashedRows,
	})
	var r3 struct {
		AnchorChecked bool `json:"anchor_checked"`
		AnchorValid   bool `json:"anchor_valid"`
	}
	if err := json.Unmarshal([]byte(out3), &r3); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !r3.AnchorChecked || r3.AnchorValid {
		t.Errorf("wrong anchor hash must fail: %s", out3)
	}

	// One anchor param without the other → usage error.
	if _, err := spec.Handler(context.Background(), &Deps{Audit: log}, map[string]any{
		"expect_head_hash": first.HeadHash,
	}); err == nil {
		t.Error("half-anchor (hash only) should error")
	}
}
