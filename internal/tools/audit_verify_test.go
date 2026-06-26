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
