package persona

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

func TestRegistryBuiltins(t *testing.T) {
	r := NewRegistry()
	for _, want := range []string{"default", "rf-recon", "badge-cloner", "hw-recon", "physical-pentest", "defender"} {
		p, ok := r.Get(want)
		if !ok {
			t.Errorf("missing built-in persona %q", want)
			continue
		}
		if p.Name != want {
			t.Errorf("persona %q: Name=%q", want, p.Name)
		}
		if p.SystemPrompt == "" {
			t.Errorf("persona %q: empty SystemPrompt", want)
		}
	}
	names := r.Names()
	if len(names) < 6 {
		t.Errorf("Names() returned %d entries, want >=6", len(names))
	}
}

func TestFilterToolsEmptyAllowlist(t *testing.T) {
	all := []anthropic.ToolUnionParam{mockTool("a"), mockTool("b")}
	got := FilterTools(all, nil)
	if len(got) != 2 {
		t.Fatalf("empty allowlist should pass through, got %d tools", len(got))
	}
}

func TestFilterToolsRestricts(t *testing.T) {
	all := []anthropic.ToolUnionParam{mockTool("subghz_receive"), mockTool("nfc_detect"), mockTool("rfid_read")}
	got := FilterTools(all, []string{"subghz_receive", "rfid_read"})
	if len(got) != 2 {
		t.Fatalf("want 2 tools, got %d", len(got))
	}
	names := map[string]bool{}
	for _, t := range got {
		names[t.OfTool.Name] = true
	}
	if !names["subghz_receive"] || !names["rfid_read"] {
		t.Errorf("filtered set missing expected tools: %v", names)
	}
	if names["nfc_detect"] {
		t.Errorf("filtered set should not contain nfc_detect")
	}
}

func TestFilterToolsSkipsUnknown(t *testing.T) {
	all := []anthropic.ToolUnionParam{mockTool("subghz_receive")}
	got := FilterTools(all, []string{"nonexistent_tool", "subghz_receive"})
	if len(got) != 1 || got[0].OfTool.Name != "subghz_receive" {
		t.Fatalf("allowlist with unknown entries should keep known ones: %+v", got)
	}
}

func TestRegistryLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	yaml := `name: ops
description: testing persona
system_prompt: |
  You are in OPS mode.
tools:
  - storage_list
  - audit_query
default_risk_threshold: medium
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := NewRegistry()
	if err := r.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, ok := r.Get("ops")
	if !ok {
		t.Fatalf("custom persona not registered")
	}
	if p.Description != "testing persona" {
		t.Errorf("description = %q", p.Description)
	}
	if len(p.Tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(p.Tools))
	}
	if p.DefaultRiskThreshold != "medium" {
		t.Errorf("DefaultRiskThreshold = %q", p.DefaultRiskThreshold)
	}
}

func TestRegistryLoadDirMissing(t *testing.T) {
	r := NewRegistry()
	if err := r.LoadDir(filepath.Join(t.TempDir(), "does-not-exist")); err != nil {
		t.Fatalf("LoadDir on missing dir should be nil, got %v", err)
	}
}

func TestRegistryLoadDirMergesAll(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"one.yaml": "name: one\nsystem_prompt: one\n",
		"two.yml":  "name: two\nsystem_prompt: two\n",
		"skip.txt": "ignored",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	r := NewRegistry()
	if err := r.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if _, ok := r.Get("one"); !ok {
		t.Errorf("one.yaml not loaded")
	}
	if _, ok := r.Get("two"); !ok {
		t.Errorf("two.yml not loaded")
	}
}

func TestRegistryLoadMissingName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("description: no name\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := NewRegistry()
	if err := r.Load(path); err == nil {
		t.Errorf("expected error for nameless persona")
	}
}

func mockTool(name string) anthropic.ToolUnionParam {
	return anthropic.ToolUnionParam{
		OfTool: &anthropic.ToolParam{Name: name},
	}
}
