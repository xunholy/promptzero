package persona

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

// TestRegistryLoad_ParsesVersionField pins that the Version field
// (roadmap P3-31) round-trips through YAML for downstream audit.Entry
// recording. Empty version stays empty (the default for unversioned
// personas).
func TestRegistryLoad_ParsesVersionField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "versioned.yaml")
	yaml := `name: opslab
description: test
version: 2026-05-10
system_prompt: |
  hello world
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	if err := r.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, ok := r.Get("opslab")
	if !ok {
		t.Fatalf("not registered")
	}
	if p.Version != "2026-05-10" {
		t.Errorf("Version = %q, want %q", p.Version, "2026-05-10")
	}
}

func TestRegistryLoad_EmptyVersionWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unversioned.yaml")
	yaml := `name: noversion
description: test
system_prompt: hi
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	p, _ := r.Get("noversion")
	if p.Version != "" {
		t.Errorf("Version = %q, want empty", p.Version)
	}
}

// TestRegistryLoad_ParsesConsensusList pins the P3-33 persona-YAML
// consensus list round-trips into the runtime struct.
func TestRegistryLoad_ParsesConsensusList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ensemble.yaml")
	yaml := `name: ensemble
description: P3-33 consensus
system_prompt: hi
consensus:
  - claude-haiku-4-5
  - claude-sonnet-4-6
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	if err := r.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, ok := r.Get("ensemble")
	if !ok {
		t.Fatalf("not registered")
	}
	if len(p.Consensus) != 2 {
		t.Fatalf("Consensus = %v, want 2 entries", p.Consensus)
	}
	if p.Consensus[0] != "claude-haiku-4-5" || p.Consensus[1] != "claude-sonnet-4-6" {
		t.Errorf("Consensus members = %v", p.Consensus)
	}
}

func TestRegistryLoad_ConsensusAbsentStaysNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-consensus.yaml")
	yaml := `name: nc
description: no consensus configured
system_prompt: hi
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	p, _ := r.Get("nc")
	if len(p.Consensus) != 0 {
		t.Errorf("Consensus = %v, want empty", p.Consensus)
	}
}

// TestRegistryLoad_ParsesConfidenceMap pins the P3-29 persona-YAML
// thresholds round-trip into the runtime struct. Two keys are
// expected (`vision`, `router`), but the parser is tolerant of any
// string key — operators may add forks.
func TestRegistryLoad_ParsesConfidenceMap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tuned.yaml")
	yaml := `name: tuned
description: P3-29 thresholds
system_prompt: hi
confidence:
  vision: 0.7
  router: 0.4
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	if err := r.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, ok := r.Get("tuned")
	if !ok {
		t.Fatalf("not registered")
	}
	if got := p.Confidence["vision"]; got != 0.7 {
		t.Errorf("vision threshold = %v, want 0.7", got)
	}
	if got := p.Confidence["router"]; got != 0.4 {
		t.Errorf("router threshold = %v, want 0.4", got)
	}
}

func TestRegistryLoad_ConfidenceAbsentMapStaysNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noconf.yaml")
	yaml := `name: nc
description: no confidence map
system_prompt: hi
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	p, _ := r.Get("nc")
	if len(p.Confidence) != 0 {
		t.Errorf("Confidence = %v, want empty/nil", p.Confidence)
	}
}

func TestRegistryLoadModelsBlock(t *testing.T) {
	// Exercise the optional models map: classify on Haiku, plan on
	// Sonnet, exploit on Opus. Required by the roadmap P0-02 cost-tier
	// routing flow — a persona author should be able to spell this out
	// in YAML and have the agent consume it unchanged.
	dir := t.TempDir()
	path := filepath.Join(dir, "tiered.yaml")
	yaml := `name: tiered-demo
description: cost-tier per-call model selection
system_prompt: You are a tiered persona.
models:
  classify: claude-haiku-4-5
  plan:     claude-sonnet-4-6
  exploit:  claude-opus-4-7
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := NewRegistry()
	if err := r.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, ok := r.Get("tiered-demo")
	if !ok {
		t.Fatalf("persona not registered")
	}
	if p.Models == nil {
		t.Fatalf("Models map is nil; yaml did not decode")
	}
	want := map[string]string{
		"classify": "claude-haiku-4-5",
		"plan":     "claude-sonnet-4-6",
		"exploit":  "claude-opus-4-7",
	}
	for k, v := range want {
		if got := p.Models[k]; got != v {
			t.Errorf("Models[%q] = %q, want %q", k, got, v)
		}
	}
}

func TestRegistryLoadWithoutModelsIsBackwardsCompatible(t *testing.T) {
	// Personas that predate the Models field must still load cleanly
	// with Models left as a nil map. The YAML here mirrors the original
	// persona schema.
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	yaml := `name: legacy
description: pre-P0-02 persona
system_prompt: Legacy.
tools:
  - audit_query
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := NewRegistry()
	if err := r.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, _ := r.Get("legacy")
	if len(p.Models) != 0 {
		t.Fatalf("Models map should be nil/empty on legacy persona, got %+v", p.Models)
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

// TestRegistryLoadDirSkipsBadFile confirms that a single malformed
// persona doesn't cost the operator their other valid personas.
// Previously LoadDir bailed on the first error, so one syntax error
// in ~/.promptzero/personas/foo.yaml would silently disable every
// other file in the directory.
func TestRegistryLoadDirSkipsBadFile(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"good.yaml":     "name: good\nsystem_prompt: ok\n",
		"broken.yaml":   "name: broken\nsystem_prompt: [unclosed\n",
		"nameless.yaml": "description: no name field\n",
		"alsogood.yaml": "name: alsogood\nsystem_prompt: ok\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	r := NewRegistry()
	if err := r.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir should not return an error when individual files fail: %v", err)
	}
	if _, ok := r.Get("good"); !ok {
		t.Errorf("good.yaml not loaded — bad sibling should not block")
	}
	if _, ok := r.Get("alsogood"); !ok {
		t.Errorf("alsogood.yaml not loaded — bad sibling should not block")
	}
	if _, ok := r.Get("broken"); ok {
		t.Errorf("broken.yaml should not register a persona")
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

// TestRegistry_ConcurrentReadWrite locks the goroutine-safety
// guarantee. Run under -race; without the RWMutex this would trip
// the race detector on a Get/Names while Load is running. Production
// today only writes at startup but the mutex keeps a future
// hot-reload feature safe.
func TestRegistry_ConcurrentReadWrite(t *testing.T) {
	r := NewRegistry()
	dir := t.TempDir()
	tmpYAML := filepath.Join(dir, "concurrent.yaml")
	if err := os.WriteFile(tmpYAML, []byte("name: hot-reload-test\nsystem_prompt: x\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	done := make(chan struct{})
	// One reader, one writer racing for ~50ms.
	go func() {
		deadline := time.Now().Add(50 * time.Millisecond)
		for time.Now().Before(deadline) {
			_ = r.Names()
			_, _ = r.Get("default")
		}
		close(done)
	}()
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = r.Load(tmpYAML)
	}
	<-done
}

func TestIsUnrestricted(t *testing.T) {
	tests := []struct {
		name  string
		tools []string
		want  bool
	}{
		{"nil tools", nil, true},
		{"empty tools slice", []string{}, true},
		{"single tool", []string{"nfc_detect"}, false},
		{"multiple tools", []string{"nfc_detect", "rfid_read", "subghz_receive"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Persona{Name: "test", Tools: tt.tools}
			if got := p.IsUnrestricted(); got != tt.want {
				t.Errorf("IsUnrestricted() = %v, want %v (tools=%v)", got, tt.want, tt.tools)
			}
		})
	}
}

func mockTool(name string) anthropic.ToolUnionParam {
	return anthropic.ToolUnionParam{
		OfTool: &anthropic.ToolParam{Name: name},
	}
}

// TestUserDir pins the documented "~/.promptzero/personas" default
// path. Trivial wrapper but every callsite that loads operator-
// supplied persona YAML resolves through here, so a regression
// (e.g. accidentally swapping to .config/promptzero/) would silently
// stop picking up the operator's personas.
func TestUserDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("os.UserHomeDir unavailable: %v", err)
	}
	got, err := UserDir()
	if err != nil {
		t.Fatalf("UserDir: %v", err)
	}
	want := filepath.Join(home, ".promptzero", "personas")
	if got != want {
		t.Errorf("UserDir() = %q; want %q", got, want)
	}
}
