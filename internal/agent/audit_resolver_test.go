package agent

import (
	"path/filepath"
	"testing"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/persona"
)

// TestSetAuditLog_WiresPersonaContextResolver pins the P3-31 wiring:
// after Agent.SetAuditLog runs, the audit log's PersonaContextResolver
// returns the active persona's Version and a non-empty PromptHash that
// matches what BuildSystemPrompt would have hashed for the current
// (no-marauder) tool set.
func TestSetAuditLog_WiresPersonaContextResolver(t *testing.T) {
	a := &Agent{}
	a.SetPersona(&persona.Persona{
		Name:    "lab",
		Version: "1.2.3",
	})

	path := filepath.Join(t.TempDir(), "audit.db")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer log.Close()

	a.SetAuditLog(log)

	var captured audit.Entry
	log.AddObserver(func(e audit.Entry) { captured = e })

	log.Record("any_tool", nil, "ok", "low", audit.LevelInfo, 0, true)

	if captured.PersonaVersion != "1.2.3" {
		t.Errorf("PersonaVersion = %q, want 1.2.3", captured.PersonaVersion)
	}
	if len(captured.PromptHash) != 64 {
		t.Errorf("PromptHash length = %d, want 64", len(captured.PromptHash))
	}

	// Hash must equal the ground-truth from SystemPromptHash for the
	// matching args (a.marauder == nil → hasWiFi false; workflows true).
	wantHash := SystemPromptHash(a.personaAtomic.Load(), false, true)
	if captured.PromptHash != wantHash {
		t.Errorf("PromptHash = %q, want %q", captured.PromptHash, wantHash)
	}
}

// TestSetAuditLog_NilLogIsNoOp confirms the safety contract: passing a
// nil log doesn't panic and doesn't try to install a resolver against
// nil.
func TestSetAuditLog_NilLogIsNoOp(t *testing.T) {
	a := &Agent{}
	a.SetAuditLog(nil) // must not panic
	if a.auditLog != nil {
		t.Errorf("auditLog set despite nil arg: %v", a.auditLog)
	}
}

// TestSetAuditLog_PersonaSwitchUpdatesNextRecord confirms a mid-session
// SetPersona changes the captured PersonaVersion on the next Record —
// the resolver is a closure over Agent.personaAtomic so updates are
// visible without re-installing.
func TestSetAuditLog_PersonaSwitchUpdatesNextRecord(t *testing.T) {
	a := &Agent{}
	a.SetPersona(&persona.Persona{
		Name:         "first",
		Version:      "v1",
		SystemPrompt: "I am persona ONE.",
	})
	log, err := audit.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer log.Close()
	a.SetAuditLog(log)

	var entries []audit.Entry
	log.AddObserver(func(e audit.Entry) { entries = append(entries, e) })

	log.Record("t1", nil, "", "low", audit.LevelInfo, 0, true)
	a.SetPersona(&persona.Persona{
		Name:         "second",
		Version:      "v2",
		SystemPrompt: "I am persona TWO with completely different framing.",
	})
	log.Record("t2", nil, "", "low", audit.LevelInfo, 0, true)

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].PersonaVersion != "v1" {
		t.Errorf("entry[0].PersonaVersion = %q, want v1", entries[0].PersonaVersion)
	}
	if entries[1].PersonaVersion != "v2" {
		t.Errorf("entry[1].PersonaVersion = %q, want v2 (post-switch)", entries[1].PersonaVersion)
	}
	if entries[0].PromptHash == entries[1].PromptHash {
		t.Errorf("PromptHash did not change after persona switch (both = %q)", entries[0].PromptHash)
	}
}
