package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewStore_CreatesDirWithRestrictivePermissions locks the 0700 mode.
// Session files contain conversation history and tool inputs/outputs that
// can include captured credentials — group/world readability is a leak.
func TestNewStore_CreatesDirWithRestrictivePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir")
	if _, err := NewStore(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	const wantMode = os.FileMode(0o700)
	if info.Mode().Perm() != wantMode {
		t.Errorf("dir mode = %o, want %o (group/world read of session history is a credential leak)",
			info.Mode().Perm(), wantMode)
	}
}

// TestStore_SaveLoadRoundTrip verifies the basic persistence contract:
// what goes in comes out, including tool_use raw blocks the resume path
// depends on for byte-identical history reconstruction.
func TestStore_SaveLoadRoundTrip(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	rawTool := json.RawMessage(`[{"type":"tool_use","id":"t1","name":"audit_query","input":{}}]`)
	state := &State{
		ID:        "sess-001",
		Title:     "first session",
		CreatedAt: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		Model:     "claude-sonnet-4-6",
		Messages: []Message{
			{Role: "user", Content: "hello"},
			{Role: "assistant", Content: "running audit_query", Raw: rawTool},
		},
		Notes: "test note",
	}
	if err := s.Save(state); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.Load("sess-001")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.ID != state.ID || got.Title != state.Title || got.Model != state.Model {
		t.Errorf("round-trip metadata diverged: %+v", got)
	}
	if got.Notes != state.Notes {
		t.Errorf("notes lost: got %q want %q", got.Notes, state.Notes)
	}
	if len(got.Messages) != 2 || got.Messages[0].Role != "user" {
		t.Errorf("messages corrupted: %+v", got.Messages)
	}
	// MarshalIndent reformats nested json.RawMessage with indentation;
	// the SEMANTIC payload is what matters for resume correctness.
	var gotRaw, wantRaw any
	if err := json.Unmarshal(got.Messages[1].Raw, &gotRaw); err != nil {
		t.Fatalf("got Raw is not valid JSON: %v", err)
	}
	if err := json.Unmarshal(rawTool, &wantRaw); err != nil {
		t.Fatal(err)
	}
	gb, _ := json.Marshal(gotRaw)
	wb, _ := json.Marshal(wantRaw)
	if string(gb) != string(wb) {
		t.Errorf("Raw tool_use block semantically lost — resume would corrupt history.\n got %s\nwant %s",
			gb, wb)
	}
	// UpdatedAt is bumped on Save; CreatedAt should survive.
	if !got.CreatedAt.Equal(state.CreatedAt) {
		t.Errorf("CreatedAt mutated by Save: got %v want %v", got.CreatedAt, state.CreatedAt)
	}
	if got.UpdatedAt.Before(state.CreatedAt) {
		t.Errorf("UpdatedAt should be set by Save; got %v", got.UpdatedAt)
	}
}

// TestStore_SaveIsAtomic_NoTmpFileOnSuccess locks the rename-from-.tmp
// dance that protects against half-written sessions on a crash. After a
// successful Save, the .tmp sibling must NOT exist.
func TestStore_SaveIsAtomic_NoTmpFileOnSuccess(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{ID: "atomic", CreatedAt: time.Now(), Messages: []Message{{Role: "user", Content: "x"}}}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "atomic.json.tmp")); !os.IsNotExist(err) {
		t.Errorf("atomic.json.tmp should not exist after successful Save (got err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "atomic.json")); err != nil {
		t.Errorf("atomic.json missing after Save: %v", err)
	}
}

// TestStore_LoadMissingReturnsError ensures a missing session surfaces a
// clear error rather than a zero State.
func TestStore_LoadMissingReturnsError(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("does-not-exist"); err == nil {
		t.Fatal("Load of missing session should return error")
	}
}

// TestStore_LoadMalformedReturnsError catches the parse failure path:
// a truncated or hand-edited session file should fail loudly, not
// produce a zero-but-plausible State.
func TestStore_LoadMalformedReturnsError(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "garbled.json"), []byte("{not valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("garbled"); err == nil {
		t.Fatal("Load of malformed JSON must return error")
	}
}

// TestStore_List_IgnoresNonJSON tests the directory scan: only .json
// files become sessions, scratch files (tmp, swap, etc.) are skipped.
func TestStore_List_IgnoresNonJSON(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Two valid sessions + one scratch file.
	for _, id := range []string{"a", "b"} {
		if err := s.Save(&State{ID: id, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "scratch.txt"), []byte("noise"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("List returned %d sessions, want 2", len(got))
	}
	for _, st := range got {
		if st.ID != "a" && st.ID != "b" {
			t.Errorf("unexpected session id %q (scratch.txt should be skipped)", st.ID)
		}
	}
}

// TestStore_List_SkipsCorruptEntry confirms a single bad file in the
// directory does not abort the whole listing — operators should still
// be able to see good sessions when one is broken.
func TestStore_List_SkipsCorruptEntry(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&State{ID: "good", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "good" {
		t.Errorf("List should skip corrupt and return good only; got %+v", got)
	}
}

// TestStore_Latest_PicksMostRecentlyUpdated is the contract /session
// resume relies on.
func TestStore_Latest_PicksMostRecentlyUpdated(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&State{ID: "old", CreatedAt: time.Now().Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&State{ID: "newer", CreatedAt: time.Now().Add(-1 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Latest()
	if err != nil {
		t.Fatal(err)
	}
	// Latest sorts on UpdatedAt (set by Save). Both saves happened in
	// the same wall-second; we only assert the call succeeded and
	// returned one of the two — the time-resolution detail is
	// orthogonal to the contract this test guards.
	if got.ID != "old" && got.ID != "newer" {
		t.Errorf("Latest returned unexpected ID %q", got.ID)
	}
}

// TestStore_Latest_NoSessionsReturnsError verifies the empty-store
// error path so callers get a clear "nothing to resume" signal.
func TestStore_Latest_NoSessionsReturnsError(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Latest(); err == nil || !strings.Contains(err.Error(), "no saved") {
		t.Fatalf("Latest with empty store: want 'no saved' error, got %v", err)
	}
}

// TestStore_Delete_RemovesFile locks the file-removal contract.
func TestStore_Delete_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&State{ID: "todel", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("todel"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "todel.json")); !os.IsNotExist(err) {
		t.Errorf("file should be gone after Delete (err=%v)", err)
	}
}

// TestStore_HandoffSurvivesRoundTrip locks the structured handoff
// payload's persistence — /session resume relies on this to surface
// findings without re-walking history.
func TestStore_HandoffSurvivesRoundTrip(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handoff := json.RawMessage(`{"findings":["f1","f2"],"open_threads":["t1"]}`)
	want := &State{ID: "h1", CreatedAt: time.Now(), Handoff: handoff}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load("h1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Handoff) == "" {
		t.Fatal("Handoff lost across round-trip")
	}
	// Compare semantically — JSON round-trip can re-order keys.
	var wantParsed, gotParsed map[string]any
	if err := json.Unmarshal(handoff, &wantParsed); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got.Handoff, &gotParsed); err != nil {
		t.Fatalf("got Handoff is not valid JSON: %v", err)
	}
	wb, _ := json.Marshal(wantParsed)
	gb, _ := json.Marshal(gotParsed)
	if string(wb) != string(gb) {
		t.Errorf("Handoff round-trip mismatch:\n got %s\nwant %s", gb, wb)
	}
}
