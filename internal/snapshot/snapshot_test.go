package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManager_StoreAndList(t *testing.T) {
	m := NewManager(t.TempDir())

	// Store three snapshots under the same session.
	for i, content := range []string{"one", "two", "three"} {
		if _, err := m.Store("sess1", "/ext/subghz/file.sub", []byte(content)); err != nil {
			t.Fatalf("Store[%d]: %v", i, err)
		}
		// A small sleep guarantees the IDs differ even on fast hardware
		// (timestamp resolution is 1 s). We only need distinct IDs once
		// across this test.
		if i < 2 {
			time.Sleep(1100 * time.Millisecond)
		}
	}
	entries, err := m.List("sess1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("List returned %d entries, want 3", len(entries))
	}
	// Newest first — each ID's timestamp prefix must monotonically decrease.
	if entries[0].ID <= entries[1].ID || entries[1].ID <= entries[2].ID {
		t.Fatalf("entries not sorted newest-first: %+v", entries)
	}
	// Metadata is populated.
	for _, e := range entries {
		if e.OriginalPath != "/ext/subghz/file.sub" {
			t.Errorf("OriginalPath = %q", e.OriginalPath)
		}
		if e.SizeBytes == 0 {
			t.Errorf("SizeBytes = 0 for entry %s", e.ID)
		}
		if len(e.SHA256) != 64 {
			t.Errorf("SHA256 hex length = %d, want 64", len(e.SHA256))
		}
	}
}

func TestManager_Restore_RoundTrip(t *testing.T) {
	m := NewManager(t.TempDir())
	content := []byte("important config bytes")
	entry, err := m.Store("sess1", "/ext/apps_data/config.cfg", content)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, body, err := m.Restore("sess1", entry.ID)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if string(body) != string(content) {
		t.Errorf("content mismatch: %q vs %q", body, content)
	}
	if got.OriginalPath != entry.OriginalPath {
		t.Errorf("OriginalPath mismatch: %q vs %q", got.OriginalPath, entry.OriginalPath)
	}
	if got.SHA256 != entry.SHA256 {
		t.Errorf("SHA256 mismatch: %q vs %q", got.SHA256, entry.SHA256)
	}
}

func TestManager_List_MissingSessionIsEmpty(t *testing.T) {
	m := NewManager(t.TempDir())
	entries, err := m.List("never-existed")
	if err != nil {
		t.Fatalf("List on missing session should not error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries should be empty, got %+v", entries)
	}
}

func TestManager_Purge(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root)
	_, err := m.Store("sess-purge", "/ext/a.sub", []byte("x"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := m.Purge("sess-purge"); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	// Session dir must be gone.
	dir := filepath.Join(root, "sess-purge")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("session dir should be removed: %v", err)
	}
	// Re-Purge is a no-op.
	if err := m.Purge("sess-purge"); err != nil {
		t.Fatalf("re-Purge should be idempotent: %v", err)
	}
}

func TestManager_Rotate_KeepsNewest(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root)
	const session = "sess-rotate"

	// Seed 5 snapshots. Store uses a timestamp + sha256 prefix in the
	// ID; tiny sleeps ensure unique timestamps so sort-order is
	// well-defined.
	for i := 0; i < 5; i++ {
		if _, err := m.Store(session, "/ext/file.sub", []byte{byte(i)}); err != nil {
			t.Fatalf("Store %d: %v", i, err)
		}
		time.Sleep(1100 * time.Millisecond)
	}

	deleted, err := m.Rotate(session, 2)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if deleted != 3 {
		t.Errorf("deleted = %d, want 3", deleted)
	}
	remaining, err := m.List(session)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining) != 2 {
		t.Errorf("remaining = %d, want 2 after rotation", len(remaining))
	}
}

// TestManager_Rotate_RemovesBothFiles locks the cleanup invariant —
// every removed snapshot drops both its .json meta and its .bak data
// file together. List() only counts .json so a regression where one
// file was left behind would not show up in the previous test.
func TestManager_Rotate_RemovesBothFiles(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root)
	const session = "sess-rotate-pairs"

	for i := 0; i < 4; i++ {
		if _, err := m.Store(session, "/ext/file.sub", []byte{byte(i)}); err != nil {
			t.Fatalf("Store %d: %v", i, err)
		}
		time.Sleep(1100 * time.Millisecond)
	}

	if _, err := m.Rotate(session, 1); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	dir := filepath.Join(root, session)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var json, bak int
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".json"):
			json++
		case strings.HasSuffix(e.Name(), ".bak"):
			bak++
		default:
			t.Errorf("unexpected file in session dir: %s", e.Name())
		}
	}
	if json != 1 || bak != 1 {
		t.Errorf("after Rotate(keep=1) want 1 .json + 1 .bak, got %d/%d (%d total entries)",
			json, bak, len(entries))
	}
}

func TestManager_Rotate_NoOpBelowKeep(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root)
	const session = "sess-rotate-noop"

	for i := 0; i < 2; i++ {
		if _, err := m.Store(session, "/ext/x.sub", []byte{byte(i)}); err != nil {
			t.Fatalf("Store %d: %v", i, err)
		}
		time.Sleep(1100 * time.Millisecond)
	}
	deleted, err := m.Rotate(session, 5)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 (fewer entries than keep cap)", deleted)
	}
}

func TestManager_Rotate_UsesDefaultRetention(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root)
	// Session dir that doesn't exist yet must no-op.
	deleted, err := m.Rotate("missing-sess", 0)
	if err != nil {
		t.Errorf("missing session should not error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}
}

func TestManager_Store_AtomicRenameLeavesNoTmp(t *testing.T) {
	// After a successful Store there should be no stray .tmp files
	// (writeAtomic must rename them into place).
	root := t.TempDir()
	m := NewManager(root)
	if _, err := m.Store("sess", "/ext/a", []byte("x")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	files, _ := os.ReadDir(filepath.Join(root, "sess"))
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".tmp") {
			t.Errorf("orphan tmp file: %s", f.Name())
		}
	}
}

func TestManager_Store_RequiresSessionAndPath(t *testing.T) {
	m := NewManager(t.TempDir())
	if _, err := m.Store("", "/ext/a", []byte("x")); err == nil {
		t.Error("empty session should error")
	}
	if _, err := m.Store("sess", "", []byte("x")); err == nil {
		t.Error("empty path should error")
	}
}

func TestManager_Restore_UnknownIDErrors(t *testing.T) {
	m := NewManager(t.TempDir())
	if _, _, err := m.Restore("sess", "nonexistent"); err == nil {
		t.Error("unknown id should error")
	}
}

// TestManager_RejectsTraversalSnapshotID closes the second-leg
// filepath.Join. Even if sessionID is sanitised, a malicious id
// like "../foo" passed to Restore would resolve to
// <root>/<session>/../foo.json — escaping the session dir.
func TestManager_RejectsTraversalSnapshotID(t *testing.T) {
	m := NewManager(t.TempDir())
	bad := []string{
		"../foo",
		"../../etc/passwd",
		"foo/bar",
		".hidden",
		"name with sp",
		"",
	}
	for _, id := range bad {
		t.Run(id, func(t *testing.T) {
			if _, _, err := m.Restore("validsession", id); err == nil {
				t.Errorf("Restore(id=%q) should error", id)
			}
		})
	}
}

// TestManager_RejectsTraversalSessionIDs locks the path-traversal
// guard. Without this check Store / List / Restore / Purge with an
// id like "../etc" would resolve outside the snapshot root because
// filepath.Join is permissive — the operator's session-store-level
// validation isn't reachable for callers that bypass the agent.
func TestManager_RejectsTraversalSessionIDs(t *testing.T) {
	m := NewManager(t.TempDir())
	bad := []string{
		"../foo",
		"../../etc",
		"foo/bar",
		"foo\\bar",
		".hidden",
		"name with sp",
		"",
		"name|pipe",
	}
	for _, id := range bad {
		t.Run(id, func(t *testing.T) {
			if _, err := m.Store(id, "/ext/x.sub", []byte("x")); err == nil {
				t.Errorf("Store(id=%q) should error", id)
			}
			if _, err := m.List(id); err == nil {
				t.Errorf("List(id=%q) should error", id)
			}
			if _, _, err := m.Restore(id, "any"); err == nil {
				t.Errorf("Restore(id=%q) should error", id)
			}
			if err := m.Purge(id); err == nil {
				t.Errorf("Purge(id=%q) should error", id)
			}
		})
	}
}

func TestDefaultRoot_EndsInSnapshots(t *testing.T) {
	root, err := DefaultRoot()
	if err != nil {
		t.Fatalf("DefaultRoot: %v", err)
	}
	if !strings.HasSuffix(root, filepath.Join(".promptzero", "snapshots")) {
		t.Fatalf("DefaultRoot = %q, want ~/.promptzero/snapshots", root)
	}
}
