//go:build unix || windows

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenFallsBackWhenFlockContended verifies that two Log instances on
// the same primary path land on different files: the first gets the
// primary, the second falls back to <path>.<pid>. Without the flock guard
// both would write to the same sqlite WAL concurrently and corrupt rows.
func TestOpenFallsBackWhenFlockContended(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "audit.db")

	a, err := Open(primary)
	if err != nil {
		t.Fatalf("open primary: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	b, err := Open(primary)
	if err != nil {
		t.Fatalf("open contended: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if a.Path() != primary {
		t.Fatalf("primary Log should keep requested path: got %q want %q", a.Path(), primary)
	}
	if b.Path() == a.Path() {
		t.Fatalf("contended Log should have been redirected, both at %q", a.Path())
	}
	wantPrefix := fmt.Sprintf("%s.%d", primary, os.Getpid())
	if !strings.HasPrefix(b.Path(), wantPrefix) {
		t.Fatalf("fallback path should start with %q, got %q", wantPrefix, b.Path())
	}

	// Both logs must be functional — the guard must not leave the
	// fallback instance with a half-initialised db handle.
	a.Record("probe", map[string]string{"from": "a"}, "ok", "low", LevelInfo, 0, true)
	b.Record("probe", map[string]string{"from": "b"}, "ok", "low", LevelInfo, 0, true)
	if rows, err := a.Query(10); err != nil || len(rows) != 1 {
		t.Fatalf("primary Query: rows=%d err=%v", len(rows), err)
	}
	if rows, err := b.Query(10); err != nil || len(rows) != 1 {
		t.Fatalf("fallback Query: rows=%d err=%v", len(rows), err)
	}
}

// TestFlockTargetsSiblingNotDBFile pins the invariant that fixes the macOS
// SQLITE_BUSY startup failure (issue #182): the advisory lock is held on a
// ".lock" sibling, never on the sqlite database file itself. On macOS
// flock(2) rides on fcntl(2), so a lock on the db file shadows sqlite's own
// locking and CREATE TABLE fails with SQLITE_BUSY; the same shadowing is
// latent on Windows LockFileEx. The symptom can't be reproduced on Linux
// (independent lock families), so this test guards the structural property
// instead: lock path == db path + ".lock", the db file opened and worked,
// and the two are distinct files on disk.
func TestFlockTargetsSiblingNotDBFile(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "audit.db")

	a, err := Open(primary)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	// The db backing the log must be the requested path, untouched by the
	// lock indirection.
	if a.Path() != primary {
		t.Fatalf("db path should be the requested path: got %q want %q", a.Path(), primary)
	}
	// The lock handle must point at the sibling, not the db file. A lock on
	// primary itself is exactly the bug.
	if a.lockFile == nil {
		t.Fatal("expected a held lock handle")
	}
	wantLock := primary + ".lock"
	if got := a.lockFile.Name(); got != wantLock {
		t.Fatalf("flock must target the .lock sibling, got %q want %q", got, wantLock)
	}

	// The db must be genuinely initialised and writable — this is the step
	// that fails with SQLITE_BUSY when the lock shadows sqlite.
	a.Record("probe", map[string]string{"from": "a"}, "ok", "low", LevelInfo, 0, true)
	if rows, err := a.Query(10); err != nil || len(rows) != 1 {
		t.Fatalf("db should be writable after Open: rows=%d err=%v", len(rows), err)
	}

	// Both files exist and are distinct.
	if _, err := os.Stat(primary); err != nil {
		t.Fatalf("db file should exist: %v", err)
	}
	if _, err := os.Stat(wantLock); err != nil {
		t.Fatalf("lock file should exist: %v", err)
	}
}

// TestCloseReleasesFlock confirms the second opener can take the primary
// path once the first Log is closed. A missing LOCK_UN would leave the
// lock held until process exit and break the "restart-in-place" case.
func TestCloseReleasesFlock(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "audit.db")

	first, err := Open(primary)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}

	second, err := Open(primary)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	if second.Path() != primary {
		t.Fatalf("second opener should reclaim primary after close, got %q", second.Path())
	}
}
