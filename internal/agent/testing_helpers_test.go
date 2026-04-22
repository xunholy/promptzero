package agent

import (
	"testing"

	"github.com/xunholy/promptzero/internal/snapshot"
)

// stubSnapshotManager returns a manager rooted under t.TempDir() so
// tests can exercise the snapshot path end-to-end without cluttering
// ~/.promptzero. Lives in a testing-only file so the production
// package doesn't accidentally reach for this helper.
func stubSnapshotManager(t *testing.T) *snapshot.Manager {
	t.Helper()
	return snapshot.NewManager(t.TempDir())
}
