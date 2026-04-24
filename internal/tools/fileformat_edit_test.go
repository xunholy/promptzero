package tools

import (
	"context"
	"strings"
	"testing"

	flippermock "github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/snapshot"
	"github.com/xunholy/promptzero/internal/testmocks"
)

// minimalSubFile is a minimal valid .sub file for testing fileformat_edit.
const minimalSubFile = "Filetype: Flipper SubGhz Key File\nVersion: 1\nFrequency: 433920000\nPreset: FuriHalSubGhzPresetOok650Async\nProtocol: Princeton\nBit: 24\nKey: AB CD EF 00 00 00 00 00\nTE: 400\n"

// TestFileformatEdit_SnapshotBeforeWrite verifies that fileformat_edit calls
// d.SnapshotBeforeWrite before writing the edited file back (§F.1).
func TestFileformatEdit_SnapshotBeforeWrite(t *testing.T) {
	const targetPath = "/ext/subghz/test.sub"
	const sessionID = "test-session-ff-edit"

	snapDir := t.TempDir()
	mgr := snapshot.NewManager(snapDir)

	// The mock storage handler returns the sub file for reads (args[0]=="read")
	// and is silent for write_chunk (handled by the mock's binary mode).
	f := testmocks.NewMockFlipper(t,
		testmocks.WithFlipperHandler("storage", flippermock.Handler(func(args []string) string {
			if len(args) >= 1 && args[0] == "read" {
				return minimalSubFile
			}
			return ""
		})),
	)

	deps := &Deps{
		Flipper:   f,
		Snapshot:  mgr,
		SessionID: sessionID,
	}

	spec, ok := Get("fileformat_edit")
	if !ok {
		t.Fatal("fileformat_edit not registered")
	}

	// Apply a valid edit — change the Frequency.
	edits := map[string]any{"Frequency": 315000000.0}
	result, err := spec.Handler(context.Background(), deps, map[string]any{
		"path":  targetPath,
		"edits": edits,
	})
	if err != nil {
		t.Fatalf("fileformat_edit returned unexpected error: %v", err)
	}
	if !strings.Contains(result, "edited") {
		t.Errorf("expected 'edited' in result, got: %s", result)
	}

	// SnapshotBeforeWrite must have run: the snapshot manager should have
	// an entry for the session + path.
	entries, err := mgr.List(sessionID)
	if err != nil {
		t.Fatalf("snapshot List: %v", err)
	}
	if len(entries) == 0 {
		t.Error("SnapshotBeforeWrite was not called: no snapshot entries found")
	}
	found := false
	for _, e := range entries {
		if e.OriginalPath == targetPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("snapshot for %s not found; entries: %+v", targetPath, entries)
	}
}

// TestFileformatEdit_RejectsEmptyEdits verifies that an empty edits map
// returns an error rather than a silent no-op.
func TestFileformatEdit_RejectsEmptyEdits(t *testing.T) {
	f := testmocks.NewMockFlipper(t)
	deps := &Deps{Flipper: f}

	spec, ok := Get("fileformat_edit")
	if !ok {
		t.Fatal("fileformat_edit not registered")
	}

	_, err := spec.Handler(context.Background(), deps, map[string]any{
		"path":  "/ext/subghz/test.sub",
		"edits": map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for empty edits, got nil")
	}
}
