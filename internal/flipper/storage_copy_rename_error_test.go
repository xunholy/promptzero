//go:build linux

package flipper_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// TestStorageCopyRename_SurfaceStorageError pins the v0.374 fix: `storage
// copy` / `storage rename` are silent on success, so the firmware's
// "Storage error: file/dir not exist" banner (printed to stdout with no CLI
// error) must be surfaced as a Go error rather than read as success.
func TestStorageCopyRename_SurfaceStorageError(t *testing.T) {
	const storageErr = "Storage error: file/dir not exist"

	// Failure case: handler returns the error banner for copy/rename.
	mFail := mock.Spawn(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 1 && (args[0] == "copy" || args[0] == "rename") {
				return storageErr
			}
			return ""
		}),
	)
	flipFail := connectAndDetect(t, mFail)
	if _, err := flipFail.StorageCopy("/ext/missing.txt", "/ext/dst.txt"); err == nil {
		t.Error("StorageCopy: expected error for missing source, got nil")
	}
	if _, err := flipFail.StorageRename("/ext/missing.txt", "/ext/dst.txt"); err == nil {
		t.Error("StorageRename: expected error for missing source, got nil")
	}

	// Success case: empty output → no error (no false positive).
	mOK := mock.Spawn(t,
		mock.WithHandler("storage", func(_ []string) string { return "" }),
	)
	flipOK := connectAndDetect(t, mOK)
	if _, err := flipOK.StorageCopy("/ext/a.txt", "/ext/b.txt"); err != nil {
		t.Errorf("StorageCopy clean: unexpected error %v", err)
	}
	if _, err := flipOK.StorageRename("/ext/a.txt", "/ext/b.txt"); err != nil {
		t.Errorf("StorageRename clean: unexpected error %v", err)
	}
}
