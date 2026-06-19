//go:build linux

package flipper_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// TestStorageRemoveMkdirMD5_SurfaceStorageError extends the v0.374 storage-error
// fix to the sibling CLI wrappers that were left unguarded: `storage remove`,
// `storage mkdir`, and `storage md5` are silent / hex on success, so the
// firmware's "Storage error: ..." banner (printed to stdout with NO CLI error)
// must surface as a Go error rather than read as success. The RPC/BLE path for
// these already errored on failure; this makes the USB/CLI path consistent.
func TestStorageRemoveMkdirMD5_SurfaceStorageError(t *testing.T) {
	const storageErr = "Storage error: file/dir not exist"

	// Failure case: the firmware returns the banner with no CLI error.
	mFail := mock.Spawn(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 1 && (args[0] == "remove" || args[0] == "mkdir" || args[0] == "md5") {
				return storageErr
			}
			return ""
		}),
	)
	flipFail := connectAndDetect(t, mFail)
	if _, err := flipFail.StorageRemove("/ext/missing.txt"); err == nil {
		t.Error("StorageRemove: expected error for missing path, got nil")
	}
	if _, err := flipFail.StorageMkdir("/ext/exists"); err == nil {
		t.Error("StorageMkdir: expected error for storage banner, got nil")
	}
	if _, err := flipFail.StorageMD5("/ext/missing.txt"); err == nil {
		t.Error("StorageMD5: expected error for missing file, got nil")
	}

	// Success case: empty (remove/mkdir) and a real digest (md5) → no error,
	// no false positive.
	const digest = "d41d8cd98f00b204e9800998ecf8427e"
	mOK := mock.Spawn(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 1 && args[0] == "md5" {
				return digest
			}
			return ""
		}),
	)
	flipOK := connectAndDetect(t, mOK)
	if _, err := flipOK.StorageRemove("/ext/a.txt"); err != nil {
		t.Errorf("StorageRemove clean: unexpected error %v", err)
	}
	if _, err := flipOK.StorageMkdir("/ext/dir"); err != nil {
		t.Errorf("StorageMkdir clean: unexpected error %v", err)
	}
	if out, err := flipOK.StorageMD5("/ext/a.txt"); err != nil {
		t.Errorf("StorageMD5 clean: unexpected error %v", err)
	} else if got := strings.TrimSpace(out); got != digest {
		t.Errorf("StorageMD5 clean: digest = %q, want %q", got, digest)
	}
}
