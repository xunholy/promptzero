//go:build linux

package flipper_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// TestStorageReadListTree_SurfaceStorageError completes the storage-error
// sibling sweep for the content-echoing CLI wrappers (read / list / tree). The
// firmware prints "Storage error: <reason>" with no CLI error code; a top-level
// failure must surface as a Go error so the USB path matches the RPC path (and
// so callers like nrf24_list_targets, which rely on StorageRead erroring for a
// missing file, behave identically on USB and BLE). Detection is leading-
// anchored, so file content and partial trees that merely contain the marker do
// NOT false-positive.
func TestStorageReadListTree_SurfaceStorageError(t *testing.T) {
	const banner = "Storage error: file/dir not exist"

	// --- Failure: a leading banner is a top-level error. ---
	mFail := mock.Spawn(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 1 && (args[0] == "read" || args[0] == "list" || args[0] == "tree") {
				return banner
			}
			return ""
		}),
	)
	flipFail := connectAndDetect(t, mFail)
	if _, err := flipFail.StorageRead("/ext/missing.txt"); err == nil {
		t.Error("StorageRead: expected error for missing file, got nil")
	}
	if _, err := flipFail.StorageList("/ext/missing"); err == nil {
		t.Error("StorageList: expected error for missing dir, got nil")
	}
	if _, err := flipFail.StorageTree("/ext/missing"); err == nil {
		t.Error("StorageTree: expected error for missing root, got nil")
	}

	// --- Success + false-positive guards. ---
	mOK := mock.Spawn(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) < 1 {
				return ""
			}
			switch args[0] {
			case "read":
				// Leads with "Size:"; the content itself contains the marker
				// and must NOT be flagged.
				return "Size: 27\r\nlog: Storage error: ignored"
			case "list":
				return "\t[D] subghz\n\t[F] note.txt 5b"
			case "tree":
				// A partial tree: the root listed fine, but one subdir failed
				// mid-walk — the embedded banner must NOT fail the whole call.
				return "\t[D] /ext\n\t[D] /ext/locked\nStorage error: denied\n\t[F] /ext/a.txt 5b"
			}
			return ""
		}),
	)
	flipOK := connectAndDetect(t, mOK)

	out, err := flipOK.StorageRead("/ext/log.txt")
	if err != nil {
		t.Errorf("StorageRead clean: unexpected error %v", err)
	} else if !strings.Contains(out, "Storage error: ignored") {
		t.Errorf("StorageRead clean: content lost: %q", out)
	}
	if _, err := flipOK.StorageList("/ext"); err != nil {
		t.Errorf("StorageList clean: unexpected error %v", err)
	}
	if out, err := flipOK.StorageTree("/ext"); err != nil {
		t.Errorf("StorageTree partial: unexpected error %v (a mid-walk subdir banner must not fail the call)", err)
	} else if !strings.Contains(out, "/ext/a.txt") {
		t.Errorf("StorageTree partial: walk truncated: %q", out)
	}
}
