package flipper

import (
	"strings"
	"testing"
)

// UpdateInstall, BackupCreate, BackupRestore, and StorageExtract now
// reject empty/whitespace path args before transport. All four operate
// on /int or wipe the SD card; an empty path produces malformed
// commands like `update install ` or `storage extract  /ext/foo`
// which various firmware forks either silently accept (writing to a
// surprising location) or bounce with an opaque banner.

func TestUpdateInstall_RejectsEmptyPath(t *testing.T) {
	f := &Flipper{}
	for _, p := range []string{"", "   ", "\t"} {
		_, err := f.UpdateInstall(p)
		if err == nil {
			t.Errorf("expected error for manifestPath=%q; got nil", p)
			continue
		}
		if !strings.Contains(err.Error(), "manifest path") {
			t.Errorf("path=%q err = %v; want manifest path error", p, err)
		}
	}
}

func TestBackupCreate_RejectsEmptyPath(t *testing.T) {
	f := &Flipper{}
	for _, p := range []string{"", "   "} {
		_, err := f.BackupCreate(p)
		if err == nil {
			t.Errorf("expected error for path=%q; got nil", p)
			continue
		}
		if !strings.Contains(err.Error(), "backup path") {
			t.Errorf("path=%q err = %v; want backup path error", p, err)
		}
	}
}

func TestBackupRestore_RejectsEmptyPath(t *testing.T) {
	f := &Flipper{}
	for _, p := range []string{"", " \t\n"} {
		_, err := f.BackupRestore(p)
		if err == nil {
			t.Errorf("expected error for path=%q; got nil", p)
			continue
		}
		if !strings.Contains(err.Error(), "backup path") {
			t.Errorf("path=%q err = %v; want backup path error", p, err)
		}
	}
}

func TestStorageExtract_RejectsEmptyArgs(t *testing.T) {
	f := &Flipper{}
	// Empty archive.
	if _, err := f.StorageExtract("", "/ext/out"); err == nil {
		t.Error("expected error for empty archive; got nil")
	} else if !strings.Contains(err.Error(), "archive") {
		t.Errorf("err = %v; want archive validation error", err)
	}
	// Empty outdir.
	if _, err := f.StorageExtract("/ext/x.tar", "   "); err == nil {
		t.Error("expected error for whitespace outdir; got nil")
	} else if !strings.Contains(err.Error(), "outdir") {
		t.Errorf("err = %v; want outdir validation error", err)
	}
}
