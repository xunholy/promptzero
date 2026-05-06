//go:build windows

package audit

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryFlock takes a non-blocking exclusive byte-range lock on path,
// opening (creating if absent) the file first. Mirrors the unix flock
// helper — same ((*os.File, bool, error)) contract — so Open() can use
// a single fallback ladder regardless of platform.
//
// Windows has no flock(2). LockFileEx with LOCKFILE_EXCLUSIVE_LOCK +
// LOCKFILE_FAIL_IMMEDIATELY is the closest equivalent: an exclusive
// lock that returns ERROR_LOCK_VIOLATION instead of blocking when the
// file is already locked. We lock the entire file by passing
// (offsetLow=0, offsetHigh=0, lengthLow=MaxUint32, lengthHigh=MaxUint32),
// which is the conventional "whole file" range for LockFileEx.
//
// The bool return distinguishes "someone else holds the lock"
// (false, nil err) from "I/O or permission error" (false, non-nil err)
// so the audit Open() ladder can pick the .pid fallback only on the
// contention case, matching unix semantics.
func tryFlock(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, false, err
	}
	ol := new(windows.Overlapped)
	const (
		exclusive       = uint32(0x00000002) // LOCKFILE_EXCLUSIVE_LOCK
		failImmediately = uint32(0x00000001) // LOCKFILE_FAIL_IMMEDIATELY
		maxUint32       = ^uint32(0)
	)
	if err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		exclusive|failImmediately,
		0, // reserved, must be 0
		maxUint32, maxUint32,
		ol,
	); err != nil {
		_ = f.Close()
		// ERROR_LOCK_VIOLATION (33) is the contention signal under
		// LOCKFILE_FAIL_IMMEDIATELY. Any other errno is a real I/O
		// problem the caller should surface.
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return f, true, nil
}

// releaseFlock drops the byte-range lock and closes the handle. Closing
// the handle is itself enough for Windows to release the lock, but the
// explicit UnlockFileEx makes the intent clear and matches the unix
// path's order (release lock before close).
func releaseFlock(f *os.File) error {
	if f == nil {
		return nil
	}
	ol := new(windows.Overlapped)
	const maxUint32 = ^uint32(0)
	// Best-effort: if Unlock fails the Close below still releases the
	// kernel-side lock when the handle goes away, so we don't surface
	// the unlock error.
	_ = windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0, // reserved
		maxUint32, maxUint32,
		ol,
	)
	return f.Close()
}
