//go:build unix

package audit

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// tryFlock takes a non-blocking exclusive advisory flock on path, opening
// (creating if absent) the file first. On success the returned *os.File is
// the lock handle — the caller is expected to keep it open for the
// lifetime of the lock and call releaseFlock to drop it.
//
// A bool is returned distinguishing "someone else holds the lock" (false,
// nil err) from "I/O or permission error" (false, non-nil err), so callers
// can choose to fall back to a PID-suffixed path only when the contention
// case applies.
func tryFlock(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return f, true, nil
}

// releaseFlock drops the advisory lock held on f and closes the fd. A nil
// receiver is tolerated so Close paths don't need to guard on the stub
// platform case.
func releaseFlock(f *os.File) error {
	if f == nil {
		return nil
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return f.Close()
}
