//go:build !unix && !windows

package audit

import "os"

// On platforms with no advisory file-locking primitive we surface, the
// stub succeeds unconditionally — concurrent writers race, same as the
// pre-Finding-#16 baseline. unix uses flock (lock_unix.go); Windows
// uses LockFileEx (lock_windows.go); everything else lands here.
func tryFlock(path string) (*os.File, bool, error) {
	return nil, true, nil
}

func releaseFlock(f *os.File) error {
	if f == nil {
		return nil
	}
	return f.Close()
}
