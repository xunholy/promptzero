//go:build !unix

package audit

import "os"

// TODO(windows): implement LockFileEx via golang.org/x/sys/windows so
// concurrent PromptZero processes on Windows get the same
// one-writer-per-db guarantee they get on unix. Until then the stub
// succeeds unconditionally — concurrent writers will race, same as the
// pre-Finding-#16 baseline.
func tryFlock(path string) (*os.File, bool, error) {
	return nil, true, nil
}

func releaseFlock(f *os.File) error {
	if f == nil {
		return nil
	}
	return f.Close()
}
