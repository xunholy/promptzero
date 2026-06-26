// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package flipper

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// TestIsDisconnectError_Errnos covers the Unix syscall-errno layer: the
// device-gone / dead-fd errnos are classified as disconnects (including when
// wrapped in the *os.PathError the os layer returns), while a would-block
// errno is not.
func TestIsDisconnectError_Errnos(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EIO bare", syscall.EIO, true},
		{"ENODEV bare", syscall.ENODEV, true},
		{"ENXIO bare", syscall.ENXIO, true},
		{"EBADF bare", syscall.EBADF, true},
		{"EIO wrapped in PathError", &os.PathError{Op: "read", Path: "/dev/ttyACM0", Err: syscall.EIO}, true},
		{"ENODEV wrapped in PathError", &os.PathError{Op: "open", Path: "/dev/ttyACM0", Err: syscall.ENODEV}, true},
		{"plain error is not an errno", errors.New("some failure"), false},
		{"EAGAIN is not disconnect", syscall.EAGAIN, false},
		{"EINVAL is not disconnect", syscall.EINVAL, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isDisconnectError(c.err); got != c.want {
				t.Errorf("isDisconnectError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
