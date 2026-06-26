// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package flipper

import (
	"errors"
	"syscall"
)

// disconnectErrnos are the Unix errnos a serial fd returns once the Flipper
// is physically gone or its descriptor is dead: EIO (I/O error — device
// removed mid-read), ENODEV / ENXIO (no such device — unplugged), and EBADF
// (bad file descriptor — fd already torn down).
var disconnectErrnos = []syscall.Errno{
	syscall.EIO,
	syscall.ENODEV,
	syscall.ENXIO,
	syscall.EBADF,
}

// isDisconnectSyscallErr reports whether err wraps a Unix disconnect-class
// errno. errors.Is unwraps the *os.PathError / *os.SyscallError envelopes the
// os and serial layers wrap around the raw errno, so detection survives
// message reformatting.
func isDisconnectSyscallErr(err error) bool {
	for _, errno := range disconnectErrnos {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
