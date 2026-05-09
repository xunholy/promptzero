//go:build linux

package main

import "golang.org/x/sys/unix"

// Linux uses the TCGETS/TCSETS ioctls to get/set termios attributes.
// BSD-likes use TIOCGETA/TIOCSETA via a sibling build-tagged file.
const (
	termiosGet = unix.TCGETS
	termiosSet = unix.TCSETS
)
