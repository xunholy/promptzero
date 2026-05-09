//go:build darwin || freebsd || netbsd || openbsd

package main

import "golang.org/x/sys/unix"

// BSD-likes (macOS, FreeBSD, NetBSD, OpenBSD) use TIOCGETA/TIOCSETA
// rather than Linux's TCGETS/TCSETS. Flag semantics (OPOST + ONLCR)
// are the same — only the request constants differ.
const (
	termiosGet = unix.TIOCGETA
	termiosSet = unix.TIOCSETA
)
