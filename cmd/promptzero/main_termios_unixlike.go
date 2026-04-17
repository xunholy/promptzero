//go:build darwin || freebsd || netbsd || openbsd

package main

import (
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// enableOPOSTONLCR on BSD-like systems uses TIOCGETA/TIOCSETA rather than
// Linux's TCGETS/TCSETS, but the flag semantics (OPOST + ONLCR) are the
// same. Failures are swallowed; see the linux build's commentary.
func enableOPOSTONLCR(fd int) {
	attr, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return
	}
	attr.Oflag |= unix.OPOST | unix.ONLCR
	_ = unix.IoctlSetTermios(fd, unix.TIOCSETA, attr)
}

// watchWindowSize on BSD-likes uses the same SIGWINCH signal as Linux.
func watchWindowSize(onResize func()) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				onResize()
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
