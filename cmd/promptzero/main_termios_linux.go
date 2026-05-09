//go:build linux

package main

import (
	"os"
	"os/signal"

	"golang.org/x/sys/unix"

	"github.com/xunholy/promptzero/internal/obs"
)

// enableOPOSTONLCR re-enables output post-processing and NL→CRLF translation
// on fd, which term.MakeRaw cleared. Linux uses the TCGETS/TCSETS ioctls.
// Failures are swallowed — the setting is purely cosmetic (controls how \n
// renders), not a correctness concern.
func enableOPOSTONLCR(fd int) {
	attr, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return
	}
	attr.Oflag |= unix.OPOST | unix.ONLCR
	_ = unix.IoctlSetTermios(fd, unix.TCSETS, attr)
}

// watchWindowSize installs a SIGWINCH handler that invokes onResize when the
// terminal changes size. Returns a stop function the caller must call on
// shutdown. Linux exposes SIGWINCH via golang.org/x/sys/unix.
func watchWindowSize(onResize func()) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGWINCH)
	done := make(chan struct{})
	obs.SafeGo("termios.linux.sigwinch", func() {
		for {
			select {
			case <-ch:
				onResize()
			case <-done:
				return
			}
		}
	})
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
