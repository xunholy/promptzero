//go:build linux || darwin || freebsd || netbsd || openbsd

package main

import (
	"os"
	"os/signal"

	"golang.org/x/sys/unix"

	"github.com/xunholy/promptzero/internal/obs"
)

// enableOPOSTONLCR re-enables output post-processing and NL→CRLF translation
// on fd, which term.MakeRaw cleared. The ioctl request constants
// (termiosGet / termiosSet) are platform-specific and live in sibling
// build-tagged files (main_termios_linux.go / main_termios_unixlike.go).
// Failures are swallowed — the setting is purely cosmetic (controls how \n
// renders), not a correctness concern.
func enableOPOSTONLCR(fd int) {
	attr, err := unix.IoctlGetTermios(fd, termiosGet)
	if err != nil {
		return
	}
	attr.Oflag |= unix.OPOST | unix.ONLCR
	_ = unix.IoctlSetTermios(fd, termiosSet, attr)
}

// watchWindowSize installs a SIGWINCH handler that invokes onResize when the
// terminal changes size. Returns a stop function the caller must call on
// shutdown. SIGWINCH is identical across Linux and BSD-likes, so this
// function isn't platform-specific — only the ioctl constants in the
// sibling files are.
func watchWindowSize(onResize func()) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGWINCH)
	done := make(chan struct{})
	obs.SafeGo("termios.sigwinch", func() {
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
