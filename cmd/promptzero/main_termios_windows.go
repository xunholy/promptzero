//go:build windows

package main

// enableOPOSTONLCR is a no-op on Windows. The Windows console / ConPTY
// handles line endings differently from Unix termios; the ONLCR restore
// isn't meaningful here. term.MakeRaw already does the platform-appropriate
// setup via SetConsoleMode on Windows.
func enableOPOSTONLCR(fd int) {}

// watchWindowSize is a no-op on Windows. The Win32 API reports console
// resize events through ReadConsoleInput rather than a signal. Promptzero
// doesn't currently consume those events on Windows; the input box will
// retain its original dimensions across resizes.
func watchWindowSize(onResize func()) func() {
	return func() {}
}
