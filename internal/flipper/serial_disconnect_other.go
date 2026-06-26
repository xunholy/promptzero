// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package flipper

// isDisconnectSyscallErr is a no-op on non-Unix platforms: disconnect
// detection there relies on the cross-platform sentinel (os.ErrClosed) and
// substring checks in isDisconnectError. Windows-specific disconnect errnos
// are intentionally not enumerated here — they are unverified on this build
// host, and adding an unvalidated string risks a false positive.
func isDisconnectSyscallErr(error) bool { return false }
