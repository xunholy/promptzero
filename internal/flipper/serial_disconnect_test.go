// SPDX-License-Identifier: AGPL-3.0-or-later

package flipper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

// TestIsDisconnectError_Portable covers the cross-platform layers of the
// disconnect classifier: typed os.ErrClosed (bare and wrapped), the
// substring fallback, and — critically — that timeouts and benign errors are
// NOT classified as disconnects (which would trigger a spurious reconnect).
func TestIsDisconnectError_Portable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"os.ErrClosed bare", os.ErrClosed, true},
		{"os.ErrClosed wrapped", fmt.Errorf("serial read: %w", os.ErrClosed), true},
		{"string: input/output error", errors.New("read /dev/ttyACM0: input/output error"), true},
		{"string: no such device", errors.New("open /dev/ttyACM0: no such device"), true},
		{"string: device not configured", errors.New("device not configured"), true},
		{"string: port has been closed", errors.New("Port has been closed"), true}, // case-insensitive
		{"string: bad file descriptor", errors.New("read: bad file descriptor"), true},
		{"timeout is not disconnect", os.ErrDeadlineExceeded, false},
		{"context deadline is not disconnect", context.DeadlineExceeded, false},
		{"context canceled is not disconnect", context.Canceled, false},
		{"benign error", errors.New("command failed: invalid argument"), false},
		{"empty-ish error", errors.New("ok"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isDisconnectError(c.err); got != c.want {
				t.Errorf("isDisconnectError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestMarkDisconnectedIfRelevant wires the classifier to the flag the
// reconnect machinery reads: a disconnect-class error trips it, benign errors
// and nil leave it clear.
func TestMarkDisconnectedIfRelevant(t *testing.T) {
	t.Run("disconnect trips the flag", func(t *testing.T) {
		f := &Flipper{}
		f.markDisconnectedIfRelevant(fmt.Errorf("read failed: %w", os.ErrClosed))
		if !f.disconnected.Load() {
			t.Error("disconnected flag should be set after a disconnect-class error")
		}
	})
	t.Run("benign error leaves it clear", func(t *testing.T) {
		f := &Flipper{}
		f.markDisconnectedIfRelevant(errors.New("invalid argument"))
		if f.disconnected.Load() {
			t.Error("benign error must not set the disconnected flag")
		}
	})
	t.Run("timeout leaves it clear", func(t *testing.T) {
		f := &Flipper{}
		f.markDisconnectedIfRelevant(context.DeadlineExceeded)
		if f.disconnected.Load() {
			t.Error("a timeout must not set the disconnected flag (no spurious reconnect)")
		}
	})
	t.Run("nil is a no-op", func(t *testing.T) {
		f := &Flipper{}
		f.markDisconnectedIfRelevant(nil)
		if f.disconnected.Load() {
			t.Error("nil error must not set the disconnected flag")
		}
	})
}

// TestReconnectIfNeededLocked_NotDisconnected verifies the fast-path guard:
// when the flag is clear, the function returns nil without touching the
// transport (so a nil transport is safe — proving no work is attempted).
func TestReconnectIfNeededLocked_NotDisconnected(t *testing.T) {
	f := &Flipper{} // transport nil; would panic if the guard didn't short-circuit
	if err := f.reconnectIfNeededLocked(context.Background()); err != nil {
		t.Errorf("not-disconnected reconnect should be a no-op, got %v", err)
	}
}
