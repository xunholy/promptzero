//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Contract tests: each registered transport must honour these
// behavioural invariants. Add a case to runContract for a new
// transport rather than re-asserting the same behaviours ad hoc.
//
// The serial case is gated on the FLIPPER_DEV env var so CI boxes
// without hardware skip it automatically. The mock case always runs
// — it's Linux-only because the pty helper below is Linux-only, hence
// the build tag.

func TestContractMockTransport(t *testing.T) {
	t.Parallel()
	runContract(t, func(t *testing.T) (tx Transport, peer io.ReadWriter, cleanup func()) {
		master, slavePath, teardown := newPty(t)
		tx, err := Open("mock://" + slavePath)
		if err != nil {
			teardown()
			t.Fatalf("Open: %v", err)
		}
		return tx, master, teardown
	})
}

func TestContractSerialTransport(t *testing.T) {
	dev := os.Getenv("FLIPPER_DEV")
	if dev == "" {
		t.Skip("FLIPPER_DEV unset; hardware-gated contract test skipped")
	}
	runContract(t, func(t *testing.T) (tx Transport, peer io.ReadWriter, cleanup func()) {
		tx, err := Open(fmt.Sprintf("serial://%s?baud=230400", dev))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		return tx, nil, func() { _ = tx.Close() }
	})
}

// factory returns a ready-to-Dial Transport, an optional "peer"
// endpoint (used by the mock case to write canned bytes into the pty
// master so the transport's Read side has something to read), and a
// cleanup hook.
type factory func(t *testing.T) (tx Transport, peer io.ReadWriter, cleanup func())

func runContract(t *testing.T, f factory) {
	t.Helper()

	t.Run("Identity is non-empty and single-line", func(t *testing.T) {
		tx, _, cleanup := f(t)
		defer cleanup()
		id := tx.Identity()
		if id == "" {
			t.Fatalf("Identity is empty")
		}
		if strings.ContainsAny(id, "\r\n") {
			t.Fatalf("Identity contains newline: %q", id)
		}
	})

	t.Run("Kind matches a known tag", func(t *testing.T) {
		tx, _, cleanup := f(t)
		defer cleanup()
		switch tx.Kind() {
		case "serial", "mock", "ble":
		default:
			t.Fatalf("Kind() = %q, not in the known set", tx.Kind())
		}
	})

	t.Run("Dial succeeds then Write and peer-read round-trip", func(t *testing.T) {
		tx, peer, cleanup := f(t)
		defer cleanup()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := tx.Dial(ctx); err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if _, err := tx.Write([]byte("ping\r")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if peer == nil {
			// Hardware case: no peer — just assert the write didn't
			// error and move on. Data flow is exercised in the
			// flipper-level handshake tests.
			return
		}
		buf := make([]byte, 16)
		if err := setReadDeadline(peer, time.Now().Add(500*time.Millisecond)); err != nil {
			t.Fatalf("setReadDeadline: %v", err)
		}
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatalf("peer.Read: %v", err)
		}
		got := string(buf[:n])
		if !strings.Contains(got, "ping") {
			t.Fatalf("peer read = %q, want to contain %q", got, "ping")
		}
	})

	t.Run("Read returns peer-written bytes", func(t *testing.T) {
		tx, peer, cleanup := f(t)
		defer cleanup()
		if peer == nil {
			t.Skip("no peer endpoint; Read exercised against live hardware instead")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := tx.Dial(ctx); err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if _, err := peer.Write([]byte("pong\r\n")); err != nil {
			t.Fatalf("peer.Write: %v", err)
		}
		buf := make([]byte, 16)
		n, err := tx.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if !strings.Contains(string(buf[:n]), "pong") {
			t.Fatalf("Read = %q, want to contain %q", string(buf[:n]), "pong")
		}
	})

	t.Run("Close unblocks a pending Read", func(t *testing.T) {
		tx, peer, cleanup := f(t)
		defer cleanup()
		if peer == nil {
			t.Skip("no peer endpoint; can't safely block a hardware read")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := tx.Dial(ctx); err != nil {
			t.Fatalf("Dial: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			buf := make([]byte, 16)
			_, err := tx.Read(buf)
			done <- err
		}()
		// Give the goroutine a moment to enter the blocking read.
		time.Sleep(50 * time.Millisecond)
		if err := tx.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("pending Read returned nil error after Close; want a close error")
			}
			if !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.EOF) {
				// Some implementations surface "file already closed"
				// directly; we only require *some* failure, not a
				// specific sentinel.
				t.Logf("pending Read returned %v after Close (acceptable)", err)
			}
		case <-time.After(1 * time.Second):
			t.Fatalf("pending Read did not unblock within 1s of Close")
		}
	})

	t.Run("Close is idempotent", func(t *testing.T) {
		tx, _, cleanup := f(t)
		defer cleanup()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := tx.Dial(ctx); err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if err := tx.Close(); err != nil {
			t.Fatalf("first Close: %v", err)
		}
		if err := tx.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	})

	t.Run("DrainTimeout is positive", func(t *testing.T) {
		tx, _, cleanup := f(t)
		defer cleanup()
		if tx.DrainTimeout() <= 0 {
			t.Fatalf("DrainTimeout = %v, want > 0", tx.DrainTimeout())
		}
	})
}

// --- Linux pty helper (test-only) ---

// newPty returns a master *os.File, the slave /dev/pts/<n> path, and a
// teardown that closes both fds. Mirrors the dance in
// internal/flipper/mock so the contract test doesn't depend on that
// package (which would create a test-cycle).
func newPty(t *testing.T) (master *os.File, slavePath string, cleanup func()) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open ptmx: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = m.Close()
		t.Fatalf("unlockpt: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = m.Close()
		t.Fatalf("ptsname: %v", err)
	}
	slavePath = fmt.Sprintf("/dev/pts/%d", n)

	// Keep a slave fd open for the duration of the test so reads on
	// master don't return EIO when the transport under test closes
	// its own slave fd.
	hold, err := os.OpenFile(slavePath, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = m.Close()
		t.Fatalf("open slave: %v", err)
	}
	if attr, gerr := unix.IoctlGetTermios(int(hold.Fd()), unix.TCGETS); gerr == nil {
		attr.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
		attr.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
		attr.Oflag &^= unix.OPOST
		_ = unix.IoctlSetTermios(int(hold.Fd()), unix.TCSETS, attr)
	}

	return m, slavePath, func() {
		_ = m.Close()
		_ = hold.Close()
	}
}

// setReadDeadline type-asserts to *os.File for the deadline call, so
// the contract test can bound peer reads. The factory currently only
// returns *os.File for peer, but the contract signature takes an
// io.ReadWriter for forward-compat with non-file peer endpoints (e.g.
// in-memory pipes).
func setReadDeadline(w io.ReadWriter, d time.Time) error {
	type deadliner interface {
		SetReadDeadline(time.Time) error
	}
	if dl, ok := w.(deadliner); ok {
		return dl.SetReadDeadline(d)
	}
	return nil
}

