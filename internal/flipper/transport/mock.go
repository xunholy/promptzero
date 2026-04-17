package transport

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// mockDrainTimeout mirrors the serial value. The pty-backed mock
// responds synchronously, so the drain delay only affects how long the
// flipper layer waits before declaring the device silent.
const mockDrainTimeout = 100 * time.Millisecond

func init() { Register("mock", mockDialer) }

// mockDialer parses a mock://<pts-path> URL and returns an undialled
// transport. The pts path is expected to already exist — the mock
// harness in internal/flipper/mock is responsible for creating the pty
// pair; this transport simply opens the slave as a raw file.
func mockDialer(rawURL string) (Transport, error) {
	path, _, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("transport: mock URL missing pts path: %q", rawURL)
	}
	return &mockTransport{path: path}, nil
}

// mockTransport is a raw-file wrapper around a pty slave. Unlike
// serialTransport it doesn't try to SetDTR or set a read timeout via
// ioctl (pty slaves don't support those). Reads block until data is
// available or the file is closed — the flipper layer polls ctx via
// short SetReadTimeout windows for serial, but for mock the read side
// unblocks by Close().
//
// The simultaneous-open behaviour matters: the mock harness keeps its
// own slave fd open for the lifetime of the test so the master doesn't
// see EIO when we close this one. Opening the same slavePath from two
// fds is legal on Linux ptys.
type mockTransport struct {
	mu sync.Mutex
	f  *os.File

	path string
}

func (t *mockTransport) Dial(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f != nil {
		return fmt.Errorf("transport: mock already dialled (%s)", t.path)
	}
	f, err := os.OpenFile(t.path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("transport: opening mock pts %s: %w", t.path, err)
	}
	t.f = f
	return nil
}

// Reconnect for the mock transport is close + open of the same pts
// path. Real tests don't exercise this — they Close the mock at the
// end — but the contract test asserts it works so the interface is
// uniform.
func (t *mockTransport) Reconnect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.OpenFile(t.path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("transport: reopening mock pts %s: %w", t.path, err)
	}
	t.f = f
	return nil
}

func (t *mockTransport) Read(p []byte) (int, error) {
	t.mu.Lock()
	f := t.f
	t.mu.Unlock()
	if f == nil {
		return 0, os.ErrClosed
	}
	return f.Read(p)
}

func (t *mockTransport) Write(p []byte) (int, error) {
	t.mu.Lock()
	f := t.f
	t.mu.Unlock()
	if f == nil {
		return 0, os.ErrClosed
	}
	return f.Write(p)
}

func (t *mockTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return nil
	}
	err := t.f.Close()
	t.f = nil
	return err
}

// SetReadTimeout is a no-op on the mock transport because pty slaves
// don't support TIOCSSETA-style per-read timeouts. Tests that need to
// unblock a pending Read should Close() the transport instead — the
// interface contract test exercises this path.
func (t *mockTransport) SetReadTimeout(d time.Duration) error { return nil }

func (t *mockTransport) Identity() string           { return "mock://" + t.path }
func (t *mockTransport) DrainTimeout() time.Duration { return mockDrainTimeout }
func (t *mockTransport) Kind() string               { return "mock" }
