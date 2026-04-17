//go:build linux

package flipper_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// TestConnectURLViaMockScheme exercises the mock:// transport end-to-end:
// Mock.URL() is passed to flipper.ConnectURL, which resolves the scheme
// to the dedicated mockTransport dialer in internal/flipper/transport
// (not the serial dialer's incidental pty support). Proves the refactor
// seam works — a future ble:// URL would flow through the same entry
// point.
func TestConnectURLViaMockScheme(t *testing.T) {
	m := mock.Spawn(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flip, err := flipper.ConnectURL(ctx, m.URL(), 10*time.Second)
	if err != nil {
		t.Fatalf("ConnectURL: %v", err)
	}
	defer flip.Close()

	caps, err := flip.DetectCapabilities()
	if err != nil {
		t.Fatalf("DetectCapabilities: %v", err)
	}
	if caps.HardwareName != "MockDolphin" {
		t.Errorf("HardwareName = %q, want MockDolphin", caps.HardwareName)
	}

	tx := flip.Transport()
	if tx.Kind() != "mock" {
		t.Errorf("Transport().Kind() = %q, want mock", tx.Kind())
	}
	if !strings.HasPrefix(tx.Identity(), "mock://") {
		t.Errorf("Transport().Identity() = %q, want mock:// prefix", tx.Identity())
	}
}

// TestConnectURLRejectsBLE proves the BLE scheme is reserved but
// unimplemented: a ble:// URL must fail with transport.ErrNotImplemented
// so operators who try it get a clear "not yet" signal rather than
// "unknown scheme".
func TestConnectURLRejectsBLE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := flipper.ConnectURL(ctx, "ble://AA:BB:CC:DD:EE:FF", 1*time.Second)
	if err == nil {
		t.Fatalf("ConnectURL(ble://...) returned nil error; want ErrNotImplemented")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("ConnectURL(ble://...) error = %q, want to contain 'not implemented'", err.Error())
	}
}
