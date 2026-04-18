//go:build linux

package flipper_test

import (
	"context"
	"os"
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

// TestConnectURLViaBLEScheme exercises the ble:// entry point end-to-
// end against a real paired Flipper whose MAC address is in
// FLIPPER_BLE_MAC. Gated on that env var so CI and WSL2 (which has no
// BLE stack) skip the test by default. When unset the test is skipped
// rather than failing — matching the FLIPPER_DEV pattern in the
// transport package's contract test.
func TestConnectURLViaBLEScheme(t *testing.T) {
	mac := os.Getenv("FLIPPER_BLE_MAC")
	if mac == "" {
		t.Skip("FLIPPER_BLE_MAC unset; hardware-gated BLE test skipped")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	flip, err := flipper.ConnectURL(ctx, "ble://"+mac, 45*time.Second)
	if err != nil {
		t.Fatalf("ConnectURL(ble://%s): %v", mac, err)
	}
	defer flip.Close()

	tx := flip.Transport()
	if tx.Kind() != "ble" {
		t.Errorf("Transport().Kind() = %q, want ble", tx.Kind())
	}
	if !strings.HasPrefix(tx.Identity(), "ble://") {
		t.Errorf("Transport().Identity() = %q, want ble:// prefix", tx.Identity())
	}
}
