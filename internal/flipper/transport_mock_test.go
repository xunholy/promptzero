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

// TestConnectURL_BLEUnreachableMAC asserts the shape of a failed BLE
// dial rather than asserting a "not implemented" rejection. Replaces
// the Phase-6 TestConnectURLRejectsBLE, whose premise was invalidated
// when the ble:// scheme went from reserved to live.
//
// An unreachable (well-formed but not-on-air) MAC must:
//  1. Route through the registered BLE dialer — not fall off the
//     unknown-scheme cliff.
//  2. Return a non-nil error whose message mentions the BLE layer
//     (scan/connect/BLE/ble), not "not implemented" or "unknown
//     scheme".
//  3. Fail within the short ctx deadline; the real scan timeout is
//     30s, so if this test takes anywhere near that long the timeout
//     plumbing regressed.
//
// Runs in CI regardless of BLE hardware. On boxes with no BLE adapter
// (WSL2, most CI runners) adapter.Enable() errors out of the dialer;
// on boxes with an adapter but no target peripheral the scan loop
// ends via the context deadline. Both paths surface a BLE-specific
// error, which is what we assert.
func TestConnectURL_BLEUnreachableMAC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	_, err := flipper.ConnectURL(ctx, "ble://00:00:00:00:00:00", 2*time.Second)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("ConnectURL(ble://00:00:00:00:00:00) = nil error, want BLE failure")
	}
	msg := err.Error()
	if strings.Contains(strings.ToLower(msg), "not implemented") {
		t.Errorf("error = %q still claims 'not implemented'; BLE dialer didn't replace the reserved-scheme stub", msg)
	}
	if strings.Contains(strings.ToLower(msg), "unknown scheme") {
		t.Errorf("error = %q reports 'unknown scheme'; ble:// is not registered as a transport dialer", msg)
	}
	wantSubs := []string{"scan", "ble", "bluetooth", "adapter", "no flipper"}
	if !containsAnyFold(msg, wantSubs) {
		t.Errorf("error = %q does not mention any of %v; caller can't tell this was a BLE failure", msg, wantSubs)
	}
	if elapsed > 10*time.Second {
		t.Errorf("ConnectURL hung for %v before failing; ctx/scan timeout plumbing regressed (bleScanTimeout is 30s — short ctx must short-circuit it)", elapsed)
	}
}

// TestConnectURLViaBLEScheme exercises the ble:// entry point end-to-
// end against a real paired Flipper whose MAC address is in
// FLIPPER_BLE_MAC. Runs alongside the unreachable-MAC test — the
// latter proves the failure path, this one proves the success path.
// Gated so CI and WSL2 (which has no BLE stack) skip it by default.
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

// containsAnyFold returns true if s contains any of subs, case-
// insensitively. Kept local to this file because it's only useful to
// the BLE error-shape assertion above.
func containsAnyFold(s string, subs []string) bool {
	lower := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
