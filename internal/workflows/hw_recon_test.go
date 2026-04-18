//go:build linux

package workflows_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/workflows"
)

// mockFlipper wires a pty-backed mock Flipper + performs capability detection
// so the returned handle mirrors what the agent uses at runtime. Shared
// helper for every workflow test in this package.
func mockFlipper(t *testing.T, opts ...mock.Option) (*flipper.Flipper, *mock.Mock) {
	t.Helper()
	m := mock.Spawn(t, opts...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	f, err := flipper.Connect(ctx, m.Path(), 115200, 10*time.Second)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.DetectCapabilities(); err != nil {
		t.Fatalf("DetectCapabilities: %v", err)
	}
	return f, m
}

// TestHWReconHappyPath verifies the workflow aggregates each probe's
// output into the JSON envelope and surfaces parsed I²C addresses.
func TestHWReconHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; drives the full 12-phase recon — rerun without -short")
	}
	f, _ := mockFlipper(t,
		mock.WithHandler("i2c", func(args []string) string {
			// "i2c scan" response — typical Flipper format with two devices.
			return "Scanning I2C bus...\nFound device at 0x3c\nFound device at 0x68"
		}),
		mock.WithHandler("onewire", func(args []string) string {
			return "Searching OneWire bus...\nROM: 28:FF:AA:BB:CC:DD:EE:01"
		}),
		mock.WithHandler("gpio", func(args []string) string {
			// Every pin reads low so the summary is "0/N high".
			return "Pin = 0"
		}),
		mock.WithHandler("bt", func(args []string) string { return "hci_version: 12\nmac: 80:E1:26:01:02:03" }),
	)

	out, err := workflows.HWReconBlackbox(context.Background(), workflows.Deps{Flipper: f}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("HWReconBlackbox: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}

	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "I2C: 2 devices") {
		t.Errorf("summary missing I2C count: %q", summary)
	}
	if !strings.Contains(summary, "OneWire: 1 devices") {
		t.Errorf("summary missing OneWire count: %q", summary)
	}

	addrs, _ := got["i2c_addresses"].([]interface{})
	if len(addrs) != 2 {
		t.Errorf("expected 2 i2c addresses, got %v", addrs)
	}

	phases, _ := got["phases"].([]interface{})
	// i2c + onewire + 8 gpios + bt + system_info = 12 phases
	if len(phases) != 12 {
		t.Errorf("expected 12 phases, got %d", len(phases))
	}

	next, _ := got["next_steps"].([]interface{})
	if len(next) == 0 {
		t.Errorf("expected at least one next_step suggestion")
	}
}

// TestHWReconRespectsGPIOOverride verifies the `gpios` param overrides
// the default pin list. We pass one pin and expect only one gpio phase.
func TestHWReconRespectsGPIOOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; rerun without -short")
	}
	f, _ := mockFlipper(t,
		mock.WithHandler("i2c", func(args []string) string { return "no devices found" }),
		mock.WithHandler("onewire", func(args []string) string { return "no devices" }),
		mock.WithHandler("gpio", func(args []string) string { return "Pin = 1" }),
		mock.WithHandler("bt", func(args []string) string { return "ok" }),
	)

	out, err := workflows.HWReconBlackbox(context.Background(), workflows.Deps{Flipper: f},
		map[string]interface{}{"gpios": []interface{}{"PA7"}})
	if err != nil {
		t.Fatalf("HWReconBlackbox: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	phases, _ := got["phases"].([]interface{})
	// i2c + onewire + 1 gpio + bt + system_info = 5
	if len(phases) != 5 {
		t.Errorf("expected 5 phases with one-pin override, got %d", len(phases))
	}
}
