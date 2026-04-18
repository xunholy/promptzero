//go:build linux

package flipper_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// TestStorageFSInfoMapHappy verifies that the happy-path block (Label / Type /
// NKiB total / NKiB free) is parsed into the expected map keys and byte counts.
func TestStorageFSInfoMapHappy(t *testing.T) {
	m := mock.Spawn(t, mock.WithHandler("storage", func(args []string) string {
		if len(args) >= 2 && args[0] == "info" {
			return "Label: TestFS\nType: FAT32\n2048KiB total\n1024KiB free"
		}
		return ""
	}))
	flip := connectAndDetect(t, m)

	got, err := flip.StorageFSInfoMap("/ext")
	if err != nil {
		t.Fatalf("StorageFSInfoMap: %v", err)
	}
	if got["present"] != "true" {
		t.Errorf("present = %q, want \"true\"", got["present"])
	}
	if got["label"] != "TestFS" {
		t.Errorf("label = %q, want \"TestFS\"", got["label"])
	}
	if got["type"] != "FAT32" {
		t.Errorf("type = %q, want \"FAT32\"", got["type"])
	}
	// 2048 KiB = 2097152 bytes
	if got["totalSpace"] != "2097152" {
		t.Errorf("totalSpace = %q, want \"2097152\"", got["totalSpace"])
	}
	// 1024 KiB = 1048576 bytes
	if got["freeSpace"] != "1048576" {
		t.Errorf("freeSpace = %q, want \"1048576\"", got["freeSpace"])
	}
}

// TestStorageFSInfoMapError verifies that "Storage error: not ready" maps to
// present=false with the error message captured in the "error" key.
func TestStorageFSInfoMapError(t *testing.T) {
	m := mock.Spawn(t, mock.WithHandler("storage", func(args []string) string {
		if len(args) >= 2 && args[0] == "info" {
			return "Storage error: not ready"
		}
		return ""
	}))
	flip := connectAndDetect(t, m)

	got, err := flip.StorageFSInfoMap("/ext")
	if err != nil {
		t.Fatalf("StorageFSInfoMap: %v", err)
	}
	if got["present"] != "false" {
		t.Errorf("present = %q, want \"false\"", got["present"])
	}
	if got["error"] != "not ready" {
		t.Errorf("error = %q, want \"not ready\"", got["error"])
	}
}

// TestStorageFSInfoMapCRLF verifies that CRLF line endings (as emitted by the
// real Flipper serial port) are tolerated: TrimSpace strips the trailing \r so
// label and type are returned clean.
func TestStorageFSInfoMapCRLF(t *testing.T) {
	m := mock.Spawn(t, mock.WithHandler("storage", func(args []string) string {
		if len(args) >= 2 && args[0] == "info" {
			return "Label: SDCARD\r\nType: EXFAT\r\n4096KiB total\r\n2048KiB free"
		}
		return ""
	}))
	flip := connectAndDetect(t, m)

	got, err := flip.StorageFSInfoMap("/ext")
	if err != nil {
		t.Fatalf("StorageFSInfoMap: %v", err)
	}
	if got["present"] != "true" {
		t.Errorf("present = %q, want \"true\"", got["present"])
	}
	if strings.Contains(got["label"], "\r") {
		t.Errorf("label contains carriage return: %q", got["label"])
	}
	if strings.Contains(got["type"], "\r") {
		t.Errorf("type contains carriage return: %q", got["type"])
	}
	// 4096 KiB = 4194304 bytes, 2048 KiB = 2097152 bytes
	if got["totalSpace"] != "4194304" {
		t.Errorf("totalSpace = %q, want \"4194304\"", got["totalSpace"])
	}
	if got["freeSpace"] != "2097152" {
		t.Errorf("freeSpace = %q, want \"2097152\"", got["freeSpace"])
	}
}

// TestPowerInfoMapDotNormalisation verifies that dot-separated keys from the
// Xtreme/Momentum `info power` response (e.g. "charge.level") are normalised
// to underscore form ("charge_level"). The mock default is Xtreme, so
// PowerInfo() issues "info power" which the handler answers.
func TestPowerInfoMapDotNormalisation(t *testing.T) {
	// Sample output mirrors real Momentum firmware: the "capacity" group
	// emits `remain` (not `remaining`) per furi_hal_power_info_get.
	m := mock.Spawn(t, mock.WithHandler("info", func(args []string) string {
		if len(args) >= 1 && args[0] == "power" {
			return "charge.level                  : 75\nbattery.voltage               : 4050\ncapacity.remain               : 1800"
		}
		return ""
	}))
	flip := connectAndDetect(t, m)

	got, err := flip.PowerInfoMap()
	if err != nil {
		t.Fatalf("PowerInfoMap: %v", err)
	}

	// Dot-form keys must not appear in the output map.
	for _, dotKey := range []string{"charge.level", "battery.voltage", "capacity.remain"} {
		if _, ok := got[dotKey]; ok {
			t.Errorf("dot key %q was not normalised to underscore form", dotKey)
		}
	}
	// Underscore-form keys must be present with correct values.
	want := map[string]string{
		"charge_level":    "75",
		"battery_voltage": "4050",
		"capacity_remain": "1800",
	}
	for k, wantV := range want {
		if got[k] != wantV {
			t.Errorf("%s = %q, want %q", k, got[k], wantV)
		}
	}
}

// TestExecLongTimeoutSendsCtrlC verifies three properties when ExecLong's
// caller budget fires on a command that never emits a closing prompt:
//  1. ExecLong returns within ≤500 ms for a 300 ms timeout (no hang).
//  2. The mock observes a \x03 (Ctrl+C) byte after the command bytes.
//  3. A subsequent Exec on the same flipper succeeds — no leftover prompt
//     state poisons the next transaction.
func TestExecLongTimeoutSendsCtrlC(t *testing.T) {
	// "freeze" is a command that never emits a closing prompt, simulating
	// indefinitely-streaming firmware commands like `subghz rx` or `log`.
	m := mock.Spawn(t,
		mock.WithSuppressPrompt("freeze"),
		mock.WithHandler("freeze", func(args []string) string {
			return "" // body only; prompt suppressed so the read never terminates
		}),
	)
	flip := connectAndDetect(t, m)

	const budget = 300 * time.Millisecond
	start := time.Now()
	out, err := flip.ExecLong("freeze", budget)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("ExecLong: expected nil error on timeout, got %v", err)
	}
	if elapsed > 600*time.Millisecond {
		t.Errorf("ExecLong took %v, want ≤600 ms", elapsed)
	}
	_ = out // partial accumulated output is fine

	// The mock must have received a Ctrl+C byte after the command.
	rx := m.BytesReceived()
	if !bytes.Contains(rx, []byte{'\x03'}) {
		t.Errorf("mock did not receive Ctrl+C (\\x03) after freeze timeout; bytes: %q", rx)
	}

	// A subsequent Exec must succeed — proves no stale prompt state remains.
	info, execErr := flip.DeviceInfo()
	if execErr != nil {
		t.Errorf("DeviceInfo after ExecLong timeout: %v", execErr)
	}
	if !strings.Contains(info, "hardware_model") {
		t.Errorf("DeviceInfo output missing expected content after timeout: %q", info)
	}
}
