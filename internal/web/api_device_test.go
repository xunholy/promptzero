//go:build linux

package web

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// momentumDeviceInfo mirrors a real Momentum-fork device_info block.
// Momentum sets PowerInfoCmd="info power", HasNFCSubshell=true, SubGHzNeedsDev=false.
const momentumDeviceInfo = `hardware_model                : Flipper Zero
hardware_uid                  : AABBCCDD11223344
hardware_name                 : MomentumDolphin
firmware_commit               : cafebabe
firmware_origin_fork          : Momentum
firmware_version              : mntm-1.0.0
firmware_build_date           : 01-01-2025`

// connectFlipperToMock wires a live *flipper.Flipper onto the mock and calls
// DetectCapabilities so fork-specific routing (e.g. "info power" vs
// "power_info") is resolved before any handler under test runs.
func connectFlipperToMock(t *testing.T, m *mock.Mock) *flipper.Flipper {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	flip, err := flipper.ConnectURL(ctx, m.URL(), 10*time.Second)
	if err != nil {
		t.Fatalf("ConnectURL: %v", err)
	}
	t.Cleanup(func() { _ = flip.Close() })
	if _, err := flip.DetectCapabilities(); err != nil {
		t.Fatalf("DetectCapabilities: %v", err)
	}
	return flip
}

// TestDeviceHappyPath exercises handleDevice end-to-end against a Momentum-fork
// mock. Verifies that the response contains all required sections and that
// device_info / info power / storage fields are parsed and grouped correctly.
func TestDeviceHappyPath(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(args []string) string {
			return momentumDeviceInfo
		}),
		mock.WithHandler("info", func(args []string) string {
			if len(args) >= 1 && args[0] == "power" {
				return "charge.level                  : 91\nbattery.voltage               : 4200"
			}
			return ""
		}),
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "info" {
				return "Label: Flipper SD\nType: FAT32\n60194KiB total\n42088KiB free"
			}
			return ""
		}),
	)
	flip := connectFlipperToMock(t, m)

	s, ts := apiServer(t, &fakeAgent{})
	s.SetFlipper(flip)

	code, body := getJSON(t, ts, "/api/device")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}

	// All structural sections must be present.
	for _, section := range []string{"firmware", "hardware", "battery", "storage", "raw"} {
		if _, ok := body[section]; !ok {
			t.Errorf("response missing %q section; body keys=%v", section, bodyKeys(body))
		}
	}

	// Firmware fields from device_info.
	firmware, _ := body["firmware"].(map[string]any)
	if firmware["firmware_origin_fork"] != "Momentum" {
		t.Errorf("firmware_origin_fork = %v, want Momentum", firmware["firmware_origin_fork"])
	}

	hardware, _ := body["hardware"].(map[string]any)
	if hardware["hardware_name"] != "MomentumDolphin" {
		t.Errorf("hardware_name = %v, want MomentumDolphin", hardware["hardware_name"])
	}

	// Power fields from "info power" — dots normalised to underscores by PowerInfoMap.
	battery, _ := body["battery"].(map[string]any)
	if battery["charge_level"] != "91" {
		t.Errorf("charge_level = %v, want \"91\"", battery["charge_level"])
	}

	// Storage fields from "storage info /ext".
	storage, _ := body["storage"].(map[string]any)
	if storage["storage_sdcard_present"] != "true" {
		t.Errorf("storage_sdcard_present = %v, want \"true\"", storage["storage_sdcard_present"])
	}

	// Happy path: no error arrays in the response.
	if _, ok := body["power_info_errors"]; ok {
		t.Errorf("power_info_errors unexpectedly present in happy-path response: %v",
			body["power_info_errors"])
	}
}

// TestDeviceCacheTTL asserts that two back-to-back GET /api/device requests
// within the 5-second TTL result in only one round of serial commands.
func TestDeviceCacheTTL(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(args []string) string { return momentumDeviceInfo }),
		mock.WithHandler("info", func(args []string) string {
			if len(args) >= 1 && args[0] == "power" {
				return "charge.level: 80"
			}
			return ""
		}),
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "info" {
				return "Label: SD\nType: FAT32\n1024KiB total\n512KiB free"
			}
			return ""
		}),
	)
	flip := connectFlipperToMock(t, m)

	s, ts := apiServer(t, &fakeAgent{})
	s.SetFlipper(flip)

	// First request — cold cache; serial commands must be issued.
	countBefore := m.Count()
	code, _ := getJSON(t, ts, "/api/device")
	if code != http.StatusOK {
		t.Fatalf("first request status = %d", code)
	}
	countAfterFirst := m.Count()
	if countAfterFirst <= countBefore {
		t.Fatalf("first request issued no commands (count %d→%d)", countBefore, countAfterFirst)
	}

	// Second request immediately — cache is warm; no additional serial commands.
	code, _ = getJSON(t, ts, "/api/device")
	if code != http.StatusOK {
		t.Fatalf("second request status = %d", code)
	}
	if m.Count() != countAfterFirst {
		t.Errorf("cache miss: second request issued %d additional commands (want 0)",
			m.Count()-countAfterFirst)
	}
}

// bodyKeys returns the top-level keys of a map for error messages.
func bodyKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
