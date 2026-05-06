//go:build linux

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
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
	flip, _, err := flipper.ConnectURL(ctx, m.URL(), 10*time.Second)
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

// TestDeviceStatusBarSections asserts the new typed status-bar payload:
// `flipper`, `marauder`, `ble`, `sd`, and `battery.percent`. The web UI's
// status bar binds to these directly, so a regression in field name or
// shape would break the pill row on every reload.
func TestDeviceStatusBarSections(t *testing.T) {
	const flipperFW = "mntm-1.2.3"
	devInfo := momentumDeviceInfo + "\nfirmware_version              : " + flipperFW
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(args []string) string { return devInfo }),
		mock.WithHandler("info", func(args []string) string {
			if len(args) >= 1 && args[0] == "power" {
				return "charge.level                  : 73"
			}
			return ""
		}),
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "info" {
				// 1024 KiB total = 1,048,576 bytes; 768 KiB free = 786,432 bytes.
				return "Label: Flipper SD\nType: FAT32\n1024KiB total\n768KiB free"
			}
			return ""
		}),
	)
	flip := connectFlipperToMock(t, m)

	s, ts := apiServer(t, &fakeAgent{})
	s.SetFlipper(flip)
	s.SetFlipperConnected(true)
	s.SetMarauderConnected(true)
	s.SetMarauderInfo("/dev/ttyACM1", "v1.2.3-marauder")

	code, body := getJSON(t, ts, "/api/device")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}

	// flipper pill: connected + firmware + transport identity (port).
	flipper, ok := body["flipper"].(map[string]any)
	if !ok {
		t.Fatalf("missing 'flipper' object; body keys=%v", bodyKeys(body))
	}
	if flipper["connected"] != true {
		t.Errorf("flipper.connected = %v, want true", flipper["connected"])
	}
	if flipper["firmware"] != flipperFW {
		t.Errorf("flipper.firmware = %v, want %q", flipper["firmware"], flipperFW)
	}
	port, _ := flipper["port"].(string)
	if port == "" {
		t.Errorf("flipper.port empty; want non-empty transport identity (mock://...)")
	}

	// marauder pill: connected + firmware + port from SetMarauderInfo.
	marauder, ok := body["marauder"].(map[string]any)
	if !ok {
		t.Fatalf("missing 'marauder' object; body keys=%v", bodyKeys(body))
	}
	if marauder["connected"] != true {
		t.Errorf("marauder.connected = %v, want true", marauder["connected"])
	}
	if marauder["port"] != "/dev/ttyACM1" {
		t.Errorf("marauder.port = %v, want /dev/ttyACM1", marauder["port"])
	}
	if marauder["firmware"] != "v1.2.3-marauder" {
		t.Errorf("marauder.firmware = %v, want v1.2.3-marauder", marauder["firmware"])
	}

	// BLE: mock transport kind != "ble", so state should be "off".
	ble, ok := body["ble"].(map[string]any)
	if !ok {
		t.Fatalf("missing 'ble' object; body keys=%v", bodyKeys(body))
	}
	if ble["state"] != "off" {
		t.Errorf("ble.state = %v, want \"off\" (mock transport, not ble)", ble["state"])
	}

	// battery.percent must be a number (JSON-decoded as float64).
	battery, ok := body["battery"].(map[string]any)
	if !ok {
		t.Fatalf("missing 'battery' object; body keys=%v", bodyKeys(body))
	}
	pct, ok := battery["percent"].(float64)
	if !ok {
		t.Fatalf("battery.percent = %v (%T), want number", battery["percent"], battery["percent"])
	}
	if int(pct) != 73 {
		t.Errorf("battery.percent = %v, want 73", pct)
	}
	// Existing string-typed key must still be present for legacy consumers.
	if battery["charge_level"] != "73" {
		t.Errorf("battery.charge_level = %v, want \"73\" (legacy field broken)", battery["charge_level"])
	}

	// sd: present + free/total in bytes (uint64 → JSON number → float64).
	sd, ok := body["sd"].(map[string]any)
	if !ok {
		t.Fatalf("missing 'sd' object; body keys=%v", bodyKeys(body))
	}
	if sd["present"] != true {
		t.Errorf("sd.present = %v, want true", sd["present"])
	}
	if free, _ := sd["free_bytes"].(float64); int64(free) != 768*1024 {
		t.Errorf("sd.free_bytes = %v, want %d", sd["free_bytes"], 768*1024)
	}
	if total, _ := sd["total_bytes"].(float64); int64(total) != 1024*1024 {
		t.Errorf("sd.total_bytes = %v, want %d", sd["total_bytes"], 1024*1024)
	}
}

// TestDeviceStatusBarEmptyMarauder asserts the marauder pill stays
// well-formed (connected:false, empty strings) when no Marauder is
// wired — the status bar relies on these fields existing so the
// front-end JSON binding doesn't crash on `undefined`.
func TestDeviceStatusBarEmptyMarauder(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(args []string) string { return momentumDeviceInfo }),
		mock.WithHandler("info", func(args []string) string {
			if len(args) >= 1 && args[0] == "power" {
				return "charge.level: 50"
			}
			return ""
		}),
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "info" {
				return "Label: SD\nType: FAT32\n0KiB total\n0KiB free"
			}
			return ""
		}),
	)
	flip := connectFlipperToMock(t, m)

	s, ts := apiServer(t, &fakeAgent{})
	s.SetFlipper(flip)
	s.SetFlipperConnected(true)
	// No SetMarauderConnected / SetMarauderInfo — the host did not wire one.

	_, body := getJSON(t, ts, "/api/device")
	marauder, ok := body["marauder"].(map[string]any)
	if !ok {
		t.Fatalf("missing 'marauder' object; body keys=%v", bodyKeys(body))
	}
	if marauder["connected"] != false {
		t.Errorf("marauder.connected = %v, want false", marauder["connected"])
	}
	if marauder["port"] != "" {
		t.Errorf("marauder.port = %v, want \"\"", marauder["port"])
	}
	if marauder["firmware"] != "" {
		t.Errorf("marauder.firmware = %v, want \"\"", marauder["firmware"])
	}
}

// dumpDevicePayloadHandoff prints a captured /api/device payload so the
// frontend integrator and team lead can reference a real (non-speculative)
// JSON shape. Gated behind PROMPTZERO_DUMP_DEVICE so it only fires when
// explicitly requested via `PROMPTZERO_DUMP_DEVICE=1 go test -run …`.
func TestDumpDevicePayloadForHandoff(t *testing.T) {
	if os.Getenv("PROMPTZERO_DUMP_DEVICE") == "" {
		t.Skip("set PROMPTZERO_DUMP_DEVICE=1 to dump the example payload")
	}
	const flipperFW = "mntm-1.2.3"
	devInfo := momentumDeviceInfo + "\nfirmware_version              : " + flipperFW
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(args []string) string { return devInfo }),
		mock.WithHandler("info", func(args []string) string {
			if len(args) >= 1 && args[0] == "power" {
				return "charge.level                  : 73"
			}
			return ""
		}),
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "info" {
				return "Label: Flipper SD\nType: FAT32\n1024KiB total\n768KiB free"
			}
			return ""
		}),
	)
	flip := connectFlipperToMock(t, m)
	s, ts := apiServer(t, &fakeAgent{})
	s.SetFlipper(flip)
	s.SetFlipperConnected(true)
	s.SetMarauderConnected(true)
	s.SetMarauderInfo("/dev/ttyACM1", "v1.2.3-marauder")
	resp, err := ts.Client().Get(ts.URL + "/api/device")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	out, _ := json.MarshalIndent(body, "", "  ")
	t.Logf("\n%s", out)
}

// TestDevice_BridgeStateInResponse locks the v0.23 contract: the
// /api/device JSON now surfaces SetBridgeMode() so the cockpit can
// render the suspended-Flipper pill and the "via Flipper bridge"
// Marauder subtitle. Closes the SPEC.md §6.3 / api.go TODO.
//
// Two cases: bridge inactive (default), bridge active with reason.
// Reason text is operator-visible — typically "Marauder stacked on
// GPIO header" or similar — and must round-trip through the JSON.
func TestDevice_BridgeStateInResponse(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(args []string) string {
			return momentumDeviceInfo
		}),
	)
	flip := connectFlipperToMock(t, m)

	// Case 1: bridge not set — JSON should still have the bridge
	// block with active=false (consumers can rely on the key always
	// being present rather than undefined).
	s, ts := apiServer(t, &fakeAgent{})
	s.SetFlipper(flip)

	_, body := getJSON(t, ts, "/api/device")
	bridge, ok := body["bridge"].(map[string]any)
	if !ok {
		t.Fatalf("bridge block missing from response; body keys=%v", bodyKeys(body))
	}
	if bridge["active"] != false {
		t.Errorf("default bridge.active = %v, want false", bridge["active"])
	}
	if _, hasReason := bridge["reason"]; hasReason {
		t.Errorf("default bridge.reason should be absent, got: %v", bridge["reason"])
	}

	// Case 2: SetBridgeMode toggled — both fields surface, and the
	// reason string round-trips byte-identical.
	const reason = "Marauder stacked on GPIO header — flipper_* tools paused"
	s.SetBridgeMode(true, reason)

	// Bypass the cache by directly invoking through a fresh request.
	// The 5s TTL would otherwise serve the stale (active=false) response.
	s.deviceCacheMu.Lock()
	s.deviceCacheResp = nil
	s.deviceCacheAt = time.Time{}
	s.deviceCacheMu.Unlock()

	_, body = getJSON(t, ts, "/api/device")
	bridge, ok = body["bridge"].(map[string]any)
	if !ok {
		t.Fatalf("bridge block missing after SetBridgeMode; body keys=%v", bodyKeys(body))
	}
	if bridge["active"] != true {
		t.Errorf("after SetBridgeMode(true): bridge.active = %v, want true", bridge["active"])
	}
	if got := bridge["reason"]; got != reason {
		t.Errorf("bridge.reason = %v, want %q", got, reason)
	}
}
