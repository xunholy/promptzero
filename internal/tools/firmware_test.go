package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper"
)

// TestFirmwareIntrospectHandler is a smoke test for the firmware_introspect
// Spec's Handler. It creates a Flipper with preloaded capabilities using
// NewForTest (no hardware access), invokes the handler, and asserts that the
// returned JSON is valid and contains every documented top-level field.
func TestFirmwareIntrospectHandler(t *testing.T) {
	caps := flipper.Capabilities{
		FirmwareFork:           "Momentum",
		FirmwareVersion:        "mntm-dev",
		FirmwareCommit:         "abc12345",
		FirmwareDate:           "09-03-2026",
		HardwareUID:            "0000000000000006",
		HardwareName:           "Unholy",
		FirmwareBand:           "momentum/mntm-dev",
		FirmwareAPIMajor:       79,
		FirmwareAPIMinor:       2,
		FirmwareCommitDirty:    false,
		FirmwareOriginGit:      "https://github.com/Next-Flip/Momentum-Firmware",
		HardwareRegion:         "2",
		HardwareVer:            13,
		DeviceInfoKeyStyle:     "underscore",
		PowerInfoCmd:           "info power",
		HasNFCSubshell:         true,
		SubGHzNeedsDev:         true,
		NFCFlaggedArgs:         true,
		SubGHzRxRawHasFilePath: false,
		JSEngineKind:           "mjs",
		HasBLESpam:             true,
		HasSubGHzBruteforcer:   true,
		HasMouseJackerFAP:      true,
		HasSeaderFAP:           true,
		HasPicopassFAP:         true,
		HasNFCMagicFAP:         true,
		HasMFKeyFAP:            true,
		HasMifareNestedFAP:     true,
		UniversalIRLibraryName: "infrared/assets",
		HasStorageFormatExt:    true,
		HasSubGHzEncryptKeeloq: true,
		HasSubGHzChat:          true,
		HasPsCmd:               true,
		HasClearCmd:            true,
		StorageExtFatLabel:     "MOMENTUM",
		SnapshotPrefix:         "/any/.flipperzero_snapshots/",
		MarauderDetected:       false,
		MarauderCompatBand:     "",
	}

	f := flipper.NewForTest(caps)
	d := &Deps{Flipper: f}

	got, err := firmwareIntrospectSpec.Handler(context.Background(), d, nil)
	if err != nil {
		t.Fatalf("Handler error: %v", err)
	}

	// Unmarshal to a generic map — JSON field names are PascalCase (no json tags).
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("JSON unmarshal failed: %v\n  json = %s", err, got)
	}

	// Assert every documented top-level field is present in the output.
	documented := []string{
		// Identity (existing)
		"FirmwareFork", "FirmwareVersion", "FirmwareCommit", "FirmwareDate",
		"HardwareUID", "HardwareName",
		// Identity (new)
		"FirmwareBand", "FirmwareAPIMajor", "FirmwareAPIMinor",
		"FirmwareCommitDirty", "FirmwareOriginGit",
		"HardwareRegion", "HardwareVer", "DeviceInfoKeyStyle",
		// CLI surface (existing)
		"PowerInfoCmd", "HasNFCSubshell", "SubGHzNeedsDev",
		"NFCFlaggedArgs", "SubGHzRxRawHasFilePath",
		// CLI surface (new — architect)
		"JSEngineKind", "HasBLESpam", "HasSubGHzBruteforcer",
		"HasMouseJackerFAP", "HasSeaderFAP", "HasPicopassFAP",
		"HasNFCMagicFAP", "HasMFKeyFAP", "HasMifareNestedFAP",
		"UniversalIRLibraryName",
		// CLI surface (new — research)
		"HasStorageFormatExt", "HasSubGHzEncryptKeeloq", "HasSubGHzChat",
		"HasPsCmd", "HasClearCmd",
		// Storage quirks
		"StorageExtFatLabel", "SnapshotPrefix",
		// Marauder
		"MarauderDetected", "MarauderCompatBand",
	}
	for _, field := range documented {
		if _, ok := m[field]; !ok {
			t.Errorf("JSON missing documented field %q", field)
		}
	}

	// Spot-check a few specific values.
	if v, _ := m["FirmwareFork"].(string); v != "Momentum" {
		t.Errorf("FirmwareFork = %q, want %q", v, "Momentum")
	}
	if v, _ := m["FirmwareBand"].(string); v != "momentum/mntm-dev" {
		t.Errorf("FirmwareBand = %q, want %q", v, "momentum/mntm-dev")
	}
	if v, _ := m["HasBLESpam"].(bool); !v {
		t.Errorf("HasBLESpam should be true")
	}
	if v, _ := m["StorageExtFatLabel"].(string); v != "MOMENTUM" {
		t.Errorf("StorageExtFatLabel = %q, want %q", v, "MOMENTUM")
	}
}

// TestFirmwareIntrospectHandlerNilFlipper verifies the nil-guard in the handler.
func TestFirmwareIntrospectHandlerNilFlipper(t *testing.T) {
	d := &Deps{Flipper: nil}
	_, err := firmwareIntrospectSpec.Handler(context.Background(), d, nil)
	if err == nil {
		t.Fatal("expected error when Flipper is nil")
	}
}

// TestFirmwareIntrospectHandlerNilDeps verifies the nil-guard in the handler.
func TestFirmwareIntrospectHandlerNilDeps(t *testing.T) {
	_, err := firmwareIntrospectSpec.Handler(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("expected error when Deps is nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// refresh=false vs default behaviour
// ─────────────────────────────────────────────────────────────────────────────

// TestFirmwareIntrospectRefreshFalseExplicit verifies that passing
// refresh=false explicitly produces the same JSON as the nil-args default path.
// Both must return the in-memory capability snapshot without hitting the device.
func TestFirmwareIntrospectRefreshFalseExplicit(t *testing.T) {
	caps := flipper.Capabilities{
		FirmwareFork:    "Unleashed",
		FirmwareVersion: "v1.0.0",
		HasBLESpam:      false,
		HasMFKeyFAP:     true,
		HardwareUID:     "AABBCCDDEEFF0011",
	}
	f := flipper.NewForTest(caps)
	d := &Deps{Flipper: f}

	// Default path: nil args → refresh defaults to false.
	defaultOut, err := firmwareIntrospectSpec.Handler(context.Background(), d, nil)
	if err != nil {
		t.Fatalf("default (nil args) handler error: %v", err)
	}

	// Explicit refresh=false path.
	explicitOut, err := firmwareIntrospectSpec.Handler(context.Background(), d, map[string]any{"refresh": false})
	if err != nil {
		t.Fatalf("refresh=false handler error: %v", err)
	}

	if defaultOut != explicitOut {
		t.Errorf("default and refresh=false outputs differ:\n  default:      %s\n  refresh=false: %s",
			defaultOut, explicitOut)
	}

	// Validate both outputs are valid JSON and surface the expected fork value.
	var m map[string]any
	if err := json.Unmarshal([]byte(defaultOut), &m); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if got, _ := m["FirmwareFork"].(string); got != "Unleashed" {
		t.Errorf("FirmwareFork = %q, want %q", got, "Unleashed")
	}
}

// TestFirmwareIntrospectBitmapFields verifies that all boolean capability-bitmap
// fields serialise correctly for both true and false values, ensuring no field is
// silently dropped by an omitempty tag or marshalling oversight.
func TestFirmwareIntrospectBitmapFields(t *testing.T) {
	// All boolean fields set to true.
	allTrue := flipper.Capabilities{
		HasNFCSubshell:         true,
		SubGHzNeedsDev:         true,
		NFCFlaggedArgs:         true,
		SubGHzRxRawHasFilePath: true,
		HasBLESpam:             true,
		HasSubGHzBruteforcer:   true,
		HasMouseJackerFAP:      true,
		HasSeaderFAP:           true,
		HasPicopassFAP:         true,
		HasNFCMagicFAP:         true,
		HasMFKeyFAP:            true,
		HasMifareNestedFAP:     true,
		HasStorageFormatExt:    true,
		HasSubGHzEncryptKeeloq: true,
		HasSubGHzChat:          true,
		HasPsCmd:               true,
		HasClearCmd:            true,
		MarauderDetected:       true,
		FirmwareCommitDirty:    true,
	}

	boolFields := []string{
		"HasNFCSubshell", "SubGHzNeedsDev", "NFCFlaggedArgs", "SubGHzRxRawHasFilePath",
		"HasBLESpam", "HasSubGHzBruteforcer", "HasMouseJackerFAP", "HasSeaderFAP",
		"HasPicopassFAP", "HasNFCMagicFAP", "HasMFKeyFAP", "HasMifareNestedFAP",
		"HasStorageFormatExt", "HasSubGHzEncryptKeeloq", "HasSubGHzChat",
		"HasPsCmd", "HasClearCmd", "MarauderDetected", "FirmwareCommitDirty",
	}

	for _, tc := range []struct {
		label    string
		caps     flipper.Capabilities
		wantTrue bool
	}{
		{"all-true", allTrue, true},
		{"all-false", flipper.Capabilities{}, false},
	} {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			f := flipper.NewForTest(tc.caps)
			d := &Deps{Flipper: f}
			out, err := firmwareIntrospectSpec.Handler(context.Background(), d, nil)
			if err != nil {
				t.Fatalf("handler error: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(out), &m); err != nil {
				t.Fatalf("JSON unmarshal: %v", err)
			}
			for _, field := range boolFields {
				val, ok := m[field]
				if !ok {
					t.Errorf("%s: JSON missing bool field %q", tc.label, field)
					continue
				}
				got, isBool := val.(bool)
				if !isBool {
					t.Errorf("%s: field %q is %T, want bool", tc.label, field, val)
					continue
				}
				if got != tc.wantTrue {
					t.Errorf("%s: field %q = %v, want %v", tc.label, field, got, tc.wantTrue)
				}
			}
		})
	}
}
