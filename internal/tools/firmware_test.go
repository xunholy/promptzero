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
