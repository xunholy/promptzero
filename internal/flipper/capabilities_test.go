package flipper

import (
	"encoding/json"
	"reflect"
	"testing"
)

// ── Existing CLI-surface tests (updated for Q1/Q2/Q3 stock-default corrections)
//
// Stock defaults after firmware-matrix.md corrections:
//   PowerInfoCmd           = "info power"  (was "power_info"  — Q1)
//   SubGHzRxRawHasFilePath = false         (was true          — Q2)
//   NFCFlaggedArgs         = true          (was false         — Q3)
//
// All per-fork non-default values are unchanged.

func TestDetectCapabilities(t *testing.T) {
	tests := []struct {
		name               string
		deviceInfo         string
		wantFork           string
		wantPowerCmd       string
		wantNFCSubshell    bool
		wantSubGHzDev      bool
		wantNFCFlaggedArgs bool
		wantRxRawFilePath  bool
	}{
		{
			// Q1: PowerInfoCmd is now "info power" even for unknown forks.
			// Q2: SubGHzRxRawHasFilePath is now false for unknown forks.
			// Q3: NFCFlaggedArgs gate: APIMajor=0 (unknown) is < 80, so stock
			//     default stays false (safe for old/unknown devices). Only
			//     explicit APIMajor >= 80 (OFW 0.103+ / 1.x) gives true.
			name:               "empty input uses stock defaults",
			deviceInfo:         "",
			wantFork:           "",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      false,
			wantNFCFlaggedArgs: false,
			wantRxRawFilePath:  false,
		},
		{
			name:               "unleashed capitalised",
			deviceInfo:         "firmware_origin_fork          : Unleashed",
			wantFork:           "Unleashed",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  false,
		},
		{
			name:               "unleashed all-lowercase",
			deviceInfo:         "firmware_origin_fork          : unleashed",
			wantFork:           "unleashed",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  false,
		},
		{
			name:               "roguemaster",
			deviceInfo:         "firmware_origin_fork          : RogueMaster",
			wantFork:           "RogueMaster",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  false,
		},
		{
			name:               "xtreme capitalised",
			deviceInfo:         "firmware_origin_fork          : Xtreme",
			wantFork:           "Xtreme",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    false,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true, // irrelevant for Xtreme (no subshell), but flag keeps its default
			wantRxRawFilePath:  false,
		},
		{
			name:               "xtreme all-lowercase",
			deviceInfo:         "firmware_origin_fork          : xtreme",
			wantFork:           "xtreme",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    false,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  false,
		},
		{
			name:               "xtreme all-uppercase",
			deviceInfo:         "firmware_origin_fork          : XTREME",
			wantFork:           "XTREME",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    false,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  false,
		},
		{
			name:               "momentum capitalised",
			deviceInfo:         "firmware_origin_fork          : Momentum",
			wantFork:           "Momentum",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  false,
		},
		{
			name:               "momentum all-lowercase",
			deviceInfo:         "firmware_origin_fork          : momentum",
			wantFork:           "momentum",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  false,
		},
		{
			name:               "momentum all-uppercase",
			deviceInfo:         "firmware_origin_fork          : MOMENTUM",
			wantFork:           "MOMENTUM",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := detectCapabilities(tt.deviceInfo)
			if caps.FirmwareFork != tt.wantFork {
				t.Errorf("FirmwareFork = %q, want %q", caps.FirmwareFork, tt.wantFork)
			}
			if caps.PowerInfoCmd != tt.wantPowerCmd {
				t.Errorf("PowerInfoCmd = %q, want %q", caps.PowerInfoCmd, tt.wantPowerCmd)
			}
			if caps.HasNFCSubshell != tt.wantNFCSubshell {
				t.Errorf("HasNFCSubshell = %v, want %v", caps.HasNFCSubshell, tt.wantNFCSubshell)
			}
			if caps.SubGHzNeedsDev != tt.wantSubGHzDev {
				t.Errorf("SubGHzNeedsDev = %v, want %v", caps.SubGHzNeedsDev, tt.wantSubGHzDev)
			}
			if caps.NFCFlaggedArgs != tt.wantNFCFlaggedArgs {
				t.Errorf("NFCFlaggedArgs = %v, want %v", caps.NFCFlaggedArgs, tt.wantNFCFlaggedArgs)
			}
			if caps.SubGHzRxRawHasFilePath != tt.wantRxRawFilePath {
				t.Errorf("SubGHzRxRawHasFilePath = %v, want %v", caps.SubGHzRxRawHasFilePath, tt.wantRxRawFilePath)
			}
		})
	}
}

// ── Full fixture tests (firmware-matrix.md §5) ────────────────────────────────
//
// One TestDetectCapabilities_* per fixture from the firmware matrix. Each
// asserts FirmwareFork, FirmwareBand, and a representative subset of the
// new flags (keeping the test readable per architect §C.4 guidance).

// ─── 5.1 OFW fixtures ────────────────────────────────────────────────────────

const ofwV103Fixture = `hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_otp_ver              : 2
hardware_timestamp            : 1641139200
hardware_target               : 7
hardware_body                 : 0
hardware_connect              : 0
hardware_display              : 0
hardware_color                : 0
hardware_name                 : Flipper
hardware_uid                  : 0000000000000000
firmware_commit               : 6a9c31b2
firmware_commit_dirty         : 0
firmware_branch               : release
firmware_branch_num           : 7201
firmware_version              : 0.103.1
firmware_build_date           : 27-02-2025
firmware_target               : 7
firmware_api_major            : 82
firmware_api_minor            : 3
firmware_origin_fork          :
firmware_origin_git           :
radio_alive                   : 1
radio_mode                    : 0
radio_stack_major             : 1
radio_stack_minor             : 17
radio_stack_sub               : 3
radio_stack_branch            : 0
radio_stack_release           : 0
radio_ble_mac                 : 802b50deadbf`

const ofwV1Fixture = `hardware_model                : Flipper Zero
hardware_region               : EU
hardware_region_provisioned   : 1
hardware_region_builtin       : 1
hardware_ver                  : 13
hardware_name                 : Flipper
hardware_uid                  : 0000000000000001
firmware_commit               : aabbccdd
firmware_commit_dirty         : 0
firmware_branch               : release
firmware_branch_num           : 8000
firmware_version              : 1.0.0
firmware_build_date           : 15-03-2026
firmware_api_major            : 85
firmware_api_minor            : 0
firmware_origin_fork          :
radio_ble_mac                 : 802b50deadc0`

const ofwDevFixture = `hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_name                 : DevKit01
hardware_uid                  : 0000000000000002
firmware_commit               : deadbeef
firmware_branch               : dev
firmware_branch_num           : 8127
firmware_version              : dev
firmware_build_date           : 20-04-2026
firmware_api_major            : 85
firmware_api_minor            : 2
firmware_origin_fork          : `

// ─── 5.2 Unleashed fixtures ──────────────────────────────────────────────────

const unleashed086Fixture = `hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_name                 : Fishy
hardware_uid                  : 0000000000000003
firmware_commit               : 1a2b3c4d
firmware_branch               : unlshd-086
firmware_branch_num           : 9120
firmware_version              : unlshd-086
firmware_build_date           : 08-03-2025
firmware_api_major            : 87
firmware_api_minor            : 6
firmware_origin_fork          : Unleashed
firmware_origin_git           : https://github.com/DarkFlippers/unleashed-firmware
radio_ble_mac                 : 802b50deadcc`

const unleashed082Fixture = `hardware_model                : Flipper Zero
hardware_region               : 0
hardware_ver                  : 13
hardware_name                 : Pepper
hardware_uid                  : 0000000000000004
firmware_commit               : 5e6f7a8b
firmware_branch               : unlshd-082
firmware_version              : unlshd-082
firmware_build_date           : 16-07-2024
firmware_api_major            : 86
firmware_api_minor            : 5
firmware_origin_fork          : unleashed`

const unleashedDevFixture = `hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : Unfishy
hardware_uid                  : 0000000000000005
firmware_commit               : 9c0d1e2f
firmware_branch               : dev
firmware_version              : dev
firmware_build_date           : 01-04-2026
firmware_api_major            : 87
firmware_api_minor            : 8
firmware_origin_fork          : Unleashed
firmware_origin_git           : https://github.com/DarkFlippers/unleashed-firmware`

// ─── 5.3 Momentum fixtures ───────────────────────────────────────────────────

const momentumDevFixture = `hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_otp_ver              : 2
hardware_timestamp            : 1672531200
hardware_name                 : Unholy
hardware_uid                  : 0000000000000006
firmware_commit               : c51cf345
firmware_commit_dirty         : 0
firmware_branch               : dev
firmware_branch_num           : 4521
firmware_version              : mntm-dev
firmware_build_date           : 09-03-2026
firmware_api_major            : 79
firmware_api_minor            : 2
firmware_origin_fork          : Momentum
firmware_origin_git           : https://github.com/Next-Flip/Momentum-Firmware
radio_ble_mac                 : 802b50dec0de`

const momentum012Fixture = `hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : Momo
hardware_uid                  : 0000000000000007
firmware_commit               : a1b2c3d4
firmware_commit_dirty         : 0
firmware_branch               : mntm-012
firmware_version              : mntm-012
firmware_build_date           : 31-12-2025
firmware_api_major            : 79
firmware_api_minor            : 0
firmware_origin_fork          : Momentum
firmware_origin_git           : https://github.com/Next-Flip/Momentum-Firmware`

const momentumLegacyFixture = `hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : OldMomo
hardware_uid                  : 0000000000000008
firmware_commit               : 00ff11ee
firmware_branch               : mntm-0.29
firmware_version              : 0.29.0
firmware_build_date           : 15-02-2024
firmware_api_major            : 66
firmware_api_minor            : 4
firmware_origin_fork          : Momentum`

// ─── 5.4 Xtreme fixtures ─────────────────────────────────────────────────────

const xtreme0053Fixture = `hardware_model                : Flipper Zero
hardware_region               : 0
hardware_ver                  : 13
hardware_name                 : XtremeCat
hardware_uid                  : 0000000000000009
firmware_commit               : ff00aa11
firmware_branch               : dev
firmware_branch_num           : 3200
firmware_version              : XFW-0053_02022024
firmware_build_date           : 02-02-2024
firmware_api_major            : 70
firmware_api_minor            : 2
firmware_origin_fork          : Xtreme`

const xtremeLowerFixture = `hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : lowX
hardware_uid                  : 000000000000000a
firmware_commit               : ee22dd33
firmware_version              : XFW-0052_09122023
firmware_build_date           : 09-12-2023
firmware_api_major            : 70
firmware_origin_fork          : xtreme`

const xtremeUpperFixture = `hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : SHOUTX
hardware_uid                  : 000000000000000b
firmware_commit               : aa11bb22
firmware_version              : XFW-0051_01092023
firmware_build_date           : 01-09-2023
firmware_api_major            : 70
firmware_origin_fork          : XTREME`

// ─── 5.5 RogueMaster fixtures ────────────────────────────────────────────────

const rm0201Fixture = `hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_name                 : RogueOne
hardware_uid                  : 000000000000000c
firmware_commit               : 925311a0
firmware_branch               : 420
firmware_version              : RM0201-1726-0.420.0-925311a
firmware_build_date           : 01-02-2025
firmware_api_major            : 87
firmware_api_minor            : 6
firmware_origin_fork          : RogueMaster
firmware_origin_git           : https://github.com/RogueMaster/flipperzero-firmware-wPlugins`

const rm0423Fixture = `hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : RM2
hardware_uid                  : 000000000000000d
firmware_commit               : 995f718b
firmware_branch               : 420
firmware_version              : RM0423-0149-0.420.0-995f718
firmware_build_date           : 23-04-2025
firmware_api_major            : 87
firmware_api_minor            : 7
firmware_origin_fork          : RogueMaster
firmware_origin_git           : https://github.com/RogueMaster/flipperzero-firmware-wPlugins`

const rm0115Fixture = `hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : RogueThree
hardware_uid                  : 000000000000000e
firmware_commit               : 73cef7f2
firmware_version              : RM0115-2126-0.420.0-73cef7f
firmware_build_date           : 15-01-2025
firmware_api_major            : 87
firmware_api_minor            : 5
firmware_origin_fork          : roguemaster
firmware_origin_git           : https://github.com/RogueMaster/flipperzero-firmware-wPlugins`

// ─── Fixture registry ────────────────────────────────────────────────────────

var fixtureMap = map[string]string{
	"ofw_0_103_1_stable":         ofwV103Fixture,
	"ofw_1_0_0_early_2026":       ofwV1Fixture,
	"ofw_dev_branch":             ofwDevFixture,
	"unleashed_unlshd_086":       unleashed086Fixture,
	"unleashed_unlshd_082_older": unleashed082Fixture,
	"unleashed_dev_build":        unleashedDevFixture,
	"momentum_mntm_dev_live":     momentumDevFixture,
	"momentum_mntm_012_release":  momentum012Fixture,
	"momentum_legacy_0_29_0":     momentumLegacyFixture,
	"xtreme_xfw_0053_final":      xtreme0053Fixture,
	"xtreme_lowercase":           xtremeLowerFixture,
	"xtreme_uppercase":           xtremeUpperFixture,
	"roguemaster_rm_0201":        rm0201Fixture,
	"roguemaster_rm_0423":        rm0423Fixture,
	"roguemaster_rm_0115":        rm0115Fixture,
}

// TestDetectCapabilitiesFull runs all 15 firmware-matrix.md §5 fixtures,
// asserting FirmwareFork, FirmwareBand, and 3+ fork-specific flags each.
func TestDetectCapabilitiesFull(t *testing.T) {
	type wantShape struct {
		fork   string
		band   string
		checks func(t *testing.T, c Capabilities)
	}

	fixtures := map[string]wantShape{
		"ofw_0_103_1_stable": {
			fork: "",
			band: "stock/0.103.x",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "PowerInfoCmd", c.PowerInfoCmd, "info power")
				assertEqual(t, "HasNFCSubshell", c.HasNFCSubshell, true)
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, false) // API 82 < 85
				assertEqual(t, "SubGHzRxRawHasFilePath", c.SubGHzRxRawHasFilePath, false)
				assertEqual(t, "NFCFlaggedArgs", c.NFCFlaggedArgs, true)
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 82)
				assertEqual(t, "FirmwareAPIMinor", c.FirmwareAPIMinor, 3)
			},
		},
		"ofw_1_0_0_early_2026": {
			fork: "",
			band: "stock/1.0.x",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true) // API 85 >= 85
				assertEqual(t, "HasNFCSubshell", c.HasNFCSubshell, true)
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 85)
				assertEqual(t, "HardwareRegion", c.HardwareRegion, "EU")
			},
		},
		"ofw_dev_branch": {
			fork: "",
			band: "stock/dev",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true) // API 85
				assertEqual(t, "NFCFlaggedArgs", c.NFCFlaggedArgs, true)
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 85)
			},
		},
		"unleashed_unlshd_086": {
			fork: "Unleashed",
			band: "unleashed/unlshd-086",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true)
				assertEqual(t, "NFCFlaggedArgs", c.NFCFlaggedArgs, true)
				assertEqual(t, "HasMFKeyFAP", c.HasMFKeyFAP, true)
				assertEqual(t, "HasPicopassFAP", c.HasPicopassFAP, true)
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 87)
			},
		},
		"unleashed_unlshd_082_older": {
			fork: "unleashed",
			band: "unleashed/unlshd-082",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true)
				assertEqual(t, "HasMFKeyFAP", c.HasMFKeyFAP, true)
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 86)
			},
		},
		"unleashed_dev_build": {
			fork: "Unleashed",
			band: "unleashed/dev",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true)
				assertEqual(t, "HasSubGHzBruteforcer", c.HasSubGHzBruteforcer, true)
				assertEqual(t, "HasNFCMagicFAP", c.HasNFCMagicFAP, true)
			},
		},
		"momentum_mntm_dev_live": {
			fork: "Momentum",
			band: "momentum/mntm-dev",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true)
				assertEqual(t, "NFCFlaggedArgs", c.NFCFlaggedArgs, true)
				assertEqual(t, "SubGHzRxRawHasFilePath", c.SubGHzRxRawHasFilePath, false)
				assertEqual(t, "HasBLESpam", c.HasBLESpam, true)
				assertEqual(t, "StorageExtFatLabel", c.StorageExtFatLabel, "MOMENTUM")
				assertEqual(t, "UniversalIRLibraryName", c.UniversalIRLibraryName, "infrared/assets")
			},
		},
		"momentum_mntm_012_release": {
			fork: "Momentum",
			band: "momentum/mntm-release",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "StorageExtFatLabel", c.StorageExtFatLabel, "MOMENTUM")
				assertEqual(t, "HasSeaderFAP", c.HasSeaderFAP, true)
				// Verified false against real momentum/mntm-dev hardware
				// (2026-05-30): `ps` is absent from the CLI command table;
				// `top` is the universal verb. See capabilities.go.
				assertEqual(t, "HasPsCmd", c.HasPsCmd, false)
			},
		},
		"momentum_legacy_0_29_0": {
			fork: "Momentum",
			band: "momentum/mntm-stable-legacy",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "NFCFlaggedArgs", c.NFCFlaggedArgs, true) // momentum always true
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true)
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 66)
			},
		},
		"xtreme_xfw_0053_final": {
			fork: "Xtreme",
			band: "xtreme/xfw-0053",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "HasNFCSubshell", c.HasNFCSubshell, false)
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true)
				assertEqual(t, "HasBLESpam", c.HasBLESpam, true)
				assertEqual(t, "JSEngineKind", c.JSEngineKind, "mjs")
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 70)
			},
		},
		"xtreme_lowercase": {
			fork: "xtreme",
			band: "xtreme/xfw-0052",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "HasNFCSubshell", c.HasNFCSubshell, false)
				assertEqual(t, "HasNFCMagicFAP", c.HasNFCMagicFAP, true)
				assertEqual(t, "HasMouseJackerFAP", c.HasMouseJackerFAP, false) // Xtreme doesn't ship it
			},
		},
		"xtreme_uppercase": {
			fork: "XTREME",
			band: "xtreme/xfw-0051",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "HasNFCSubshell", c.HasNFCSubshell, false)
				assertEqual(t, "HasPsCmd", c.HasPsCmd, true)
				assertEqual(t, "HasSeaderFAP", c.HasSeaderFAP, false) // Xtreme doesn't ship Seader
			},
		},
		"roguemaster_rm_0201": {
			fork: "RogueMaster",
			band: "roguemaster/rm-0201",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true)
				assertEqual(t, "NFCFlaggedArgs", c.NFCFlaggedArgs, true)
				assertEqual(t, "HasBLESpam", c.HasBLESpam, true)
				assertEqual(t, "HasMFKeyFAP", c.HasMFKeyFAP, true)
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 87)
			},
		},
		"roguemaster_rm_0423": {
			fork: "RogueMaster",
			band: "roguemaster/rm-0423",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				assertEqual(t, "SubGHzNeedsDev", c.SubGHzNeedsDev, true)
				assertEqual(t, "HasSeaderFAP", c.HasSeaderFAP, true)
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 87)
			},
		},
		"roguemaster_rm_0115": {
			fork: "roguemaster",
			band: "roguemaster/rm-0115",
			checks: func(t *testing.T, c Capabilities) {
				t.Helper()
				// Lowercase fork string still resolves to the correct band.
				assertEqual(t, "HasNFCMagicFAP", c.HasNFCMagicFAP, true)
				assertEqual(t, "HasSubGHzBruteforcer", c.HasSubGHzBruteforcer, true)
				assertEqual(t, "FirmwareAPIMajor", c.FirmwareAPIMajor, 87)
			},
		},
	}

	for name, want := range fixtures {
		name, want := name, want
		t.Run(name, func(t *testing.T) {
			raw, ok := fixtureMap[name]
			if !ok {
				t.Fatalf("fixture %q not found in fixtureMap", name)
			}
			caps := detectCapabilities(raw)

			if caps.FirmwareFork != want.fork {
				t.Errorf("FirmwareFork = %q, want %q", caps.FirmwareFork, want.fork)
			}
			if caps.FirmwareBand != want.band {
				t.Errorf("FirmwareBand = %q, want %q", caps.FirmwareBand, want.band)
			}
			want.checks(t, caps)
		})
	}
}

// TestCapabilitiesJSONRoundTrip verifies that the Capabilities struct
// survives a Marshal → Unmarshal round-trip with deep equality.
func TestCapabilitiesJSONRoundTrip(t *testing.T) {
	original := detectCapabilities(momentumDevFixture)

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var restored Capabilities
	if err := json.Unmarshal(b, &restored); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(original, restored) {
		t.Errorf("round-trip mismatch:\n  original = %+v\n  restored = %+v", original, restored)
	}
}

// TestResolveBand covers the §3.6 band resolution table in isolation.
func TestResolveBand(t *testing.T) {
	tests := []struct {
		fork    string
		version string
		want    string
	}{
		// OFW
		{"", "0.82.3", "stock/0.82.x"},
		{"", "0.103.1", "stock/0.103.x"},
		{"", "1.0.0", "stock/1.0.x"},
		{"", "dev", "stock/dev"},
		// Unleashed
		{"Unleashed", "unlshd-085", "unleashed/unlshd-085"},
		{"Unleashed", "unlshd-086", "unleashed/unlshd-086"},
		{"Unleashed", "dev", "unleashed/dev"},
		// Momentum
		{"Momentum", "mntm-dev", "momentum/mntm-dev"},
		{"Momentum", "mntm-dev-abc123", "momentum/mntm-dev"}, // dev with sha suffix
		{"Momentum", "mntm-012", "momentum/mntm-release"},
		{"Momentum", "0.29.0", "momentum/mntm-stable-legacy"},
		// Xtreme
		{"Xtreme", "XFW-0053_02022024", "xtreme/xfw-0053"},
		{"xtreme", "XFW-0052_09122023", "xtreme/xfw-0052"},
		{"XTREME", "XFW-0051_01092023", "xtreme/xfw-0051"},
		// RogueMaster
		{"RogueMaster", "RM0201-1726-0.420.0-925311a", "roguemaster/rm-0201"},
		{"RogueMaster", "RM0423-0149-0.420.0-995f718", "roguemaster/rm-0423"},
		{"roguemaster", "RM0115-2126-0.420.0-73cef7f", "roguemaster/rm-0115"},
	}

	for _, tt := range tests {
		got := resolveBand(tt.fork, tt.version)
		if got != tt.want {
			t.Errorf("resolveBand(%q, %q) = %q, want %q", tt.fork, tt.version, got, tt.want)
		}
	}
}

// assertEqual is a type-safe equality helper for capability field checks.
func assertEqual[T comparable](t *testing.T, field string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", field, got, want)
	}
}
