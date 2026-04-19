package flipper

import "testing"

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
			name:               "empty input uses stock defaults",
			deviceInfo:         "",
			wantFork:           "",
			wantPowerCmd:       "power_info",
			wantNFCSubshell:    true,
			wantSubGHzDev:      false,
			wantNFCFlaggedArgs: false,
			wantRxRawFilePath:  true,
		},
		{
			name:               "unleashed capitalised",
			deviceInfo:         "firmware_origin_fork          : Unleashed",
			wantFork:           "Unleashed",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  true,
		},
		{
			name:               "unleashed all-lowercase",
			deviceInfo:         "firmware_origin_fork          : unleashed",
			wantFork:           "unleashed",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  true,
		},
		{
			name:               "roguemaster",
			deviceInfo:         "firmware_origin_fork          : RogueMaster",
			wantFork:           "RogueMaster",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    true,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: true,
			wantRxRawFilePath:  true,
		},
		{
			name:               "xtreme capitalised",
			deviceInfo:         "firmware_origin_fork          : Xtreme",
			wantFork:           "Xtreme",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    false,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: false,
			wantRxRawFilePath:  true,
		},
		{
			name:               "xtreme all-lowercase",
			deviceInfo:         "firmware_origin_fork          : xtreme",
			wantFork:           "xtreme",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    false,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: false,
			wantRxRawFilePath:  true,
		},
		{
			name:               "xtreme all-uppercase",
			deviceInfo:         "firmware_origin_fork          : XTREME",
			wantFork:           "XTREME",
			wantPowerCmd:       "info power",
			wantNFCSubshell:    false,
			wantSubGHzDev:      true,
			wantNFCFlaggedArgs: false,
			wantRxRawFilePath:  true,
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
