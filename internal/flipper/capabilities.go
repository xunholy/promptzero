package flipper

import (
	"strings"
)

// Capabilities captures the firmware-specific CLI surface of the connected
// Flipper, detected from `device_info` at connect time. Different custom
// firmwares (stock, Unleashed, RogueMaster, Xtreme, ...) expose slightly
// different CLI commands; wrappers branch on these flags to stay portable.
type Capabilities struct {
	// Identity
	FirmwareFork    string // "" (stock), "Xtreme", "Unleashed", "RogueMaster", ...
	FirmwareVersion string
	FirmwareCommit  string
	FirmwareDate    string
	HardwareUID     string
	HardwareName    string // user-settable dolphin name

	// CLI surface
	PowerInfoCmd   string // "power_info" | "info power" | "" (unavailable)
	HasNFCSubshell bool   // `nfc` subshell with `scanner`/`emulate`/... subcommands
	SubGHzNeedsDev bool   // `subghz tx/rx` requires a trailing `<device>` arg
}

// FriendlyFork returns a display-ready fork name, falling back to "stock"
// when the fork field is empty.
func (c Capabilities) FriendlyFork() string {
	if c.FirmwareFork == "" {
		return "stock"
	}
	return c.FirmwareFork
}

// detectCapabilities parses `device_info` output (newline-separated
// "key: value" pairs) and applies known-quirk rules per fork.
func detectCapabilities(deviceInfo string) Capabilities {
	c := Capabilities{}
	for _, raw := range strings.Split(deviceInfo, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "firmware_origin_fork":
			c.FirmwareFork = val
		case "firmware_version":
			c.FirmwareVersion = val
		case "firmware_commit":
			c.FirmwareCommit = val
		case "firmware_build_date":
			c.FirmwareDate = val
		case "hardware_uid":
			c.HardwareUID = val
		case "hardware_name":
			c.HardwareName = val
		}
	}

	// Set the stock/Unleashed baseline before the switch so new fork cases
	// only need to override the fields that actually differ.
	c.PowerInfoCmd = "power_info"
	c.HasNFCSubshell = true
	c.SubGHzNeedsDev = false

	switch strings.ToLower(c.FirmwareFork) {
	case "xtreme":
		c.PowerInfoCmd = "info power"
		c.HasNFCSubshell = false
		c.SubGHzNeedsDev = true
	case "momentum":
		// Momentum dropped the legacy `power_info` alias — only `info power`
		// is registered (see applications/services/cli/cli_main_commands.c
		// in Next-Flip/Momentum-Firmware). NFC/SubGHz surface otherwise
		// tracks the stock/Unleashed side.
		c.PowerInfoCmd = "info power"
	}
	return c
}
