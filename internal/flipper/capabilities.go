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
	PowerInfoCmd           string // "power_info" | "info power" | "" (unavailable)
	HasNFCSubshell         bool   // `nfc` subshell with `scanner`/`emulate`/... subcommands
	SubGHzNeedsDev         bool   // `subghz tx/rx` requires a trailing `<device>` arg
	NFCFlaggedArgs         bool   // NFC subshell uses flag-based args (-p, -d, -b) instead of positional
	SubGHzRxRawHasFilePath bool   // `subghz rx_raw` accepts a file-path arg (false on Momentum — streams to stdout)
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

	// Set the stock baseline before the switch so new fork cases only need to
	// override the fields that actually differ.
	c.PowerInfoCmd = "power_info"
	c.HasNFCSubshell = true
	c.SubGHzNeedsDev = false
	c.SubGHzRxRawHasFilePath = true

	switch strings.ToLower(c.FirmwareFork) {
	case "unleashed", "roguemaster":
		// Unleashed (and RogueMaster, which is based on Unleashed) dropped the
		// legacy `power_info` command — only `info power` is registered
		// (cli_main_commands.c). All subghz commands that take args also
		// require a trailing <device> index (subghz_cli.c: parse_err ORs
		// both frequency and device_ind results when args is non-empty).
		// The NFC subshell uses the same flag-based parser as Momentum
		// (nfc_cli_command_mfu.c: mfu rdbl -b <n>, mfu wrbl -b <n> -d <hex>).
		c.PowerInfoCmd = "info power"
		c.SubGHzNeedsDev = true
		c.NFCFlaggedArgs = true
	case "xtreme":
		c.PowerInfoCmd = "info power"
		c.HasNFCSubshell = false
		c.SubGHzNeedsDev = true
	case "momentum":
		// Momentum dropped the legacy `power_info` alias — only `info power`
		// is registered (applications/services/cli/cli_main_commands.c in
		// Next-Flip/Momentum-Firmware). Its `subghz rx` requires a mandatory
		// <Device: 0|1> trailing arg (subghz_cli.c → subghz_cli_command_rx).
		//
		// Momentum's NFC subshell uses a flag-based arg parser
		// (nfc_cli_command_processor.c) that rejects positional args.
		// Correct forms: `raw -p iso14a -d <hex>`, `apdu -d <hex>`,
		// `mfu rdbl -b <n>`, `mfu wrbl -b <n> -d <hex>`, `dump -p <protocol>`.
		//
		// Momentum's `subghz rx_raw` streams pulses to stdout and does NOT
		// accept a file-path argument (subghz_cli.c:subghz_cli_command_rx_raw).
		c.PowerInfoCmd = "info power"
		c.SubGHzNeedsDev = true
		c.NFCFlaggedArgs = true
		c.SubGHzRxRawHasFilePath = false
	}
	return c
}
