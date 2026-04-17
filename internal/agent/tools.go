package agent

import "github.com/anthropics/anthropic-sdk-go"

func buildTools() []anthropic.ToolUnionParam {
	return []anthropic.ToolUnionParam{
		// --- Sub-GHz ---
		tool("subghz_transmit",
			"Transmit a saved Sub-GHz signal file (.sub). Use for garage doors, remotes, gate openers, car keys, weather stations, or any device operating on Sub-GHz frequencies. Modded firmware unlocks the full frequency range with no restrictions.",
			props(
				reqProp("file", "string", "Path to .sub file on Flipper SD card, e.g. /ext/subghz/garage.sub"),
			),
			"file",
		),
		tool("subghz_receive",
			"Capture/receive Sub-GHz signals on a specific frequency. Records signals from nearby transmitters. Full spectrum unlocked.",
			props(
				reqProp("frequency", "integer", "Frequency in Hz, e.g. 433920000 for 433.92MHz"),
				optProp("duration_seconds", "integer", "How long to listen (default 30)"),
			),
			"frequency",
		),
		tool("subghz_decode",
			"Decode and analyze a captured Sub-GHz signal file. Shows protocol, frequency, key data.",
			props(
				reqProp("file", "string", "Path to .sub file to decode"),
			),
			"file",
		),
		tool("subghz_bruteforce",
			"Brute force a Sub-GHz signal by replaying with variations. No limits on attempts or frequency.",
			props(
				reqProp("file", "string", "Path to .sub file to use as base"),
				reqProp("frequency", "integer", "Target frequency in Hz"),
				optProp("duration_seconds", "integer", "How long to run (default 60)"),
			),
			"file", "frequency",
		),

		// --- Infrared ---
		tool("ir_transmit",
			"Send a decoded infrared command using protocol, address, and command values. Use for TVs, ACs, projectors, sound systems, or any IR-controlled device.",
			props(
				reqProp("protocol", "string", "IR protocol name, e.g. NEC, Samsung32, RC6, SIRC"),
				reqProp("address", "string", "Address hex value, e.g. 00 00 00 00"),
				reqProp("command", "string", "Command hex value, e.g. 70 00 00 00"),
			),
			"protocol", "address", "command",
		),
		tool("ir_transmit_raw",
			"Send a raw infrared signal with explicit frequency, duty cycle, and timing data.",
			props(
				optProp("frequency", "integer", "Carrier frequency in Hz (default 38000)"),
				optProp("duty_cycle", "number", "Duty cycle 0.0–1.0 (default 0.33)"),
				reqProp("data", "string", "Space-separated timing values in microseconds"),
			),
			"data",
		),
		tool("ir_receive",
			"Capture/learn an infrared signal from a remote control. Point the remote at the Flipper and press a button.",
			props(
				optProp("timeout_seconds", "integer", "How long to wait for a signal (default 30)"),
			),
		),
		tool("ir_bruteforce",
			"Brute force IR codes against a device. Cycles through known protocols to find working commands.",
			props(
				reqProp("file", "string", "Path to .ir brute force database file"),
				optProp("duration_seconds", "integer", "How long to run (default 60)"),
			),
			"file",
		),

		// --- NFC ---
		tool("nfc_detect",
			"Detect an NFC tag/card. Supports MIFARE Classic, MIFARE Ultralight, NTAG, DESFire, EMV bank cards, transit cards, and more. Returns UID, type, and data.",
			props(
				optProp("timeout_seconds", "integer", "How long to wait for a tag (default 30)"),
			),
		),
		tool("nfc_emulate",
			"Emulate a saved NFC tag/card. The Flipper becomes the tag — hold it against a reader.",
			props(
				reqProp("file", "string", "Path to .nfc file on Flipper SD card"),
			),
			"file",
		),
		tool("nfc_subcommand",
			"Run an arbitrary NFC subshell subcommand. Valid subcommands: scanner, emulate, dump, field, raw, apdu, mfu.",
			props(
				reqProp("subcommand", "string", "NFC subcommand to run, e.g. raw, field, apdu"),
				optProp("timeout_seconds", "integer", "How long to wait (default 30)"),
			),
			"subcommand",
		),

		// --- RFID (125kHz) ---
		tool("rfid_read",
			"Read a 125kHz RFID tag/card (building access fobs, prox cards). Returns as soon as a tag is decoded; the timeout is just the max wait. Before calling, tell the user to hold the fob flat against the BACK of the Flipper (LF antenna side). Supports EM4100, HIDProx, Indala, AWID, FDX, and more. For 13.56MHz cards (NFC/MIFARE) use nfc_detect instead; for car remotes use sub-GHz tools.",
			props(
				optProp("mode", "string", "Read mode: normal, indala, ask, psk (default: empty for auto-detect — start here)"),
				optProp("timeout_seconds", "integer", "Max wait in seconds (default 15). Detection returns early; longer timeouts only help when the user is still positioning the fob."),
			),
		),
		tool("rfid_emulate",
			"Emulate an RFID tag by specifying protocol and data directly.",
			props(
				reqProp("protocol", "string", "RFID protocol: EM4100, HIDProx, Indala, AWID, FDX-A, FDX-B, etc."),
				reqProp("data", "string", "Hex data to emulate"),
			),
			"protocol", "data",
		),
		tool("rfid_write",
			"Write data to a writable RFID tag. Clones data onto a blank T5577 or similar tag.",
			props(
				reqProp("protocol", "string", "RFID protocol: EM4100, HIDProx, Indala, AWID, FDX-A, FDX-B, etc."),
				reqProp("data", "string", "Hex data to write"),
			),
			"protocol", "data",
		),

		// --- iButton ---
		tool("ibutton_read",
			"Read an iButton key. Supports Dallas DS1990A, Cyfral, Metakom protocols.",
			props(
				optProp("timeout_seconds", "integer", "How long to wait (default 30)"),
			),
		),
		tool("ibutton_emulate",
			"Emulate an iButton key by specifying protocol and hex data.",
			props(
				reqProp("protocol", "string", "iButton protocol: Dallas, Cyfral, Metakom"),
				reqProp("hex_data", "string", "Hex key data to emulate"),
			),
			"protocol", "hex_data",
		),
		tool("ibutton_write",
			"Write/clone a Dallas iButton key to a writable blank.",
			props(
				reqProp("hex_data", "string", "Hex key data to write (Dallas protocol only)"),
			),
			"hex_data",
		),

		// --- GPIO ---
		tool("gpio_set",
			"Set a GPIO pin high (1) or low (0). Control external hardware, relays, LEDs, motors.",
			props(
				reqProp("pin", "string", "GPIO pin name: PA7, PA6, PA4, PB3, PB2, PC3, PC1, PC0"),
				reqProp("value", "integer", "0 for low, 1 for high"),
			),
			"pin", "value",
		),
		tool("gpio_read",
			"Read the current state of a GPIO pin. Returns high/low and voltage level.",
			props(
				reqProp("pin", "string", "GPIO pin name: PA7, PA6, PA4, PB3, PB2, PC3, PC1, PC0"),
			),
			"pin",
		),

		// --- BadUSB ---
		tool("badusb_run",
			"Execute a BadUSB/Rubber Ducky script. The Flipper acts as a USB keyboard and types commands on the connected computer. No restrictions on payloads.",
			props(
				reqProp("file", "string", "Path to .txt BadUSB script on SD card"),
			),
			"file",
		),

		// --- Loader ---
		tool("list_apps",
			"List every installed Flipper application plus the settings-menu entries. Call this BEFORE loader_open when the target app's availability is uncertain — avoids the silent-failure path where loader_open launches a missing FAP. Returns structured JSON: {apps: [...], settings: [...]}.",
			props(),
		),
		tool("loader_open",
			"Open a Flipper application by name with optional arguments. Use to launch any built-in or FAP app. If you're unsure whether the app is installed, call list_apps first.",
			props(
				reqProp("app_name", "string", "Application name, e.g. NFC, SubGHz, iButton, Bad USB, GPIO"),
				optProp("args", "string", "Optional arguments to pass to the app"),
			),
			"app_name",
		),
		tool("loader_close",
			"Close the currently running Flipper application.",
			props(),
		),

		// --- Input ---
		tool("input_send",
			"Send a synthetic button input event to the Flipper UI.",
			props(
				reqProp("button", "string", "Button: up, down, left, right, ok, back"),
				reqProp("event_type", "string", "Event type: press, release, short, long, repeat"),
			),
			"button", "event_type",
		),

		// --- Storage / File Management ---
		tool("storage_list",
			"List files and directories on the Flipper SD card.",
			props(
				reqProp("path", "string", "Directory path, e.g. /ext/subghz or /ext/nfc"),
			),
			"path",
		),
		tool("storage_read",
			"Read the contents of a file on the Flipper SD card.",
			props(
				reqProp("path", "string", "File path to read"),
			),
			"path",
		),
		tool("storage_delete",
			"Delete a file or directory from the Flipper SD card.",
			props(
				reqProp("path", "string", "Path to delete"),
			),
			"path",
		),
		tool("storage_mkdir",
			"Create a directory on the Flipper SD card.",
			props(
				reqProp("path", "string", "Directory path to create"),
			),
			"path",
		),
		tool("storage_info",
			"Get file/directory info (size, type) from the Flipper SD card.",
			props(
				reqProp("path", "string", "Path to inspect"),
			),
			"path",
		),

		// --- System ---
		tool("system_info",
			"Get Flipper Zero device information: firmware version, hardware revision, uptime, etc.",
			props(),
		),
		tool("power_info",
			"Get battery and power information: charge level, voltage, charging status.",
			props(),
		),
		tool("device_reboot",
			"Reboot the Flipper Zero.",
			props(),
		),
		tool("flipper_raw_cli",
			"Escape hatch: send an arbitrary command directly to the Flipper CLI. Use only when no dedicated tool exists for what you need (e.g., firmware features we haven't wrapped, or commands unique to a specific fork like Xtreme/RogueMaster). High risk — the user will be prompted to approve. Output is returned verbatim.",
			props(
				reqProp("command", "string", "Exact CLI string as typed at >: (e.g., `info power`, `gpio read PA0`, `subghz chat 433920000 0`). Do NOT include a trailing newline."),
			),
		),
		tool("led_set",
			"Set a single Flipper LED channel to a brightness value. Channels: r (red), g (green), b (blue), bl (backlight).",
			props(
				reqProp("channel", "string", "LED channel: r, g, b, bl"),
				reqProp("value", "integer", "Brightness 0-255"),
			),
			"channel", "value",
		),
		tool("vibro",
			"Trigger the Flipper vibration motor.",
			props(
				reqProp("on", "boolean", "true to vibrate, false to stop"),
			),
			"on",
		),

		// --- Device Registry ---
		tool("list_devices",
			"List all named devices from the user's configuration. These are friendly names mapped to signal files (e.g. 'garage' -> /ext/subghz/garage.sub). Use this to discover what the user has set up before trying to control devices by name.",
			props(),
		),
	}
}

// Helper constructors for clean tool definitions.

func tool(name, desc string, properties map[string]interface{}, required ...string) anthropic.ToolUnionParam {
	input := anthropic.ToolInputSchemaParam{
		Properties: properties,
	}
	if len(required) > 0 {
		input.Required = required
	}
	return anthropic.ToolUnionParam{
		OfTool: &anthropic.ToolParam{
			Name:        name,
			Description: anthropic.String(desc),
			InputSchema: input,
		},
	}
}

func props(items ...map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{})
	for _, item := range items {
		for k, v := range item {
			merged[k] = v
		}
	}
	return merged
}

func reqProp(name, typ, desc string) map[string]interface{} {
	return map[string]interface{}{
		name: map[string]interface{}{
			"type":        typ,
			"description": desc,
		},
	}
}

func optProp(name, typ, desc string) map[string]interface{} {
	return reqProp(name, typ, desc) // optionality is handled by not putting it in required
}

// ToolCatalogEntry pairs a registered tool's name with its description.
// Used by /tools to render each entry with a short description alongside
// the name.
type ToolCatalogEntry struct {
	Name        string
	Description string
}

// ToolCatalog returns every registered tool's name + description, in the
// same builder order as ToolNames. Marauder/WiFi entries are appended when
// hasMarauder is true.
func ToolCatalog(hasMarauder bool) []ToolCatalogEntry {
	tools := buildTools()
	tools = append(tools, buildGenTools()...)
	if hasMarauder {
		tools = append(tools, buildMarauderTools()...)
	}
	out := make([]ToolCatalogEntry, 0, len(tools))
	for _, t := range tools {
		if t.OfTool == nil {
			continue
		}
		desc := ""
		if t.OfTool.Description.Valid() {
			desc = t.OfTool.Description.Value
		}
		out = append(out, ToolCatalogEntry{Name: t.OfTool.Name, Description: desc})
	}
	return out
}
