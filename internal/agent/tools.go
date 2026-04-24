package agent

import (
	"encoding/json"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/toolctx"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
)

func buildTools() []anthropic.ToolUnionParam {
	// Registry-backed prepass: emit one entry per registered Spec (and per
	// Alias) so the LLM sees every migrated tool. The legacy slice below
	// covers tools not yet in the registry. Wave 5 collapses both into one.
	var regTools []anthropic.ToolUnionParam
	for _, spec := range toolsreg.All() {
		propsMap := schemaToProps(spec.Schema)
		regTools = append(regTools, tool(spec.Name, spec.Description, propsMap, spec.Required...))
		for _, alias := range spec.Aliases {
			regTools = append(regTools, tool(alias, spec.Description, propsMap, spec.Required...))
		}
	}

	legacy := []anthropic.ToolUnionParam{
		// --- Sub-GHz ---
		toolEx("subghz_transmit",
			"Transmit a saved Sub-GHz signal file (.sub). Use for garage doors, remotes, gate openers, car keys, weather stations, or any device operating on Sub-GHz frequencies. Modded firmware unlocks the full frequency range with no restrictions.",
			props(
				reqProp("file", "string", "Path to .sub file on Flipper SD card, e.g. /ext/subghz/garage.sub"),
			),
			[]ToolExample{
				{Input: `{"file":"/ext/subghz/garage.sub"}`, Note: "replay a saved garage-door capture"},
				{Input: `{"file":"/ext/subghz/car_fob.sub"}`, Note: "re-transmit a rolling-code car key capture"},
			},
			"file",
		),
		toolEx("subghz_receive",
			"Capture/receive Sub-GHz signals on a specific frequency. Records signals from nearby transmitters. Full spectrum unlocked.",
			props(
				reqProp("frequency", "integer", "Frequency in Hz, e.g. 433920000 for 433.92MHz"),
				optProp("duration_seconds", "integer", "How long to listen (default 30)"),
			),
			[]ToolExample{
				{Input: `{"frequency":433920000,"duration_seconds":15}`, Note: "common garage-door band, 15 s sweep"},
				{Input: `{"frequency":315000000,"duration_seconds":30}`, Note: "common car-key band, longer sweep"},
			},
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
		tool("nfc_read_save",
			"Scan an NFC tag and save it to the SD card as /ext/nfc/<name>.nfc. This is the default tool for operator requests like 'scan this fob', 'read the badge', or 'save this card'. Does a full NFCDetect, constructs a valid .nfc file (UID + ATQA + SAK, device-type-aware), runs the static verifier, and writes via the same snapshot/rewind pipeline as the parametric builders. Works for Classic 1K/4K, NTAG213/215/216, Ultralight. For high-security badges where sector keys are required for full block reads, the UID-only save is still useful as a first pass — chain with loader_mfkey / loader_mifare_nested for key recovery.",
			props(
				optProp("name", "string", "Output filename stem (default: scanned_<uid>). Result lands at /ext/nfc/<name>.nfc"),
				optProp("path", "string", "Full SD path override — when set, takes precedence over name"),
				optProp("timeout_seconds", "integer", "How long to wait for a tag (default 15 — shorter than nfc_detect to keep the interactive flow snappy)"),
				optProp("verify_bypass", "boolean", "Skip the static verifier block on high/critical findings"),
			),
		),
		toolEx("nfc_emulate",
			"Emulate a saved NFC tag/card. The Flipper becomes the tag — hold it against a reader.",
			props(
				reqProp("file", "string", "Path to .nfc file on Flipper SD card"),
			),
			[]ToolExample{
				{Input: `{"file":"/ext/nfc/badge.nfc"}`, Note: "replay a previously captured MIFARE access badge"},
			},
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
		toolEx("rfid_write",
			"Write data to a writable RFID tag. Clones data onto a blank T5577 or similar tag.",
			props(
				reqProp("protocol", "string", "RFID protocol: EM4100, HIDProx, Indala, AWID, FDX-A, FDX-B, etc."),
				reqProp("data", "string", "Hex data to write"),
			),
			[]ToolExample{
				{Input: `{"protocol":"EM4100","data":"1A2B3C4D5E"}`, Note: "clone a captured 40-bit EM4100 fob onto a T5577 blank"},
			},
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

		// --- BadUSB ---
		toolEx("badusb_run",
			"Execute a BadUSB/Rubber Ducky script. The Flipper acts as a USB keyboard and types commands on the connected computer. No restrictions on payloads.",
			props(
				reqProp("file", "string", "Path to .txt BadUSB script on SD card"),
			),
			[]ToolExample{
				{Input: `{"file":"/ext/badusb/demo.txt"}`, Note: "execute a generated or saved DuckyScript payload"},
			},
			"file",
		),
		tool("badusb_validate",
			"Dry-run a BadUSB/DuckyScript payload through the pre-flight validator without executing it. Flags rm -rf /, reverse shells, persistence, defense-disable, and other dangerous patterns. Returns a Severity (info|warn|critical) and the list of findings with line numbers. Use before badusb_run to preview what a script will do.",
			props(
				reqProp("file", "string", "Path to .txt BadUSB script on SD card"),
			),
			"file",
		),

		// --- Sub-GHz (extended primitives) ---
		tool("subghz_tx_key",
			"Transmit a raw Sub-GHz key on a specific frequency without needing a saved .sub file. Use for replay attacks, custom codes, and protocol experimentation. Xtreme firmware auto-appends the internal-radio device arg. Hardware: use the internal CC1101 — no antenna module needed.",
			props(
				reqProp("key_hex", "string", "Key bytes as hex, e.g. 'F00F00AA'"),
				reqProp("frequency", "integer", "Frequency in Hz, e.g. 433920000"),
				reqProp("te", "integer", "Timing base in microseconds (protocol-dependent, e.g. 400 for common OOK remotes)"),
				reqProp("repeat", "integer", "Repeat count, typically 3-10"),
			),
			"key_hex", "frequency", "te", "repeat",
		),
		tool("subghz_rx_raw",
			"Stream raw Sub-GHz pulse data to the return value (Momentum firmware only). Returns captured pulses as a string; use storage_write to save as a .sub file if persistence is needed. Not available on stock/Unleashed/Xtreme — use subghz_receive there.",
			props(
				optProp("frequency", "integer", "Frequency in Hz (defaults to firmware last-used)"),
				optProp("duration_seconds", "integer", "Capture duration (default 30)"),
			),
			"",
		),
		tool("subghz_chat",
			"Join an interactive Sub-GHz text chat on the given frequency — the Flipper transmits on every keystroke until the duration elapses. Actively on-air; ensure the frequency is license-legal in the user's region.",
			props(
				reqProp("frequency", "integer", "Frequency in Hz, e.g. 433920000"),
				optProp("duration_seconds", "integer", "How long to stay in the chat (default 60)"),
			),
			"frequency",
		),

		// --- Infrared (extended primitives) ---
		tool("ir_decode_file",
			"Decode a saved .ir file and return the parsed remote entries (protocol, address, command per button). Read-only; use this before ir_transmit to inspect what a library file actually contains.",
			props(
				reqProp("path", "string", "Path to the .ir file, e.g. /ext/infrared/tv.ir"),
			),
			"path",
		),
		tool("ir_universal_list",
			"List the button entries inside a universal-remote library file (TVs, ACs, audio, projectors) so the agent can see the valid signal names before calling ir_universal transmit. Read-only.",
			props(
				reqProp("library", "string", "Universal library name, e.g. tv, ac, audio, projector"),
			),
			"library",
		),

		// --- NFC (extended subshell primitives) ---
		tool("nfc_raw_frame",
			"Send a raw ISO14443 frame to a field-held NFC tag and return its response. Use for protocol-level experimentation (custom commands, non-standard tags). Fork-gated: requires the nfc CLI subshell (stock / Unleashed / RogueMaster). Not available on Xtreme. Hardware: keep the tag against the back of the Flipper while the command runs.",
			props(
				reqProp("hex", "string", "Raw frame bytes as hex, e.g. '30 04' to read block 4"),
				optProp("timeout_seconds", "integer", "How long to wait for the response (default 10)"),
			),
			"hex",
		),
		tool("nfc_apdu",
			"Send an ISO7816 APDU command to a contactless smart card (EMV, DESFire, applet-hosting cards). Fork-gated on the nfc CLI subshell. Hardware: hold the card against the back of the Flipper.",
			props(
				reqProp("hex", "string", "APDU as hex, e.g. '00A404000E325041592E5359532E4444463031' (SELECT PPSE)"),
				optProp("timeout_seconds", "integer", "How long to wait for the response (default 10)"),
			),
			"hex",
		),
		tool("nfc_mfu_rdbl",
			"Read a single page (4 bytes) from a MIFARE Ultralight / NTAG tag via the nfc subshell. Use to sample tag contents before dumping. Fork-gated.",
			props(
				reqProp("page", "integer", "Page number to read (0-based)"),
				optProp("timeout_seconds", "integer", "How long to wait (default 10)"),
			),
			"page",
		),
		tool("nfc_mfu_wrbl",
			"Write 4 bytes of hex data to a MIFARE Ultralight / NTAG page. Destructive — the previous contents of the page are overwritten. Some pages (e.g. OTP, lock bytes) are one-way. Fork-gated.",
			props(
				reqProp("page", "integer", "Page number to write"),
				reqProp("hex", "string", "Exactly 4 bytes as hex, e.g. 'DEADBEEF'"),
				optProp("timeout_seconds", "integer", "How long to wait (default 10)"),
			),
			"page", "hex",
		),
		tool("nfc_dump_protocol",
			"Dump all readable contents of an NFC tag matching a specific protocol (Mifare_Classic, Mifare_Ultralight, etc). Fork-gated.",
			props(
				reqProp("protocol", "string", "Protocol name, e.g. Mifare_Classic or Mifare_Ultralight"),
				optProp("timeout_seconds", "integer", "How long to wait (default 30)"),
			),
			"protocol",
		),
		tool("loader_nfc_magic",
			"Launch the NFC Magic FAP — writes UIDs to 'magic' MIFARE tags that allow cloning of locked blocks. Requires the FAP to be installed on the SD card; call list_apps if unsure.",
			props(),
		),
		tool("loader_mfkey",
			"Launch the MFKey32 FAP — recovers MIFARE Classic sector keys from captured reader nonces. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_mifare_nested",
			"Launch the Mifare Nested FAP — nested-attack key recovery for MIFARE Classic once at least one key is known. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_picopass",
			"Launch the PicoPass FAP — HID iClass / PicoPass tag tooling. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_seader",
			"Launch the SEADER FAP — advanced HID iClass SE attack toolkit. Requires the FAP to be installed.",
			props(),
		),

		// --- RFID (extended primitives) ---
		tool("rfid_raw_read",
			"Perform a raw 125 kHz LF capture to a file for later analysis. Unlike rfid_read, the result is the unprocessed bitstream — use when you need to reverse-engineer a non-standard protocol. Hardware: hold the fob flat against the BACK of the Flipper (LF antenna side).",
			props(
				optProp("mode", "string", "Modulation: 'ask' or 'psk' (default: empty for auto)"),
				reqProp("file", "string", "Destination file path, e.g. /ext/lfrfid/raw_01.raw"),
				optProp("duration_seconds", "integer", "Capture duration (default 30)"),
			),
			"file",
		),
		tool("rfid_raw_analyze",
			"Analyse a previously captured raw LF file and attempt to decode the protocol. Read-only; runs entirely on the device.",
			props(
				reqProp("file", "string", "Path to the raw LF capture to analyse"),
			),
			"file",
		),
		tool("rfid_raw_emulate",
			"Replay a raw LF capture against a reader. Active transmission — use only with authorisation from the reader's operator. Hardware: hold the BACK of the Flipper against the reader coil.",
			props(
				reqProp("file", "string", "Path to the raw LF capture to replay"),
				optProp("duration_seconds", "integer", "How long to emulate (default 30)"),
			),
			"file",
		),
		tool("loader_t5577_multiwriter",
			"Launch the T5577 Multiwriter FAP — batch-writes T5577 blanks with a list of protocol/data combinations. Requires the FAP to be installed.",
			props(),
		),

		// --- Scripting ---
		tool("js_run",
			"Execute a saved JavaScript file via the Flipper's JS runtime. Arbitrary code execution on the device — risk is that the script can drive any subsystem (RF, storage, GPIO). Fork-gated: only Xtreme, Momentum, and RogueMaster ship a JS runtime; returns a friendly-fork error on stock.",
			props(
				reqProp("path", "string", "Absolute .js file path, e.g. /ext/apps/Scripts/foo.js"),
				optProp("duration_seconds", "integer", "Max runtime in seconds (default 60)"),
			),
			"path",
		),

		// --- Loader FAP shortcuts (Sub-GHz / misc) ---
		tool("loader_subghz_bruteforcer",
			"Launch the Sub-GHz Bruteforcer FAP — performs large code-sweep attacks across known protocols. Critical: emits enormous amounts of RF, likely illegal outside a shielded lab. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_subghz_playlist",
			"Launch the Sub-GHz Playlist FAP — replays a sequence of .sub captures in order. Active transmission. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_protoview",
			"Launch the ProtoView FAP — visualises raw Sub-GHz signals for protocol inspection. Receive-only scanning. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_spectrum_analyzer",
			"Launch the Spectrum Analyzer FAP — shows RF power across a frequency range. Receive-only. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_signal_generator",
			"Launch the Signal Generator FAP — drives a square wave on a GPIO pin at a configurable frequency. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_nrf24mousejacker",
			"Launch the NRF24 Mousejacker FAP — attack tool against 2.4 GHz wireless mice/keyboards. Requires both an external NRF24 devboard on the GPIO header AND the FAP installed. Critical (arbitrary keystroke injection).",
			props(),
		),
		tool("loader_uart_terminal",
			"Launch the UART Terminal FAP — bidirectional serial console on the Flipper's GPIO pins, useful for UART recon on target boards. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_spi_mem_manager",
			"Launch the SPI Mem Manager FAP — reads and writes SPI flash chips via the GPIO header. Useful for firmware extraction on embedded targets. Requires the FAP to be installed.",
			props(),
		),
		tool("loader_unitemp",
			"Launch the Unitemp FAP — reads external temperature/humidity sensors (DHT, DS18B20, BMP280, ...) over the GPIO header. Read-only.",
			props(),
		),
	}
	return append(regTools, legacy...)
}

// buildWorkflowTools returns every composite pentest workflow tool. Each
// workflow orchestrates several primitives behind a single LLM-callable
// interface and returns a structured JSON envelope — prefer these over
// asking the LLM to chain primitives by hand when the user describes a
// pentest goal rather than a specific command.
func buildWorkflowTools() []anthropic.ToolUnionParam {
	return []anthropic.ToolUnionParam{
		tool("workflow_nfc_badge_pipeline",
			"Triage an unknown NFC badge: detect protocol, decide whether it's clonable, and return a cloning or attack plan. Runs nfc_detect → protocol parser → protocol-specific follow-up (MIFARE Classic → mfkey suggestion; Ultralight → block reads; NTAG → dump; DESFire/EMV → apdu recon). Expected runtime: 15–45s. Params: attempt_dump (default false), timeout_seconds (default 30). Risk: High (may launch FAPs and read tag contents).",
			props(
				optProp("attempt_dump", "boolean", "When true, also launch an appropriate dumping FAP after detection (default false)"),
				optProp("timeout_seconds", "integer", "Max time to wait for a tag (default 30)"),
			),
		),
		tool("workflow_wifi_target_to_hashcat",
			"Scan WiFi APs, pick the strongest WPA/WPA2 target, capture a PMKID, and emit a hashcat 22000-format hash file. Marauder devboard required — returns a friendly error when --wifi is not active. Expected runtime: 50–90s. Params: scan_seconds (default 20), capture_seconds (default 30), bssid (optional override), output_path (default /ext/wifi/hashcat_input.22000). Risk: High (active PMKID capture).",
			props(
				optProp("scan_seconds", "integer", "AP scan duration (default 20)"),
				optProp("capture_seconds", "integer", "PMKID sniff duration (default 30)"),
				optProp("bssid", "string", "Specific BSSID to target (overrides the strongest-AP pick)"),
				optProp("output_path", "string", "Where to save the 22000 hash file on the SD card (default /ext/wifi/hashcat_input.22000)"),
			),
		),
		tool("workflow_garage_door_triage",
			"Scan common garage / gate / car-remote frequencies, save and decode any captured signals, and suggest attack paths (replay vs. rolling). Pure RX — does not transmit. Expected runtime: 35–70s (default 5s × 7 frequencies). Params: frequencies ([]int override), per_freq_seconds (default 5). Risk: Medium (receive only).",
			props(
				optProp("frequencies", "array", "Override the frequency list in Hz (default: 300/310/315/318/390/433.92/868.35 MHz)"),
				optProp("per_freq_seconds", "integer", "How long to listen on each frequency (default 5)"),
			),
		),
		tool("workflow_rolljam_lab_demo",
			"Lab-only rolling-code capture demo: records two consecutive button presses to separate .sub files for later authorised replay. Does NOT transmit. Requires lab_consent=true or the call is refused. Expected runtime: 20–30s. Params: frequency (required), output_dir (default /ext/subghz/rolljam), capture_window_seconds (default 10), lab_consent (required true). Risk: Critical — captured files enable subsequent rolljam transmission.",
			props(
				reqProp("frequency", "integer", "Target frequency in Hz, e.g. 433920000"),
				reqProp("lab_consent", "boolean", "MUST be true — acknowledges this is authorised lab/research use"),
				optProp("output_dir", "string", "Directory on SD card for the two capture files (default /ext/subghz/rolljam)"),
				optProp("capture_window_seconds", "integer", "Max seconds to wait for each press (default 10)"),
			),
			"frequency", "lab_consent",
		),
		tool("workflow_phys_pentest_badge_walk",
			"Continuous RFID + NFC + iButton census for walking a site during a physical pentest. Loops per-scan ~5s between each technology, dedupes unique UIDs, writes a CSV to the SD card. Stops on ctx cancellation or duration elapsed. Expected runtime: configurable, default 5 minutes. Params: duration_seconds (default 300, clamped 30–1800), dedupe_window_seconds (default 0 = forever), csv_path (default /ext/badge_walk_<unix>.csv). Risk: Medium.",
			props(
				optProp("duration_seconds", "integer", "Total walk duration, clamped to 30–1800 (default 300)"),
				optProp("dedupe_window_seconds", "integer", "Window after which a previously-seen UID can be re-logged (default 0 = suppress duplicates for the whole run)"),
				optProp("csv_path", "string", "Path on SD card to write the CSV (default /ext/badge_walk_<unix>.csv)"),
			),
		),
		tool("workflow_hw_recon_blackbox_device",
			"Recon an unknown PCB attached to the Flipper GPIO header: i2c_scan, onewire_search, gpio_read sweep across 8 pins, bt_hci_info, system_info — aggregated into a structured report with chip-ID hints for common I²C addresses (0x3c OLED, 0x68 RTC/IMU, 0x76/0x77 BMP280, etc.). Read-only. Expected runtime: 15–25s. Params: gpios ([]string optional override of the default pin list). Risk: Low.",
			props(
				optProp("gpios", "array", "Optional override of the GPIO pins to sample (default: PA7, PA6, PA4, PB3, PB2, PC3, PC1, PC0)"),
			),
		),
		tool("workflow_badusb_target_profile",
			"Generate a target-OS-aware BadUSB payload via the generation pipeline, deploy to the SD card, and optionally execute it. Re-uses generate_badusb under the hood but threads OS context into the prompt (cmd vs zsh vs bash, no-UAC constraints, etc.). Expected runtime: 5–20s (LLM generation dominates). Params: description (required), target_os (required: windows|macos|linux|chromeos), output_path (optional), auto_run (default false). Risk: Critical when auto_run=true, High otherwise.",
			props(
				reqProp("description", "string", "Natural-language description of what the payload should do"),
				reqProp("target_os", "string", "One of: windows, macos, linux, chromeos"),
				optProp("output_path", "string", "Custom SD-card path (default /ext/badusb/profile_<target>_<ts>.txt)"),
				optProp("auto_run", "boolean", "Execute after deploying (default false)"),
			),
			"description", "target_os",
		),
		tool("workflow_mousejack",
			"NRF24 Mousejack engagement composite: read existing sniffer targets (/ext/apps_data/nrfsniff/addresses.txt), build a DuckyScript payload for /ext/mousejacker/<name>.txt, re-gate the FAP launch through the operator confirmation hook, then launch the Mousejacker FAP. Does NOT run the sniffer itself — call nrf24_sniff_start first if the target list is empty. Critical-risk: culminates in keystroke injection at the paired host.",
			props(
				reqProp("name", "string", "Payload filename (written to /ext/mousejacker/<name>.txt)"),
				reqProp("script", "string", "DuckyScript body"),
				optProp("target_os", "string", "windows | macos | linux (default windows)"),
				optProp("max_delay_ms", "integer", "Override the 5000 ms DELAY ceiling"),
				optProp("addresses_path", "string", "Override the sniffer output path"),
				optProp("launch", "boolean", "Launch the FAP after deploy (default true). Set false to stage only."),
			),
			"name", "script",
		),
	}
}

// buildFileFormatTools returns the structural read/edit/diff tools for the
// four Flipper capture formats (.sub, .nfc, .ir, .rfid). Registered
// unconditionally — they operate on SD-card files via the existing Flipper
// storage CLI primitives.
func buildFileFormatTools() []anthropic.ToolUnionParam {
	return []anthropic.ToolUnionParam{
		tool("fileformat_read",
			"Read a Flipper file from the SD card, parse it according to its extension (.sub/.nfc/.ir/.rfid), and return the structural JSON (fields, blocks, signals) instead of the raw text. Use this when you need to reason about *fields* rather than string-match. Read-only.",
			props(
				reqProp("path", "string", "SD-card path, e.g. /ext/subghz/garage.sub"),
			),
			"path",
		),
		tool("fileformat_edit",
			"Parse a Flipper file, apply a top-level edits map, re-serialize, and write back to the SD card (same path unless output_path is given). Allowed edit keys per format — .sub: frequency, protocol, key, te, preset — .nfc: uid, atqa, sak, device_type, block_<n> — .ir: signal_<n>_name, signal_<n>_address, signal_<n>_command — .rfid: key_type, data. Unknown keys return an error.",
			props(
				reqProp("path", "string", "SD-card path to read + parse"),
				reqProp("edits", "object", "Top-level field overrides per the format's allowed keys"),
				optProp("output_path", "string", "Optional alternate SD path to write to (defaults to input path)"),
			),
			"path", "edits",
		),
		tool("fileformat_diff",
			"Parse two Flipper files and return a structural diff (per-field, per-block, per-signal). Read-only. Format mismatches return {same_format:false} with no entries.",
			props(
				reqProp("path_a", "string", "First SD-card path"),
				reqProp("path_b", "string", "Second SD-card path"),
			),
			"path_a", "path_b",
		),
	}
}

// schemaToProps converts the "properties" object from a JSON Schema into the
// map[string]interface{} that tool() / anthropic.ToolInputSchemaParam.Properties
// expects. Returns nil for an empty or unparseable schema.
func schemaToProps(schema json.RawMessage) map[string]interface{} {
	if len(schema) == 0 {
		return nil
	}
	var s struct {
		Properties map[string]interface{} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &s); err != nil || len(s.Properties) == 0 {
		return nil
	}
	return s.Properties
}

// Helper constructors for clean tool definitions.

// ToolExample is a single canonical input → outcome pair for a tool's
// description. Examples are rendered into the prompt-cached tool
// definition so the model sees concrete usage patterns without any
// per-turn cost. Keep each example short — two lines max — so the
// cumulative description stays under ~1 KB.
type ToolExample struct {
	Input string // JSON for the tool's input params, e.g. `{"file":"/ext/subghz/garage.sub"}`
	Note  string // short human-readable outcome, e.g. "replays a garage-door capture"
}

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
			Description: anthropic.String(toolctx.EnrichDescription(name, desc)),
			InputSchema: input,
		},
	}
}

// toolEx is tool() with a few-shot examples block appended to the
// description. Literature (arXiv 2310.08540 and follow-ups) shows a
// single canonical example lifts tool-arg accuracy on rare tools by
// double-digit points; two examples cover the common / edge-case
// split. The block is deterministic, so the system+tools prompt-cache
// breakpoint placed in buildCachedRequest still hits on every turn.
func toolEx(name, desc string, properties map[string]interface{}, examples []ToolExample, required ...string) anthropic.ToolUnionParam {
	return tool(name, renderExamples(desc, examples), properties, required...)
}

// renderExamples appends a short "Examples:" section to the tool
// description. Exposed (package-private) so tests can exercise the
// rendering shape without reaching through tool().
func renderExamples(desc string, examples []ToolExample) string {
	if len(examples) == 0 {
		return desc
	}
	var b strings.Builder
	b.WriteString(desc)
	b.WriteString("\n\nExamples:")
	for _, ex := range examples {
		b.WriteString("\n- ")
		b.WriteString(ex.Input)
		if ex.Note != "" {
			b.WriteString("  — ")
			b.WriteString(ex.Note)
		}
	}
	return b.String()
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
	tools = append(tools, buildWorkflowTools()...)
	tools = append(tools, buildFileFormatTools()...)
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
