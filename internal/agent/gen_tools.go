package agent

import "github.com/anthropics/anthropic-sdk-go"

func buildGenTools() []anthropic.ToolUnionParam {
	return []anthropic.ToolUnionParam{
		// --- Generate, Deploy, Run Pipeline ---
		tool("generate_evil_portal",
			"Generate an evil portal captive portal HTML page from a description. Creates a convincing login page that captures credentials. Describe what it should look like: 'Google login page', 'Starbucks WiFi portal', 'corporate VPN login', etc. The AI creates a pixel-perfect replica. Returns the generated HTML and optionally deploys it to the Flipper.",
			props(
				reqProp("description", "string", "What the portal should look like. Be specific: 'Google sign-in page with dark mode', 'airport free WiFi captive portal', 'Netflix login page'"),
				optProp("deploy", "boolean", "Auto-deploy to Flipper SD card (default true)"),
				optProp("path", "string", "Custom path on SD card (default /ext/apps_data/evil_portal/index.html)"),
				optProp("verify_bypass", "boolean", "Bypass the chain-of-verification pre-deploy check. Default false. When the verifier returns a high/critical severity the deploy is blocked unless this is true."),
			),
			"description",
		),
		tool("generate_badusb",
			"Generate a BadUSB/DuckyScript payload from a description. Describe what it should do: 'open reverse shell on Windows', 'exfiltrate WiFi passwords', 'rickroll the screen', 'install a keylogger'. The AI creates the payload, validates syntax, and deploys to the Flipper.",
			props(
				reqProp("description", "string", "What the payload should do. Be specific about the target and goal."),
				optProp("target_os", "string", "Target OS: windows, macos, linux (default windows)"),
				optProp("deploy", "boolean", "Auto-deploy to Flipper SD card (default true)"),
				optProp("path", "string", "Custom path on SD card"),
				optProp("verify_bypass", "boolean", "Bypass the chain-of-verification pre-deploy check. Default false. When the verifier returns a high/critical severity the deploy is blocked unless this is true."),
			),
			"description",
		),
		tool("generate_subghz",
			"Generate a Sub-GHz signal file (.sub) from a description. Describe the target: '433MHz garage door opener', '315MHz car remote', 'CAME protocol gate opener'. The AI creates the signal file with proper encoding.",
			props(
				reqProp("description", "string", "Target device and protocol details"),
				optProp("deploy", "boolean", "Auto-deploy to Flipper SD card (default true)"),
				optProp("path", "string", "Custom path on SD card"),
				optProp("verify_bypass", "boolean", "Bypass the chain-of-verification pre-deploy check. Default false. When the verifier returns a high/critical severity the deploy is blocked unless this is true."),
			),
			"description",
		),
		tool("generate_ir",
			"Generate an infrared remote file (.ir) from a description. Describe the target: 'Samsung TV remote', 'LG AC unit', 'Sony soundbar'. Creates a complete remote with all common commands.",
			props(
				reqProp("description", "string", "Target device — brand, model, type"),
				optProp("deploy", "boolean", "Auto-deploy to Flipper SD card (default true)"),
				optProp("path", "string", "Custom path on SD card"),
				optProp("verify_bypass", "boolean", "Bypass the chain-of-verification pre-deploy check. Default false. When the verifier returns a high/critical severity the deploy is blocked unless this is true."),
			),
			"description",
		),
		tool("generate_nfc",
			"Generate an NFC tag file (.nfc) from a description. Describe what kind of tag: 'MIFARE Classic 1K with default keys', 'NTAG215 amiibo data', 'blank UID-changeable tag'.",
			props(
				reqProp("description", "string", "Tag type and data description"),
				optProp("deploy", "boolean", "Auto-deploy to Flipper SD card (default true)"),
				optProp("path", "string", "Custom path on SD card"),
				optProp("verify_bypass", "boolean", "Bypass the chain-of-verification pre-deploy check. Default false. When the verifier returns a high/critical severity the deploy is blocked unless this is true."),
			),
			"description",
		),
		tool("run_payload",
			"Run a previously generated or existing payload on the Flipper. Automatically detects the type from the file path and executes the appropriate command (evil portal start, badusb run, subghz tx, ir tx, nfc emulate).",
			props(
				reqProp("path", "string", "Path to the payload file on Flipper SD card"),
				optProp("command", "string", "For IR files: specific command name to send"),
			),
			"path",
		),
		tool("generate_deploy_run",
			"All-in-one: generate a payload from a description, deploy it to the Flipper, and immediately execute it. This is the fastest way to go from idea to action. Specify the type and describe what you want.",
			props(
				reqProp("type", "string", "Payload type: evil_portal, badusb, subghz, ir, nfc"),
				reqProp("description", "string", "What to generate — be descriptive"),
				optProp("target_os", "string", "For badusb: target OS (default windows)"),
				optProp("path", "string", "Custom deploy path"),
			),
			"type", "description",
		),

		// --- Vision ---
		tool("analyze_image",
			"Analyze a photo of a device, remote, tag, lock, keypad, or any physical target. The AI identifies what it is and suggests exactly how to interact with it using the Flipper Zero. Send a photo and get back: device identification, protocol/frequency, and recommended promptzero commands.",
			props(
				reqProp("image", "string", "Base64-encoded image data or file path to an image"),
				optProp("question", "string", "Specific question about the image (default: identify the device and suggest Flipper actions)"),
			),
			"image",
		),

		// --- Discovery ---
		tool("discover_apps",
			"Scan the Flipper Zero SD card and discover all installed FAP applications, saved signals, BadUSB scripts, NFC tags, RFID tags, and other files. Returns a categorized inventory of everything available on the device.",
			props(),
		),

		// --- Parametric file builders (P1-13) ---
		// These produce correctly-framed Flipper files from structured
		// parameters. Use them instead of generate_* when you know the
		// exact protocol / fields — the output never has syntactic
		// errors because a Go builder synthesises the bytes.
		tool("subghz_build",
			"Construct a valid Flipper .sub file from parameters and write it to the SD card. Use when you know the exact frequency, protocol, and key hex — safer than generate_subghz for replaying a captured key. Returns the written path.",
			props(
				reqProp("path", "string", "Destination on SD card, e.g. /ext/subghz/remote.sub"),
				reqProp("frequency", "integer", "Frequency in Hz, e.g. 433920000"),
				optProp("protocol", "string", "Protocol name: Princeton, CAME, Keeloq, etc. Omit for RAW data."),
				optProp("preset", "string", "Flipper preset name (defaults to OOK 650 async for ISM bands)."),
				optProp("key_hex", "string", "Space-separated hex bytes, e.g. '00 00 00 1A 2B 3C 4D 00'"),
				optProp("bit", "integer", "Protocol bit length (e.g. 24 for Princeton)"),
				optProp("te", "integer", "Timing element in microseconds (e.g. 400)"),
			),
			"path", "frequency",
		),
		tool("rfid_build",
			"Construct a valid Flipper .rfid file and write it to the SD card. Use to clone a known LF protocol + hex payload onto a T5577 blank via rfid_write.",
			props(
				reqProp("path", "string", "Destination on SD card, e.g. /ext/lfrfid/badge.rfid"),
				reqProp("key_type", "string", "RFID protocol: EM4100, HIDProx, Indala, AWID, FDX-A, FDX-B"),
				reqProp("data", "string", "Hex data, e.g. '1A 2B 3C 4D 5E' (spaces optional)"),
			),
			"path", "key_type", "data",
		),
		tool("ir_build",
			"Construct a valid Flipper .ir remote file from a list of IR signals. Each signal specifies protocol+address+command (parsed mode) or frequency+duty_cycle+data (raw mode).",
			props(
				reqProp("path", "string", "Destination on SD card, e.g. /ext/infrared/tv.ir"),
				optProp("name", "string", "Display label for the remote (defaults to 'generated')"),
				reqProp("signals", "array", "Array of signal objects. Each: {name, type?, protocol?, address?, command?, frequency?, duty_cycle?, data?}"),
			),
			"path", "signals",
		),
		tool("nfc_build",
			"Construct a valid Flipper .nfc file from parameters. UID-only files are valid for spoofing badges; include ATQA/SAK/blocks for full MIFARE clones.",
			props(
				reqProp("path", "string", "Destination on SD card, e.g. /ext/nfc/badge.nfc"),
				reqProp("device_type", "string", "Device type: 'Mifare Classic', 'Mifare Ultralight', 'NTAG213', etc."),
				reqProp("uid", "string", "Tag UID as hex, e.g. 'AA BB CC DD'"),
				optProp("atqa", "string", "ATQA response hex, e.g. '0004'"),
				optProp("sak", "string", "SAK response hex, e.g. '08'"),
				optProp("mifare_type", "string", "Classic type label: '1K', '4K'"),
				optProp("blocks", "object", "Map of block index (string) to space-separated hex contents"),
			),
			"path", "device_type", "uid",
		),

		// --- Audit ---
		tool("audit_query",
			"Query the audit log. Shows recent tool executions with timestamps, inputs, outputs, risk levels, and success/failure status.",
			props(
				optProp("limit", "integer", "Number of entries to return (default 20)"),
			),
		),
		tool("audit_export",
			"Export the current session's complete audit log as JSON. Useful for pentest reports and compliance documentation.",
			props(),
		),
		tool("audit_stats",
			"Show statistics for the current session: total actions, success rate, unique tools used.",
			props(),
		),
	}
}
