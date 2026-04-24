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
		tool("nfc_read_save",
			"Scan an NFC tag and save it to the SD card as /ext/nfc/<name>.nfc. This is the default tool for operator requests like 'scan this fob', 'read the badge', or 'save this card'. Does a full NFCDetect, constructs a valid .nfc file (UID + ATQA + SAK, device-type-aware), runs the static verifier, and writes via the same snapshot/rewind pipeline as the parametric builders. Works for Classic 1K/4K, NTAG213/215/216, Ultralight. For high-security badges where sector keys are required for full block reads, the UID-only save is still useful as a first pass — chain with loader_mfkey / loader_mifare_nested for key recovery.",
			props(
				optProp("name", "string", "Output filename stem (default: scanned_<uid>). Result lands at /ext/nfc/<name>.nfc"),
				optProp("path", "string", "Full SD path override — when set, takes precedence over name"),
				optProp("timeout_seconds", "integer", "How long to wait for a tag (default 15 — shorter than nfc_detect to keep the interactive flow snappy)"),
				optProp("verify_bypass", "boolean", "Skip the static verifier block on high/critical findings"),
			),
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
// same builder order as ToolNames. WiFi/Marauder tools are now surfaced via
// the registry-backed prepass in buildTools() regardless of hasMarauder.
func ToolCatalog(hasMarauder bool) []ToolCatalogEntry {
	_ = hasMarauder // retained for API compatibility; Wave 3 unified WiFi tools into registry
	tools := buildTools()
	tools = append(tools, buildGenTools()...)
	tools = append(tools, buildWorkflowTools()...)
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
