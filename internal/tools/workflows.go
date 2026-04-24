package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/workflows"
)

// workflows.go registers all 8 composite workflow tools.
//
// Three of them — workflow_hw_recon_blackbox_device, workflow_garage_door_triage,
// workflow_phys_pentest_badge_walk — are AgentOnly:false because they were
// already registered in the MCP server's registerWorkflowTools() and their
// Deps requirements (Flipper + Marauder only) are satisfied by MCP's deps().
// The remaining five are AgentOnly:true.

//nolint:gochecknoinits
func init() {
	// --- MCP-accessible workflows (AgentOnly: false) ---

	Register(Spec{
		Name: "workflow_hw_recon_blackbox_device",
		Description: "Recon an unknown PCB attached to the Flipper GPIO header: i2c_scan, onewire_search, " +
			"gpio_read sweep across 8 pins, bt_hci_info, system_info — aggregated into a structured report " +
			"with chip-ID hints for common I²C addresses (0x3c OLED, 0x68 RTC/IMU, 0x76/0x77 BMP280, etc.). " +
			"Read-only. Expected runtime: 15–25s. Params: gpios ([]string optional override of the default pin list). Risk: Low.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"gpios":{"type":"array","description":"Optional override of the GPIO pins to sample (default: PA7, PA6, PA4, PB3, PB2, PC3, PC1, PC0)"}` +
			`}}`),
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupWorkflows,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return workflows.HWReconBlackbox(ctx, buildWorkflowDeps(d), p)
		},
	})

	Register(Spec{
		Name: "workflow_garage_door_triage",
		Description: "Scan common garage / gate / car-remote frequencies, save and decode any captured signals, " +
			"and suggest attack paths (replay vs. rolling). Pure RX — does not transmit. Expected runtime: 35–70s " +
			"(default 5s × 7 frequencies). Params: frequencies ([]int override), per_freq_seconds (default 5). Risk: Medium.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"frequencies":{"type":"array","description":"Override the frequency list in Hz (default: 300/310/315/318/390/433.92/868.35 MHz)"},` +
			`"per_freq_seconds":{"type":"integer","description":"How long to listen on each frequency (default 5)"}` +
			`}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupWorkflows,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return workflows.GarageDoorTriage(ctx, buildWorkflowDeps(d), p)
		},
	})

	Register(Spec{
		Name: "workflow_phys_pentest_badge_walk",
		Description: "Continuous RFID + NFC + iButton census for walking a site during a physical pentest. " +
			"Loops per-scan ~5s between each technology, dedupes unique UIDs, writes a CSV to the SD card. " +
			"Stops on ctx cancellation or duration elapsed. Expected runtime: configurable, default 5 minutes. " +
			"Params: duration_seconds (default 300, clamped 30–1800), dedupe_window_seconds (default 0 = forever), " +
			"csv_path (default /ext/badge_walk_<unix>.csv). Risk: Medium.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"duration_seconds":{"type":"integer","description":"Total walk duration, clamped to 30–1800 (default 300)"},` +
			`"dedupe_window_seconds":{"type":"integer","description":"Window after which a previously-seen UID can be re-logged (default 0 = suppress duplicates for the whole run)"},` +
			`"csv_path":{"type":"string","description":"Path on SD card to write the CSV (default /ext/badge_walk_<unix>.csv)"}` +
			`}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupWorkflows,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return workflows.PhysPentestBadgeWalk(ctx, buildWorkflowDeps(d), p)
		},
	})

	// --- Agent-only workflows ---

	Register(Spec{
		Name: "workflow_nfc_badge_pipeline",
		Description: "Triage an unknown NFC badge: detect protocol, decide whether it's clonable, and return a " +
			"cloning or attack plan. Runs nfc_detect → protocol parser → protocol-specific follow-up " +
			"(MIFARE Classic → mfkey suggestion; Ultralight → block reads; NTAG → dump; DESFire/EMV → apdu recon). " +
			"Expected runtime: 15–45s. Params: attempt_dump (default false), timeout_seconds (default 30). Risk: High.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"attempt_dump":{"type":"boolean","description":"When true, also launch an appropriate dumping FAP after detection (default false)"},` +
			`"timeout_seconds":{"type":"integer","description":"Max time to wait for a tag (default 30)"}` +
			`}}`),
		Required:  nil,
		Risk:      risk.High,
		Group:     GroupWorkflows,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return workflows.NFCBadgePipeline(ctx, buildWorkflowDeps(d), p)
		},
	})

	Register(Spec{
		Name: "workflow_wifi_target_to_hashcat",
		Description: "Scan WiFi APs, pick the strongest WPA/WPA2 target, capture a PMKID, and emit a hashcat " +
			"22000-format hash file. Marauder devboard required — returns a friendly error when --wifi is not active. " +
			"Expected runtime: 50–90s. Params: scan_seconds (default 20), capture_seconds (default 30), bssid " +
			"(optional override), output_path (default /ext/wifi/hashcat_input.22000). Risk: High.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"scan_seconds":{"type":"integer","description":"AP scan duration (default 20)"},` +
			`"capture_seconds":{"type":"integer","description":"PMKID sniff duration (default 30)"},` +
			`"bssid":{"type":"string","description":"Specific BSSID to target (overrides the strongest-AP pick)"},` +
			`"output_path":{"type":"string","description":"Where to save the 22000 hash file on the SD card (default /ext/wifi/hashcat_input.22000)"}` +
			`}}`),
		Required:  nil,
		Risk:      risk.High,
		Group:     GroupWorkflows,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return workflows.WiFiTargetToHashcat(ctx, buildWorkflowDeps(d), p)
		},
	})

	Register(Spec{
		Name: "workflow_rolljam_lab_demo",
		Description: "Lab-only rolling-code capture demo: records two consecutive button presses to separate .sub " +
			"files for later authorised replay. Does NOT transmit. Requires lab_consent=true or the call is refused. " +
			"Expected runtime: 20–30s. Params: frequency (required), output_dir (default /ext/subghz/rolljam), " +
			"capture_window_seconds (default 10), lab_consent (required true). Risk: Critical.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"frequency":{"type":"integer","description":"Target frequency in Hz, e.g. 433920000"},` +
			`"lab_consent":{"type":"boolean","description":"MUST be true — acknowledges this is authorised lab/research use"},` +
			`"output_dir":{"type":"string","description":"Directory on SD card for the two capture files (default /ext/subghz/rolljam)"},` +
			`"capture_window_seconds":{"type":"integer","description":"Max seconds to wait for each press (default 10)"}` +
			`}}`),
		Required:  []string{"frequency", "lab_consent"},
		Risk:      risk.Critical,
		Group:     GroupWorkflows,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return workflows.RolljamLabDemo(ctx, buildWorkflowDeps(d), p)
		},
	})

	Register(Spec{
		Name: "workflow_badusb_target_profile",
		Description: "Generate a target-OS-aware BadUSB payload via the generation pipeline, deploy to the SD card, " +
			"and optionally execute it. Re-uses generate_badusb under the hood but threads OS context into the prompt " +
			"(cmd vs zsh vs bash, no-UAC constraints, etc.). Expected runtime: 5–20s (LLM generation dominates). " +
			"Params: description (required), target_os (required: windows|macos|linux|chromeos), output_path (optional), " +
			"auto_run (default false). Risk: Critical when auto_run=true, High otherwise.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"description":{"type":"string","description":"Natural-language description of what the payload should do"},` +
			`"target_os":{"type":"string","description":"One of: windows, macos, linux, chromeos"},` +
			`"output_path":{"type":"string","description":"Custom SD-card path (default /ext/badusb/profile_<target>_<ts>.txt)"},` +
			`"auto_run":{"type":"boolean","description":"Execute after deploying (default false)"}` +
			`}}`),
		Required:  []string{"description", "target_os"},
		Risk:      risk.High,
		Group:     GroupWorkflows,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return workflows.BadUSBTargetProfile(ctx, buildWorkflowDeps(d), p)
		},
	})

	Register(Spec{
		Name: "workflow_mousejack",
		Description: "NRF24 Mousejack engagement composite: read existing sniffer targets " +
			"(/ext/apps_data/nrfsniff/addresses.txt), build a DuckyScript payload for " +
			"/ext/mousejacker/<name>.txt, re-gate the FAP launch through the operator confirmation hook, " +
			"then launch the Mousejacker FAP. Does NOT run the sniffer itself — call nrf24_sniff_start first " +
			"if the target list is empty. Critical-risk: culminates in keystroke injection at the paired host.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"name":{"type":"string","description":"Payload filename (written to /ext/mousejacker/<name>.txt)"},` +
			`"script":{"type":"string","description":"DuckyScript body"},` +
			`"target_os":{"type":"string","description":"windows | macos | linux (default windows)"},` +
			`"max_delay_ms":{"type":"integer","description":"Override the 5000 ms DELAY ceiling"},` +
			`"addresses_path":{"type":"string","description":"Override the sniffer output path"},` +
			`"launch":{"type":"boolean","description":"Launch the FAP after deploy (default true). Set false to stage only."}` +
			`}}`),
		Required:  []string{"name", "script"},
		Risk:      risk.Critical,
		Group:     GroupWorkflows,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return workflows.Mousejack(ctx, buildWorkflowDeps(d), p)
		},
	})
}

// buildWorkflowDeps converts a *tools.Deps into a workflows.Deps so that
// registry handlers can call workflows.* functions without the agent package
// in the call chain.
func buildWorkflowDeps(d *Deps) workflows.Deps {
	var caps flipper.Capabilities
	if d.Flipper != nil {
		caps = d.Flipper.Capabilities()
	}
	return workflows.Deps{
		Flipper:        d.Flipper,
		Marauder:       d.Marauder,
		Vision:         d.Vision,
		Audit:          d.Audit,
		Generator:      d.Generator,
		GenLLM:         d.GenLLM,
		Capabilities:   caps,
		ConfirmSubtool: d.WorkflowConfirm,
	}
}
