package risk

import "sync"

type Level int

const (
	Low      Level = iota // Read-only, informational
	Medium                // Writes data, emulates signals
	High                  // Transmits RF, writes to tags, executes scripts
	Critical              // Attacks, brute force, destructive operations
)

func (l Level) String() string {
	switch l {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	default:
		return "unknown"
	}
}

// toolLevels is the single source of truth for tool risk classification.
// Grouped by level so additions are easy to scan and drift between risk.go
// and the tool catalogues in internal/agent is caught by the coverage test.
var toolLevels = func() map[string]Level {
	m := map[string]Level{}
	register := func(l Level, names ...string) {
		for _, n := range names {
			m[n] = l
		}
	}

	// Read-only / informational
	register(Low,
		"power_info", "device_info", "list_devices",
		"storage_list", "storage_read", "storage_info",
		"gpio_read", "led_set", "vibro",
		"wifi_stop_scan", "wifi_list_aps", "wifi_list_ssids", "wifi_list_stations",
		"wifi_clear_aps", "wifi_clear_ssids", "wifi_clear_stations",
		"wifi_info", "wifi_settings",
		"audit_query", "audit_export", "audit_stats",
		"docs_search",
		"target_recall",
		"nrf24_list_targets",
		"discover_apps",
		"analyze_image",
		"list_apps",
		"ir_decode_file", "ir_universal_list",
		"rfid_raw_analyze",
		"onewire_search",
		"i2c_scan",
		"storage_md5", "storage_tree",
		"loader_info", "log_stream",
		"bt_hci_info",
		"loader_unitemp",
		"fileformat_read", "fileformat_diff",
		"badusb_validate",
		"system_info",
		"firmware_introspect", // v0.5 wave-1: read-only capability oracle
		"workflow_hw_recon_blackbox_device",
		// Marauder GPS, counters, storage, and LED (all read-only or trivial writes)
		"marauder_gps_data", "marauder_gps_field", "marauder_nmea",
		"marauder_packet_count", "marauder_storage_ls",
		"marauder_led_set", "marauder_led_rainbow",
		// v0.5 security: hash_identify is pure offline format detection
		"hash_identify",
		// v0.6 OSS-expansion: passive analysis bridge — runs urh-ng in
		// a sandboxed container against a Flipper .sub capture, no I/O.
		"urh_decode_sub",
		// v0.6 OSS-expansion: stateless classifier (no I/O), and
		// keeloq_decrypt with a known key (no transmission).
		"defense_classify_advertisement",
		"keeloq_decrypt",
		// v0.6 OSS-expansion: read-only corpus searches over operator-
		// curated asset directories. No network, no transmission, no
		// device I/O — a directory walk + grep.
		"ir_irdb_lookup", "evil_portal_template_pick", "badusb_payload_search",
	)

	// Captures, scans, file writes
	register(Medium,
		"subghz_receive", "subghz_decode",
		"ir_receive", "ir_transmit_raw",
		"rfid_read",
		"ibutton_read",
		"wifi_scan_ap", "wifi_scan_all",
		"wifi_select_ap", "wifi_select_station", "wifi_select_ssid",
		"wifi_sniff_beacon", "wifi_sniff_deauth", "wifi_sniff_probe",
		"wifi_sniff_pwnagotchi", "wifi_sniff_raw",
		"wifi_sniff_bt", "wifi_sniff_skimmer",
		"wifi_add_ssid", "wifi_remove_ssid", "wifi_generate_ssids",
		"wifi_set_channel",
		"wifi_save_aps", "wifi_save_ssids", "wifi_load_aps", "wifi_load_ssids",
		"wifi_set_setting",
		"wifi_random_mac", "wifi_clone_mac",
		"nfc_detect", "nfc_subcommand", "nfc_read_save",
		"generate_evil_portal", "generate_badusb", "generate_subghz", "generate_ir", "generate_nfc",
		"input_send",
		"storage_mkdir", "storage_delete", "storage_write",
		"subghz_rx_raw",
		"nfc_mfu_rdbl", "nfc_dump_protocol",
		"rfid_raw_read",
		"storage_copy", "storage_rename",
		"loader_protoview", "loader_spectrum_analyzer",
		"loader_signal_generator", "loader_uart_terminal",
		"loader_spi_mem_manager",
		"fileformat_edit",
		"loader_close",
		"workflow_garage_door_triage",
		"workflow_phys_pentest_badge_walk",
		// Parametric file-builders (P1-13). Medium risk because the
		// build tool writes a file to SD but does not transmit /
		// emulate — the operator still has to invoke subghz_transmit
		// / rfid_write / nfc_emulate separately.
		"subghz_build", "rfid_build", "ir_build", "nfc_build",
		"subghz_bruteforce_generate", "subghz_freq_sweep",
		// NRF24 — sniffer is passive 2.4 GHz scan (Medium), payload
		// build writes a DuckyScript file to SD (Medium). Medium is
		// the correct tier because nothing injects until a separate
		// Critical tool (nrf24_mousejack_start) launches the FAP.
		"nrf24_sniff_start", "nrf24_payload_build",
		// Target memory mutators (Batch B). Medium because a wrong
		// Remember/Forget can mislead future sessions, but nothing
		// transmits over the air.
		"target_remember", "target_forget",
		// v0.6 OSS-expansion: container bridges that produce host-side
		// artifacts (extracted firmware tree, compiled .fap binary).
		// Medium because they write to host filesystem; no RF or
		// network attack surface beyond the docker daemon.
		"firmware_extract", "fap_build",
		// v0.6 OSS-expansion: keeloq_dictionary tries published
		// manufacturer keys against a captured ciphertext. Medium
		// because a hit recovers a key that enables transmission, but
		// the lookup itself is a 1-byte-per-vendor table check.
		"keeloq_dictionary",
	)

	// Active transmission, emulation, execution
	register(High,
		"subghz_transmit",
		"ir_transmit",
		"nfc_emulate",
		"rfid_emulate", "rfid_write",
		"ibutton_emulate", "ibutton_write",
		"gpio_set",
		"badusb_run",
		"wifi_beacon_spam", "wifi_beacon_random", "wifi_beacon_clone",
		"wifi_beacon_rickroll", "wifi_beacon_funny",
		"wifi_probe_flood",
		"wifi_sniff_pmkid", "wifi_sniff_sae",
		"wifi_evil_portal_start", "wifi_evil_portal_stop",
		"wifi_ble_spam",
		"wifi_join",
		"wifi_ping_scan", "wifi_arp_scan", "wifi_port_scan", "wifi_portscan_service",
		"run_payload",
		"generate_deploy_run",
		"loader_open",
		"subghz_tx_key", "subghz_chat",
		"nfc_raw_frame", "nfc_apdu", "nfc_mfu_wrbl",
		"loader_nfc_magic", "loader_mfkey", "loader_mifare_nested",
		"loader_picopass", "loader_seader",
		"rfid_raw_emulate",
		"loader_t5577_multiwriter",
		"loader_subghz_playlist",
		// v0.5 offline crackers — recover keys without RF emission. High because
		// recovered keys enable cloning of access credentials.
		"mfoc_attack", "mfcuk_attack", "mfkey32_recover",
		"iclass_loclass_recover",
		"loader_signal",
		"crypto_store_key",
		"workflow_nfc_badge_pipeline",
		"workflow_wifi_target_to_hashcat",
		"workflow_badusb_target_profile",
		// v0.5 security: host-side active recon (same tier as wifi_port_scan)
		"port_scan_tcp",
		"http_enum_common",
		// TODO(v0.5.1 risk-review): mfoc_attack, mfcuk_attack, mfkey32_recover — tasks #7
	)

	// Destructive, attack, brute force. flipper_raw_cli is here because it's
	// an unrestricted passthrough — a single call could reboot the device,
	// overwrite files, or transmit on any frequency. Always prompt.
	register(Critical,
		"wifi_deauth", "wifi_deauth_station_list",
		"wifi_csa_attack",
		"wifi_sae_flood",
		"subghz_bruteforce",
		"ir_bruteforce",
		"device_reboot", "wifi_reboot",
		"flipper_raw_cli",
		"loader_subghz_bruteforcer",
		"loader_nrf24mousejacker",
		// NRF24 Mousejacker FAP launch — immediately precedes
		// keystroke injection into the target's paired host. Same
		// blast radius as badusb_run; same tier.
		"nrf24_mousejack_start",
		"workflow_mousejack",
		"js_run",
		"power_reboot_dfu",
		"update_install",
		"workflow_rolljam_lab_demo",
		// v0.5 security: offline dictionary hash cracking (same tier as subghz_bruteforce)
		"hash_crack_dictionary",
		// v0.6 OSS-expansion: KeeLoq CPU brute-force can run for hours
		// against a multi-billion-key range; once recovered, the key
		// enables open-air rolling-code replay. Same tier as
		// subghz_bruteforce.
		"keeloq_bruteforce",
	)

	return m
}()

// runtimeLevels is the post-init overlay used by federated tools (internal/mcpfed)
// and any other code path that needs to publish a risk level after the static
// init has run. Reads are checked first in Classify so an explicit Register
// always wins over the static fallback.
var (
	runtimeMu     sync.RWMutex
	runtimeLevels = map[string]Level{}
)

// Register publishes a risk level for tool at runtime. Used by mcpfed to
// classify federated MCP tools after their annotations are read at startup.
// A second Register call for the same tool overrides the previous level —
// the most recent assertion wins.
func Register(tool string, level Level) {
	if tool == "" {
		return
	}
	runtimeMu.Lock()
	runtimeLevels[tool] = level
	runtimeMu.Unlock()
}

// Unregister removes a runtime entry. Falls through to the static toolLevels
// map and ultimately the High default. Used in tests to keep the runtime
// overlay clean between cases.
func Unregister(tool string) {
	runtimeMu.Lock()
	delete(runtimeLevels, tool)
	runtimeMu.Unlock()
}

// Classify returns the risk level for a given tool name. The runtime overlay
// is consulted first; otherwise the static toolLevels map; otherwise High
// (the safe default — an unknown capability is gated behind a confirmation
// rather than silently auto-approved).
func Classify(tool string) Level {
	runtimeMu.RLock()
	if l, ok := runtimeLevels[tool]; ok {
		runtimeMu.RUnlock()
		return l
	}
	runtimeMu.RUnlock()
	if l, ok := toolLevels[tool]; ok {
		return l
	}
	return High
}

// ClassifyExplicit returns the registered risk level and true if the tool
// has an explicit classification (either from the runtime overlay or the
// static map), or (High, false) if the tool fell through to the safe
// default. Used by the agent-package coverage test to detect drift between
// the tool catalogue and this registry.
func ClassifyExplicit(tool string) (Level, bool) {
	runtimeMu.RLock()
	if l, ok := runtimeLevels[tool]; ok {
		runtimeMu.RUnlock()
		return l, true
	}
	runtimeMu.RUnlock()
	l, ok := toolLevels[tool]
	return l, ok
}

// AutoApprove returns whether a tool at the given risk level should auto-execute.
func AutoApprove(threshold Level, toolRisk Level) bool {
	return toolRisk <= threshold
}
