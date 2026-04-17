package risk

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

// Classify returns the risk level for a given tool name.
func Classify(tool string) Level {
	switch tool {
	// Read-only / informational
	case "power_info", "device_info", "list_devices",
		"storage_list", "storage_read", "storage_info",
		"gpio_read", "led_set", "vibro",
		"wifi_stop_scan", "wifi_list_aps", "wifi_list_ssids", "wifi_list_stations",
		"wifi_clear_aps", "wifi_clear_ssids", "wifi_clear_stations",
		"wifi_info", "wifi_settings", "wifi_get_channel",
		"audit_query", "audit_export", "audit_stats",
		"discover_apps",
		"analyze_image",
		"loader_list", "list_apps":
		return Low

	// Captures, scans, file writes
	case "subghz_receive", "subghz_decode",
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
		"nfc_detect", "nfc_subcommand",
		"generate_evil_portal", "generate_badusb", "generate_subghz", "generate_ir", "generate_nfc",
		"deploy_payload",
		"input_send",
		"storage_write", "storage_mkdir", "storage_delete":
		return Medium

	// Active transmission, emulation, execution
	case "subghz_transmit",
		"ir_transmit",
		"nfc_emulate",
		"rfid_emulate", "rfid_write",
		"ibutton_emulate", "ibutton_write",
		"gpio_set",
		"badusb_run",
		"wifi_beacon_spam", "wifi_beacon_random", "wifi_beacon_clone",
		"wifi_beacon_rickroll", "wifi_beacon_funny",
		"wifi_probe_flood",
		"wifi_sniff_pmkid",
		"wifi_evil_portal_start", "wifi_evil_portal_stop",
		"wifi_ble_spam",
		"wifi_join",
		"wifi_ping_scan", "wifi_arp_scan", "wifi_port_scan",
		"run_payload",
		"generate_deploy_run",
		"loader_open":
		return High

	// Destructive, attack, brute force. flipper_raw_cli is here because it's
	// an unrestricted passthrough — a single call could reboot the device,
	// overwrite files, or transmit on any frequency. Always prompt.
	case "wifi_deauth", "wifi_deauth_targeted",
		"wifi_csa_attack",
		"wifi_sae_flood",
		"subghz_bruteforce",
		"ir_bruteforce",
		"device_reboot", "wifi_reboot",
		"flipper_raw_cli":
		return Critical

	default:
		return High
	}
}

// AutoApprove returns whether a tool at the given risk level should auto-execute.
func AutoApprove(threshold Level, toolRisk Level) bool {
	return toolRisk <= threshold
}
