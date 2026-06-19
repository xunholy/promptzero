package tools

import (
	"sort"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// gatedTools is the golden set of every tool classified risk>=High — i.e. every
// tool the MCP consent gate (internal/mcp.add) refuses unless the operator opts
// in via PROMPTZERO_MCP_ALLOW_HIGH / ALLOW_CRITICAL. This is the security-
// critical "what can a local MCP client NOT run without consent" surface.
//
// TestGatedToolSetIsPinned asserts the registry's current >=High set EXACTLY
// equals this golden set, in BOTH directions:
//
//   - A tool here that drops below High fails — that is the bug ir_transmit_raw
//     was (active IR TX silently sitting at Medium, reachable ungated).
//   - A newly >=High tool NOT here fails — forcing a conscious "is this gated
//     correctly?" review before a new destructive tool ships, rather than the
//     classification slipping in unexamined.
//
// So adding / removing / reclassifying a tool across the High boundary is a
// deliberate, reviewed change: update this set and confirm the gating is right.
// (The registry-coverage test separately pins Spec.Risk == risk.Classify, so a
// Spec and risk.go can't disagree.)
var gatedTools = map[string]bool{ //nolint:gochecknoglobals
	"badkb_run": true, "badusb_run": true, "bruce_badusb_run": true, "bruce_evil_twin": true,
	"bruce_ir_send": true, "bruce_raw_cli": true, "bruce_wifi_deauth": true, "buspirate_pin_set": true,
	"canbus_inject": true, "canbus_replay": true, "crypto_store_key": true, "device_reboot": true,
	"flipper_backup_create": true, "flipper_backup_restore": true, "flipper_factory_reset": true, "flipper_power_3v3": true,
	"flipper_power_5v": true, "flipper_power_off": true, "flipper_raw_cli": true, "flipper_storage_format": true,
	"generate_deploy_run": true, "glitch_arm": true, "glitch_disarm": true, "glitch_fire": true,
	"glitch_set_pulse": true, "glitch_sweep": true, "gpio_set": true, "hash_crack_dictionary": true,
	"http_enum_common": true, "ibutton_emulate": true, "ibutton_write": true, "iclass_loclass_recover": true,
	"ir_bruteforce": true, "ir_transmit": true, "ir_transmit_raw": true, "js_run": true,
	"keeloq_bruteforce": true, "loader_magspoof": true, "loader_mfkey": true, "loader_mifare_nested": true,
	"loader_nfc_magic": true, "loader_nrf24mousejacker": true, "loader_open": true, "loader_picopass": true,
	"loader_seader": true, "loader_sentry_safe": true, "loader_signal": true, "loader_subghz_bruteforcer": true,
	"loader_subghz_playlist": true, "loader_t5577_multiwriter": true, "mfcuk_attack": true, "mfkey32_recover": true,
	"mfoc_attack": true, "mifare_hardnested_host": true, "nfc_apdu": true, "nfc_emulate": true,
	"nfc_mfu_wrbl": true, "nfc_raw_frame": true, "nrf24_mousejack_start": true, "port_scan_tcp": true,
	"power_reboot_dfu": true, "rfid_emulate": true, "rfid_raw_emulate": true, "rfid_write": true,
	"run_payload": true, "subghz_bruteforce": true, "subghz_chat": true, "subghz_transmit": true,
	"subghz_tx_key": true, "update_install": true, "wifi_arp_scan": true, "wifi_attack_badmsg": true,
	"wifi_attack_quiet": true, "wifi_attack_sleep": true, "wifi_beacon_clone": true, "wifi_beacon_funny": true,
	"wifi_beacon_random": true, "wifi_beacon_rickroll": true, "wifi_beacon_spam": true, "wifi_ble_spam": true,
	"wifi_bt_spoof_airtag": true, "wifi_csa_attack": true, "wifi_deauth": true, "wifi_deauth_station_list": true,
	"wifi_evil_portal_set_ap": true, "wifi_evil_portal_set_html": true, "wifi_evil_portal_start": true, "wifi_join": true,
	"wifi_karma": true, "wifi_ping_scan": true, "wifi_port_scan": true, "wifi_portscan_service": true,
	"wifi_probe_flood": true, "wifi_reboot": true, "wifi_sae_flood": true, "wifi_sniff_pmkid": true,
	"wifi_sniff_sae": true, "workflow_badusb_target_profile": true, "workflow_mousejack": true, "workflow_nfc_badge_pipeline": true,
	"workflow_rolljam_lab_demo": true, "workflow_wifi_target_to_hashcat": true,
}

// TestGatedToolSetIsPinned pins the MCP consent-gated (risk>=High) tool set
// against gatedTools in both directions — see gatedTools' doc for why.
func TestGatedToolSetIsPinned(t *testing.T) {
	current := map[string]bool{}
	for _, s := range All() {
		if risk.Classify(s.Name) >= risk.High {
			current[s.Name] = true
		}
	}

	// Reverse: a tool that is >=High now but absent from the golden set — a new
	// gated tool that hasn't been reviewed into the contract.
	var added []string
	for name := range current {
		if !gatedTools[name] {
			added = append(added, name)
		}
	}
	// Forward: a golden tool that is no longer >=High (downgraded) or no longer
	// registered (removed/renamed) — the ir_transmit_raw regression class.
	var droppedOrGone []string
	for name := range gatedTools {
		if !current[name] {
			droppedOrGone = append(droppedOrGone, name)
		}
	}
	sort.Strings(added)
	sort.Strings(droppedOrGone)

	if len(added) > 0 {
		t.Errorf("%d tool(s) are now risk>=High but missing from the gatedTools golden set: %v\n"+
			"Confirm each is INTENTIONALLY gated, then add it to gatedTools.", len(added), added)
	}
	if len(droppedOrGone) > 0 {
		t.Errorf("%d golden-set tool(s) are no longer risk>=High (downgraded) or no longer registered: %v\n"+
			"A downgrade means the tool is now reachable UNGATED over MCP — confirm that is safe (it usually is NOT) "+
			"before removing it from gatedTools.", len(droppedOrGone), droppedOrGone)
	}
}
