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
		// Stop-only verb — terminates an active TX session, never starts one.
		"wifi_evil_portal_stop",
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
		// v0.204 (gap-analysis top-30): POCSAG paging decoder is
		// receive-only — same risk class as the Pocsag CLI tools the
		// Momentum firmware bundles. No transmit, no writes.
		"loader_pocsag_pager",
		// v0.205 (gap-analysis top-30): receive-only RF decoders.
		// Weather Station = LaCrosse/Acurite/Oregon 433 MHz pull-only;
		// Sub-GHz Jammer Detect = RSSI dwell heuristic, defensive.
		"loader_weather_station",
		"loader_subghz_jammer_detect",
		// v0.206 (NATIVE-fit gap from top-30 rank 19): EM4100 customer-ID
		// decoder. Pure offline parser, no Flipper required, host-side
		// only. Same risk band as the existing wiegand_decode.
		"em4100_decode",
		// v0.207 (NATIVE-fit gap from top-30 rank 21): EMV BER-TLV
		// decoder for contactless-card APDU responses. Pure offline
		// parser; no card crypto verification (deliberately scoped out).
		"nfc_emv_decode",
		// v0.208 (NATIVE-fit gap from top-30 rank 8): Apple Continuity
		// dissector — pure offline parser over a manufacturer-data hex
		// blob. Pairs with the existing defense_classify_advertisement
		// which decides spam vs. legit; this decodes the legit content.
		"ble_continuity_decode",
		// v0.209 (NATIVE-fit gap from top-30 rank 4): POCSAG paging
		// protocol decoder — pure offline walker over a bit-stream or
		// pre-aligned codeword list. Receive-only / parse-only; no
		// transmit, no Flipper, no SDR. Pairs with the loader_pocsag_pager
		// FAP wrapper which covers the live-device flow.
		"subghz_pocsag_decode",
		// v0.210 (NATIVE-fit gap adjacent to top-30 rank 8): Google
		// Eddystone BLE-beacon dissector — pure offline walker over a
		// service-data payload (UID / URL / TLM / EID frame types).
		// Receive-only / parse-only. Complements ble_continuity_decode
		// in the Google service-data space.
		"ble_eddystone_decode",
		// v0.211 (NATIVE-fit gap in the NFC decode space): Mifare
		// Classic block + dump dissector — manufacturer block / sector
		// trailer (with access-bit decode per NXP AN10833) / value
		// block (with complement integrity check) / data block. Pure
		// offline parser. Complements internal/crypto1 (mfoc / mfcuk /
		// mfkey32 recover keys; this decodes the data).
		"mifare_classic_decode_block",
		"mifare_classic_decode_dump",
		// v0.212 (NATIVE-fit gap in the NFC decode space): NDEF
		// (NFC Data Exchange Format) message dissector — what every
		// NDEF-formatted NFC tag stores. URI prefix table, Text
		// record (UTF-8 / UTF-16), Smart Poster recursion, MIME and
		// External type pass-through. Pure offline parser.
		"ndef_decode",
		// v0.213 (NATIVE-fit gap in the WiFi decode space): EAPOL-Key
		// frame dissector — WPA/WPA2/WPA3 4-way handshake. Header,
		// key-info bitfield, handshake-message ID (M1/M2/M3/M4),
		// KDE walker for RSN IE / GTK / MAC address etc. Pure offline
		// parser. Pairs with marauder_handoff_hashcat.
		"wifi_eapol_decode",
		// v0.214 (NATIVE-fit gap in the Sub-GHz decode space):
		// LoRaWAN PHYPayload dissector — MAC-layer structural decode
		// for LoRaWAN 1.0.x / 1.1 captures. MHDR + FHDR + FCtrl
		// bitfield + FPort + FRMPayload (encrypted, surfaced as hex);
		// Join Request / Accept structural decode. Pure offline
		// parser. Pairs with bruce_lora_scan.
		"lorawan_decode",
		// v0.215 (NATIVE-fit gap in the 2.4 GHz IoT decode space):
		// IEEE 802.15.4 MAC frame dissector — wire format under
		// Zigbee / Thread / OpenThread. Frame Control + addressing
		// modes (Short / Extended), Beacon / Data / Ack / MAC
		// Command frame types, optional FCS handling. Pure offline
		// parser. Pairs with bruce_zigbee_scan.
		"ieee802154_decode",
		// v0.216 (NATIVE-fit gap in the NFC tag-identification
		// space): ISO 14443A anti-collision identifier — maps
		// (ATQA, SAK) combinations to documented tag types (Mifare
		// Classic / Ultralight / NTAG / DESFire / JCOP / SmartMX /
		// Mifare Plus), decodes UID length + manufacturer + cascade,
		// optional ATS structural decode (T0 + interface bytes +
		// historicals). Pure offline parser.
		"nfc_iso14443a_identify",
		// v0.217 (NATIVE-fit gap in the BLE decode space): generic
		// GAP / EIR advertisement walker — the outer (length, AD type,
		// data) record loop that wraps every BLE advertisement.
		// Per-type decoders for Flags, Service UUID lists (16/32/128-bit),
		// Local Name, TX Power, Service Data 16-bit, Appearance,
		// Manufacturer Specific Data. SIG company-ID + service-UUID
		// + appearance-category lookup tables. Pairs with
		// ble_continuity_decode / ble_eddystone_decode.
		"ble_gap_decode",
		// v0.218 (NATIVE-fit gap in the contact-smart-card decode
		// space): ISO/IEC 7816-3 ATR (Answer To Reset) dissector —
		// what every PC/SC reader returns when a card is inserted.
		// TS convention + T0 + TA/TB/TC/TD interface-byte chain +
		// historical bytes + TCK validation. Pure offline parser.
		"iso7816_atr_decode",
		// v0.219 (NATIVE-fit gap in the hardware-recon decode
		// space): JTAG IDCODE / SWD DPIDR chip identifier — IEEE
		// 1149.1 bit walker + JEDEC JEP106 manufacturer lookup +
		// per-vendor part-number tables (ARM Cortex-M / STM32 /
		// AVR / SAM / nRF52 / MSP430 / iCE40 / ECP5 / Spartan-Artix
		// / Cyclone). Pure offline parser. Pairs with Bus Pirate /
		// hw_recon workflows.
		"jtag_idcode_decode",
		// v0.220 (NATIVE-fit gap in the WiFi decode space): IEEE
		// 802.11 management frame dissector — beacon / probe req+resp
		// / auth / assoc / deauth / disassoc with full per-subtype
		// body decode, capability info bitfield, Information Element
		// walker (SSID / Rates / DS / RSN with WPA2/WPA3 cipher
		// suites / Vendor Specific with WPA1+WPS subtype lookup),
		// 802.11 reason code table. Pure offline parser. Pairs with
		// wifi_eapol_decode for the key-exchange frames.
		"wifi_80211_decode",
		// v0.221 (NATIVE-fit gap in the 2.4 GHz IoT decode space):
		// Zigbee Network Layer (NWK) frame dissector — sits on top
		// of IEEE 802.15.4 MAC. Frame Control bitfield (Data / NWK
		// Command / Inter-PAN + flags), 16-bit short addresses with
		// broadcast-class lookup, optional 64-bit IEEE addresses,
		// multicast control, source route subframe, auxiliary security
		// header. Pure offline parser. Pairs with ieee802154_decode.
		"zigbee_nwk_decode",
		"fileformat_read", "fileformat_diff",
		// v0.52 OSS-expansion (P2-20): host-side Freqman library walker.
		// Read-only directory traversal under ~/.promptzero/freqman/
		// followed by a parser pass. No RF, no Flipper or Marauder I/O.
		"signal_library_search",
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
		// v0.6 OSS-expansion: passive automotive CAN reads (controller
		// status + stop-sniffer); no bus writes.
		"canbus_info", "canbus_sniff_stop",
		// v0.6 OSS-expansion: Bruce capability read-out + Faultier
		// status read-out; no RF or bus emission.
		"bruce_capabilities",
		"glitch_status",
		// v0.6 OSS-expansion: Bus Pirate 5 read-only — voltage probe,
		// per-pin read, mode switch (HiZ is the safe idle).
		"buspirate_voltages", "buspirate_pin_read", "buspirate_mode",
		// v0.7 OSS-expansion: pure-Go Sub-GHz protocol classifier.
		// Pure analysis on a captured .sub file — no I/O, no transmission.
		"subghz_classify",
		// v0.16 — passive Marauder sniffers and read-only GPS / info / crypto / GUI.
		"wifi_info_ap",
		"wifi_sigmon", "wifi_sniff_pinescan", "wifi_sniff_multissid",
		"wifi_wardrive_stop", "wifi_wardrive_poi",
		"gps_tracker_start", "gps_tracker_stop", "gps_poi",
		"crypto_has_key", "gui_screen_stream", "flipper_date_get",
		// v0.20.0 — explorer persona meta-tool. Reads the most recent
		// audit row(s) and returns the JSON for the agent to narrate.
		// No mutation, no I/O beyond a read of the audit DB the operator
		// already owns.
		"explain_last_result",
		// v0.43+ — pure offline Wiegand parser (no IO, no
		// transmission). Operators paste sniffed D0/D1 bitstreams.
		"wiegand_decode",
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
		// v0.20.0 — PMKID pcap → hashcat .hc22000 handoff. Pure host-
		// side: reads the pcap, writes the .hc22000, may shell out to
		// hcxpcapngtool. No RF, no Flipper or Marauder writes.
		"marauder_handoff_hashcat",
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
		// v0.205 (gap-analysis top-30): sample-only hw recon FAPs.
		// 8-channel logic capture + 1 MS/s ADC — no signal generation,
		// same tier as the existing Spectrum Analyzer / UART Terminal.
		"loader_logic_analyzer",
		"loader_oscilloscope",
		"fileformat_edit",
		"loader_close",
		"workflow_garage_door_triage",
		"workflow_phys_pentest_badge_walk",
		// v0.52 OSS-expansion (P2-20): host-side Freqman library
		// import. Medium risk because the tool writes a file under
		// ~/.promptzero/freqman/ from a remote URL, even though the
		// allowlist + size cap + Freqman-parse validation make the
		// blast radius small. No RF, no Flipper or Marauder I/O.
		"signal_import",
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
		// v0.6 OSS-expansion: CAN init + passive sniff. No bus writes
		// (writes are gated separately as canbus_inject Critical).
		"canbus_init", "canbus_sniff_start",
		// v0.6 OSS-expansion: Bruce passive scans + receive-only
		// captures. No active transmission until explicit higher-tier
		// Specs are invoked.
		"bruce_wifi_scan", "bruce_wifi_5g_scan", "bruce_zigbee_scan",
		"bruce_lora_scan", "bruce_ir_receive", "bruce_nfc_read",
		// v0.6 OSS-expansion: Bus Pirate 5 active bus operations.
		// I2C scan + SPI dump + UART bridge are all bus reads/writes
		// but limited to the connected target — no broader blast.
		"buspirate_i2c_scan", "buspirate_spi_dump", "buspirate_uart_bridge",
		// v0.16 — passive sniffer with active probe class, list mutators,
		// crypto enclave reads, RTC writes, archive extract, evil-portal
		// state mutators that don't TX (reset/ack drain).
		"wifi_clone_sta_mac", "wifi_mactrack", "wifi_wardrive_start",
		"wifi_add_ap", "wifi_add_station",
		"wifi_evil_portal_reset", "wifi_evil_portal_ack",
		"crypto_encrypt", "crypto_decrypt",
		"flipper_date_set", "flipper_storage_extract",
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
		// v0.22.0 — BadUSB over BLE HID. Same payload risk class as
		// badusb_run; only the transport changes (BLE vs USB), the
		// validator gate still fires.
		"badkb_run",
		"wifi_beacon_spam", "wifi_beacon_random", "wifi_beacon_clone",
		"wifi_beacon_rickroll", "wifi_beacon_funny",
		"wifi_probe_flood",
		"wifi_sniff_pmkid", "wifi_sniff_sae",
		"wifi_evil_portal_start",
		"wifi_ble_spam",
		"wifi_join",
		"wifi_ping_scan", "wifi_arp_scan", "wifi_port_scan", "wifi_portscan_service",
		"run_payload",
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
		// v0.6 OSS-expansion: Bruce active transmission Specs.
		"bruce_ir_send",
		// v0.6 OSS-expansion: Bus Pirate 5 pin drive — mis-set a high
		// voltage and damage the target. Same tier as gpio_set.
		"buspirate_pin_set",
		// v0.6 OSS-expansion: hardnested container bridge — recovers
		// a hardened MIFARE Classic key. Same tier as mfoc/mfcuk.
		"mifare_hardnested_host",
		"loader_signal",
		"crypto_store_key",
		"workflow_nfc_badge_pipeline",
		"workflow_wifi_target_to_hashcat",
		"workflow_badusb_target_profile",
		// v0.5 security: host-side active recon (same tier as wifi_port_scan)
		"port_scan_tcp",
		"http_enum_common",
		// mfoc_attack, mfcuk_attack, mfkey32_recover review (v0.5.1
		// task #7) concluded: stay at High. Recovered keys enable
		// cloning of access credentials — same downstream effect as
		// nfc_emulate, classified by impact rather than RF emission.
		// (Lines 226-228 above already register them at High with
		// the same rationale; this comment closes the open marker.)
		// v0.16 — RF transmit + state-affecting Flipper primitives that
		// drive external hardware (5V/3V3 rails) or reach the boot loop
		// (power off, full backup write).
		"wifi_bt_spoof_airtag",
		"wifi_evil_portal_set_html", "wifi_evil_portal_set_ap",
		"flipper_backup_create", "flipper_power_off",
		"flipper_power_5v", "flipper_power_3v3",
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
		// v0.204: physical-pentest FAPs from gap-analysis top-30.
		// Sentry Safe opens any in-scope safe via factory backdoor;
		// MagSpoof emits mag-stripe data into nearby readers — both
		// need same risk gating as the other physical-attack tools.
		"loader_sentry_safe",
		"loader_magspoof",
		"js_run",
		"power_reboot_dfu",
		"update_install",
		"workflow_rolljam_lab_demo",
		// generate_deploy_run: all-in-one generate→deploy→run; execution risk
		// is Critical because the inner runPayload can launch badusb/subghz/portal.
		"generate_deploy_run",
		// v0.5 security: offline dictionary hash cracking (same tier as subghz_bruteforce)
		"hash_crack_dictionary",
		// v0.6 OSS-expansion: KeeLoq CPU brute-force can run for hours
		// against a multi-billion-key range; once recovered, the key
		// enables open-air rolling-code replay. Same tier as
		// subghz_bruteforce.
		"keeloq_bruteforce",
		// v0.6 OSS-expansion: CAN injection + replay can write to a
		// live vehicle bus; same tier as wifi_deauth.
		"canbus_inject", "canbus_replay",
		// v0.6 OSS-expansion: Bruce destructive Specs — deauth, evil
		// twin, BadUSB execution, raw CLI passthrough. Same tier as
		// the equivalent Marauder / Flipper raw_cli Specs.
		"bruce_wifi_deauth", "bruce_evil_twin", "bruce_badusb_run",
		"bruce_raw_cli",
		// v0.6 OSS-expansion: Faultier glitch Specs — arming, firing,
		// disarming, or even just setting pulse parameters can lead
		// to chip damage if mis-sequenced. The Faultier engineer
		// marked all five as Critical for safety; we honour that
		// classification here.
		"glitch_arm", "glitch_fire", "glitch_sweep",
		"glitch_disarm", "glitch_set_pulse",
		// v0.16 — destructive (format SD, factory reset, backup restore)
		// and disruptive RF (Marauder karma + WPA3-era attack-t variants).
		// Each destructive Spec also requires a literal confirm token in
		// args (see internal/tools/system_v016.go).
		"flipper_storage_format", "flipper_factory_reset", "flipper_backup_restore",
		"wifi_karma",
		"wifi_attack_quiet", "wifi_attack_badmsg", "wifi_attack_sleep",
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
//
// Invalid levels (outside [Low, Critical]) are rejected. AutoApprove
// is `toolRisk <= threshold`, so a stored Level(-1) would silently
// auto-approve at any non-negative threshold and bypass the confirm
// gate — exactly the property the registry exists to defend. The
// reject-vs-clamp choice matches Classify's fail-safe: an
// unregistered tool falls through to High, the safe default, rather
// than to whatever a typo'd caller passed.
func Register(tool string, level Level) {
	if tool == "" {
		return
	}
	if level < Low || level > Critical {
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

// WantsDiff reports whether tools at the given level should have a
// unified-diff preview attached to their confirmation request. Today
// only Medium qualifies: High/Critical already require explicit
// approval and the operator usually wants to read the params box, not
// scroll a diff. Medium is the tier where the previous prompt asked
// "approve this write?" with no insight into what would change — the
// diff plugs that gap.
func WantsDiff(level Level) bool {
	return level == Medium
}
