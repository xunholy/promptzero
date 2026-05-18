package tools_test

import (
	"os"
	"testing"

	"github.com/xunholy/promptzero/internal/tools"
)

// initialRegistrySize captures the number of registered names (canonical + aliases)
// after all package init() functions have run — before any test calls resetForTest()
// (which lives in spec_test.go and resets the global registry between unit tests).
// Captured in TestMain so it is always the pre-test, post-init count regardless
// of test ordering.
var initialRegistrySize int

// initialSpecs is the snapshot of the full production registry captured before
// any test can call resetForTest(). TestRegistryCoverage iterates over this
// slice instead of calling tools.All() at test-run time, which would see a
// partial registry if TestNames_IncludesAliases (or any other spec_test.go
// test) has already reset it.
var initialSpecs []tools.Spec

func TestMain(m *testing.M) {
	// tools.Names() counts every invocable name: canonical names plus aliases.
	// The runbook §D cumulative counts use this metric (e.g. device_info +
	// system_info alias = 2 names from 1 Spec; Wave 0 contributes 4 names,
	// but the Wave 0 test used All() = 3, so Wave 1 switches to Names()
	// to align with the runbook's "34 entries" target).
	initialRegistrySize = len(tools.Names())
	initialSpecs = tools.All()
	os.Exit(m.Run())
}

func TestRegistrySize(t *testing.T) {
	// Wave 3: 84 (Wave 2 cumulative) + 62 new specs (no aliases) = 146.
	// Wave 4: 146 + 33 new AgentOnly specs (no aliases) = 179.
	// The 33 new specs are:
	//   1 nfc_read_save
	//   8 generate_* + run_payload + generate_deploy_run (= 10 total in gen family)
	//   1 analyze_image
	//   1 discover_apps
	//   1 docs_search
	//   3 audit_* (audit_query, audit_export, audit_stats)
	//   3 target_* (target_remember, target_recall, target_forget)
	//   2 nrf24_mousejack_start + nrf24_payload_build (added to nrf24.go)
	//   4 *_build (subghz_build, rfid_build, ir_build, nfc_build)
	//   2 subghz_bruteforce_generate + subghz_freq_sweep
	//   8 workflow_* (3 AgentOnly:false + 5 AgentOnly:true)
	// None of the 33 new specs carry aliases.
	// AgentOnly specs cumulative: list_devices (W1), subghz_bruteforce,
	// ir_bruteforce (W2), nrf24_sniff_start, nrf24_list_targets (W3),
	// plus all 33 Wave 4 specs except the 3 MCP-accessible workflows = 38 total.
	// Wave 5: no new specs — deletion only.
	// v0.5 task #6 (firmware_introspect): +1 new spec (no aliases).
	// v0.5 task #10 (MCP/security): +4 new specs (no aliases):
	//   hash_identify, hash_crack_dictionary, port_scan_tcp, http_enum_common
	// v0.5 task #7 (Mifare crackers, stub-deferred to v0.5.1): +3 specs:
	//   mfoc_attack, mfcuk_attack, mfkey32_recover (Handler returns
	//   "scheduled for v0.5.1" message; algorithm reference in
	//   docs/refactor/mifare-algorithms.md is the v0.5 deliverable)
	// v0.5 task #8 (loclass): +1 spec (iclass_loclass_recover) — sub-primitives
	//   functional, end-to-end deferred to v0.5.1 (CSN-selection bug)
	// +1 fap_build (H4)
	//
	// Subsequent waves (v0.7 native crypto1 ports, v0.8 hardware-backend
	// expansion: Bruce/Faultier/Bus Pirate, FlipperHTTP, Sub-GHz
	// classifier; v0.9 Companion FAP integration) added a further +42
	// specs without re-narrating the wave deltas in this comment block.
	// v0.16 closes the remaining v0.14 audit gaps (~/ObsidianVault/agent/
	// integration-coverage-and-skills.md): +37 specs across new Marauder
	// verbs (wardrive, mactrack, sigmon, karma, attack-t quiet/badmsg/
	// sleep, evil-portal subverbs) and new Flipper primitives (crypto
	// enclave encrypt/decrypt/has_key, GUI screen stream, RTC date
	// get/set, storage extract, plus the destructive trio: format,
	// factory_reset, backup create/restore + power off and 5V/3V3 rails).
	// When this number drifts, the right action is *not* to bump the
	// constant blindly — diff `tools.Names()` against the prior known
	// good (git blame this line) and confirm every new name is
	// intentional. A surprise +1 usually means a duplicate alias or a
	// loader_* generated for a new firmware app; both are bugs to fix
	// at the source.
	// v0.20.0 added explain_last_result + marauder_handoff_hashcat.
	// v0.22.0 added badkb_run (BadUSB-over-BLE thin wrapper).
	// v0.43+ added wiegand_decode (offline parser for sniffed
	// access-control reader bitstreams; no Flipper required).
	// v0.52.0 added signal_library_search + signal_import (P2-20:
	// host-side Freqman signal library walker, and an HTTPS-only
	// allowlisted importer that pulls Freqman lists from vetted
	// public hosts into ~/.promptzero/freqman/ with size cap, hash
	// pinning, and parse-before-write validation).
	// v0.204.0 added three FAP wrappers from gap-analysis top-30:
	// loader_sentry_safe, loader_pocsag_pager, loader_magspoof.
	// v0.205.0 added four more: loader_weather_station,
	// loader_subghz_jammer_detect, loader_logic_analyzer,
	// loader_oscilloscope.
	// v0.206.0 added em4100_decode (native offline parser — first
	// implementation under the wrap-vs-native principle: pure
	// algorithms get reimplemented rather than wrapped via a FAP).
	// v0.207.0 added nfc_emv_decode (native EMV BER-TLV walker with
	// ~80-entry tag-name table from EMV Books 1-4).
	// v0.208.0 added ble_continuity_decode (native Apple Continuity
	// dissector — gap-analysis rank 8; named action types + per-type
	// field decoders for NearbyInfo/NearbyAction/Handoff/Tethering/
	// ProximityPairing/AirDrop/MagicSwitch/iBeacon).
	// v0.209.0 added subghz_pocsag_decode (native POCSAG paging
	// decoder — gap-analysis rank 4; sync-aligned bit-stream walker
	// + 32-bit codeword walker with numeric BCD and alphanumeric
	// 7-bit ASCII content decoding).
	// v0.210.0 added ble_eddystone_decode (Google Eddystone BLE
	// beacon dissector — UID / URL / TLM / EID frame walkers,
	// URL-table TLD compression decode, eTLM-version recognition).
	// v0.211.0 added mifare_classic_decode_block and
	// mifare_classic_decode_dump (native NFC dissectors:
	// manufacturer NUID+BCC integrity, sector trailer with NXP
	// AN10833 access-bit decode, value-block complement integrity,
	// plain data with ASCII preview; dump variant walks a full 1K
	// or 4K capture in one pass). +2 new specs.
	// v0.212.0 added ndef_decode (NFC Data Exchange Format
	// dissector — the payload format every NDEF-formatted NFC
	// tag stores; URI prefix table, Text record with language
	// code, Smart Poster recursion, MIME + External pass-through).
	// v0.213.0 added wifi_eapol_decode (802.1X EAPOL-Key frame
	// dissector — WPA/WPA2/WPA3 4-way handshake with header,
	// key-info bitfield, handshake-message ID M1/M2/M3/M4, KDE
	// walker for RSN IE / GTK / MAC address).
	// v0.214.0 added lorawan_decode (LoRaWAN PHYPayload dissector
	// — MAC-layer decode of LoRa Alliance 1.0.x/1.1 captures;
	// MHDR + FHDR FCtrl bitfield + FPort + Join Request/Accept
	// structural decode; FRMPayload surfaced as hex).
	// v0.215.0 added ieee802154_decode (IEEE 802.15.4 MAC frame
	// dissector — wire format under Zigbee / Thread / OpenThread;
	// Frame Control bitfield + addressing-mode-driven address
	// walker (Short 16-bit + Extended 64-bit, PAN ID compression)
	// + Beacon/Data/Ack/MAC-Command frame types + optional FCS).
	// v0.216.0 added nfc_iso14443a_identify (ISO 14443A anti-
	// collision tag-type identifier — maps (ATQA, SAK) to
	// documented tag types per NXP AN10833 + AN10927; decodes
	// UID length + manufacturer + cascade; optional ATS decode
	// with T0 + interface bytes + historicals).
	// v0.217.0 added ble_gap_decode (generic BLE GAP / EIR
	// advertisement walker — (length, AD type, data) record loop
	// with per-type decoders for Flags / UUIDs / Local Name /
	// TX Power / Service Data / Appearance / Manufacturer Data;
	// SIG company-ID + well-known-service + appearance-category
	// lookup tables).
	// v0.218.0 added iso7816_atr_decode (ISO/IEC 7816-3 ATR
	// dissector — TS convention + T0 + TA/TB/TC/TD interface-byte
	// chain + historical bytes + TCK validation; TA1 decode with
	// Fi/Di clock/baud factors).
	// v0.219.0 added jtag_idcode_decode (JTAG IDCODE / SWD DPIDR
	// chip identifier — IEEE 1149.1 bit walker + JEDEC JEP106
	// manufacturer lookup + per-vendor part-number tables for
	// ARM Cortex-M / STM32 / AVR / nRF52 / MSP430 / iCE40 / etc.).
	const expected = 296
	if initialRegistrySize != expected {
		t.Errorf("registry names at init = %d, want %d (wave-by-wave checked in §D of runbook)",
			initialRegistrySize, expected)
	}
}
