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
	// v0.220.0 added wifi_80211_decode (IEEE 802.11 management
	// frame dissector — beacon / probe / auth / assoc / deauth
	// with capability info, IE walker including RSN cipher-suite
	// decode, Vendor Specific WPA1+WPS subtype lookup, reason
	// code table).
	// v0.221.0 added zigbee_nwk_decode (Zigbee Network Layer
	// frame dissector — sits on top of IEEE 802.15.4 MAC;
	// FC bitfield + 16-bit + 64-bit addressing + multicast +
	// source route + aux security header walking).
	// v0.222.0 added zigbee_aps_decode (Zigbee APS Application
	// Support sublayer dissector — sits on top of Zigbee NWK;
	// FC bitfield + dest endpoint/group + cluster + profile
	// + source endpoint + APS counter + extended + security
	// headers; well-known profile name lookup).
	// v0.223.0 added badusb_script_parse (DuckyScript / BadUSB
	// syntax parser — line-by-line command + argument validation,
	// estimated execution time; pairs with badusb_validate
	// which scans for malicious patterns).
	// v0.224.0 added nrf24_packet_decode (NRF24L01 ESB packet
	// dissector — address + PCF + payload + CRC walk with
	// Logitech Unifying / Mousejack report-type recognition).
	// v0.225.0 added zigbee_zcl_decode (Zigbee Cluster Library
	// frame dissector — application layer above APS;
	// completes the MAC → NWK → APS → ZCL chain; profile-wide
	// command name lookup).
	// v0.226.0 added bluetooth_cod_decode (Bluetooth Class of
	// Device dissector — 24-bit device-type field with major +
	// minor class lookups and service-class bitmap).
	// v0.227.0 added dcf77_decode (DCF77 time-signal dissector
	// — 60-bit long-wave time/date broadcast from Mainflingen
	// Germany; BCD minute/hour/date + parity validation +
	// timezone + leap-second decode).
	// v0.228.0 added mqtt_packet_decode (MQTT v3.1.1 control
	// packet dissector — IoT application-layer protocol with
	// CONNECT/CONNACK/PUBLISH/SUBSCRIBE/SUBACK/PUB*/UNSUB*/
	// PINGREQ/DISCONNECT decoding).
	// v0.229.0 added zigbee_zcl_attribute_decode (ZCL attribute
	// value type dissector — extends zigbee_zcl_decode by
	// decoding typed values per ZCL §2.5.2 catalog of 30 data
	// types: boolean / bitmaps / int/uint 8-64 / floats / strings
	// / time / IEEE address / cluster ID / etc.).
	// v0.230.0 added nfc_desfire_aid_decode (DESFire AID
	// dissector — 3-byte Application Identifier per NXP DESFire
	// reference; special-value detection, MAD format detection,
	// function code category lookup, well-known AID catalog).
	// v0.231.0 added coap_packet_decode (CoAP RFC 7252 packet
	// dissector — constrained-IoT application-layer protocol;
	// header + token + option-list walker + payload).
	// v0.232.0 added bluetooth_gatt_uuid_lookup (Bluetooth SIG
	// GATT UUID enumerator — ~75 Services + ~120
	// Characteristics + ~16 Descriptors; 16-bit short + 128-bit
	// canonical input with vendor-UUID detection).
	// v0.233.0 added automotive_j1850_decode (SAE J1850 frame
	// dissector for legacy pre-2008 GM/Ford OBD-II; header +
	// ECU lookup + OBD-II mode/PID decode + CRC-8 validation).
	// v0.234.0 added ibutton_decode (host-side Dallas 1-Wire
	// ROM ID dissector — 8-byte ROM layout + ~45-entry family
	// code table + Dallas CRC-8 validation; complements the
	// hardware-side ibutton_read/emulate/write tools).
	// v0.235.0 added adsb_mode_s_decode (Mode S / ADS-B 1090
	// MHz frame dissector — DF detection, ICAO extraction,
	// CRC-24 validation, DF17 TC dispatch covering Aircraft
	// Identification + Airborne Position + Airborne Velocity
	// + Surface Position; raw CPR exposed for paired solve).
	// v0.236.0 added drone_remote_id_decode (ASTM F3411-22
	// drone Remote ID payload dissector — FAA/EU-mandated
	// broadcast beacon. Covers Basic ID, Location/Vector,
	// Self-ID, System, Operator ID, Message Pack types).
	// v0.237.0 added aprs_packet_decode (APRS / AX.25
	// ham-radio packet dissector — TNC2 text + AX.25 hex
	// input; address parsing, info-field dispatch,
	// uncompressed position with symbol lookup, PHG
	// extension, status, message, basic telemetry).
	// v0.238.0 added ais_nmea_decode (AIS NMEA sentence
	// dissector — maritime counterpart of ADS-B; ITU-R
	// M.1371-5 envelope + 6-bit ASCII unpack + dispatch on
	// Types 1/2/3, 4, 5 (multi-fragment), 18, 24).
	// v0.239.0 added modbus_decode (Modbus RTU + Modbus TCP
	// dissector — most-deployed industrial control protocol;
	// envelope auto-detection + RTU CRC-16 + function code
	// dispatch covering read/write coils + registers +
	// exception responses with named codes).
	// v0.240.0 added bacnet_ip_decode (BACnet/IP ASHRAE 135
	// Annex J frame dissector — BVLC + NPDU + APDU envelope
	// with confirmed/unconfirmed service choice naming;
	// reject/abort reason lookup. Companion to modbus_decode
	// for the OT/building-automation pentest workflow).
	// v0.241.0 added tls_handshake_decode (TLS ClientHello /
	// ServerHello dissector per RFC 5246/8446 — record
	// envelope + handshake dispatch + cipher suite + extension
	// lookup (SNI/ALPN/supported_versions/groups/sig_algs/
	// key_share) + JA3 fingerprint with GREASE stripping).
	// v0.242.0 added x509_certificate_decode (X.509 v3
	// certificate dissector per RFC 5280 — PEM/DER input,
	// subject/issuer DN, validity + days_remaining + expired,
	// public key + signature algorithm, SAN, key usage, EKU,
	// basic constraints, AIA, CRL, SKI/AKI, SHA-1/SHA-256
	// fingerprints. Complements tls_handshake_decode).
	// v0.243.0 added jwt_decode (JWT dissector per RFC 7519/
	// 7515/7516 — JWS+JWE detection, header + registered
	// claims + custom claims, alg=none + expired/nbf
	// security flags. Pure decode; no signature verification).
	const expected = 320
	if initialRegistrySize != expected {
		t.Errorf("registry names at init = %d, want %d (wave-by-wave checked in §D of runbook)",
			initialRegistrySize, expected)
	}
}
