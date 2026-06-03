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
		"ir_decode_file", "ir_universal_list", "ir_raw_decode",
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
		"em4100_frame_decode",
		// em4100_encode builds the 64-bit EM4100 wire frame (header + row/
		// column parity + stop) from the 5-byte ID — generation only, no
		// write/TX (the Flipper firmware does this for `rfid write EM4100`),
		// so it stays Low like the decoder.
		"em4100_encode",
		// v0.404 (NATIVE-fit NFC gap): nfc_t2t_decode dissects the NFC
		// Forum Type 2 Tag structure (NTAG21x / Ultralight) from a dump —
		// 7-byte UID + BCC0/BCC1 validation (hand-computable XOR), static
		// lock bytes -> locked pages, and the Capability Container. Pure
		// offline parser; per-variant config pages deliberately not
		// guessed. Distinct from mifare (Classic) and ndef (the message).
		"nfc_t2t_decode",
		// v0.410 (inverse of nfc_t2t_decode): nfc_t2t_encode builds the
		// Type 2 Tag header (UID + computed BCCs + lock + CC) from a chosen
		// UID — clone-prep for a magic NTAG/Ultralight (NFC analogue of
		// ibutton_encode). Generation only — touches no card; round-trip-
		// verified against the decoder. Low like the decoder.
		"nfc_t2t_encode",
		// v0.207 (NATIVE-fit gap from top-30 rank 21): EMV BER-TLV
		// decoder for contactless-card APDU responses. Pure offline
		// parser; no card crypto verification (deliberately scoped out).
		"nfc_emv_decode",
		"nfc_emv_track2_decode",
		"nfc_emv_dol_decode",
		"nfc_emv_afl_decode",
		// Raw ISO 7813 magnetic-stripe swipe parser (Track 1/2 ASCII
		// from a reader/skimmer dump). Offline deterministic decode of
		// an operator-supplied string, Luhn-anchored; transmits
		// nothing, so it is Low.
		"magstripe_decode",
		"nfc_emv_cvm_decode",
		// nfc_emv_encode is the offline inverse — assembles EMV BER-TLV bytes
		// (tag/length/value, constructed recursion) from a tag tree,
		// round-trip-verified against nfc_emv_decode. Generation only; no card
		// I/O, no TX, so it stays Low.
		"nfc_emv_encode",
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
		// subghz_pocsag_synth is the offline inverse — builds the full
		// POCSAG transmission (BCH(31,21) + parity + batch framing) from a
		// RIC + function + message, round-trip-verified against
		// subghz_pocsag_decode. Generation only; it transmits nothing (the
		// Sub-GHz TX is a separate risk-gated step), so it stays Low.
		"subghz_pocsag_synth",
		// v0.210 (NATIVE-fit gap adjacent to top-30 rank 8): Google
		// Eddystone BLE-beacon dissector — pure offline walker over a
		// service-data payload (UID / URL / TLM / EID frame types).
		// Receive-only / parse-only. Complements ble_continuity_decode
		// in the Google service-data space.
		"ble_eddystone_decode",
		// v0.387 (offline inverse of ble_eddystone_decode): builds an
		// Eddystone service-data payload (UID / URL / TLM / EID) from
		// parameters, with the URL scheme/expansion table abbreviation.
		// Generation only — advertises nothing, touches no radio (the
		// BLE TX is a separate step) — round-trip-verified against the
		// decoder. Low like the decoder.
		"ble_eddystone_encode",
		// v0.388 (offline inverse of the iBeacon decode in
		// ble_continuity_classify): builds an Apple iBeacon
		// manufacturer-data payload (UUID + major + minor + measured
		// power) from parameters. Generation only — advertises nothing,
		// touches no radio — round-trip-verified against the decoder.
		// Low like the decoder.
		"ble_ibeacon_encode",
		// v0.389 — AltBeacon (the open, vendor-neutral beacon standard)
		// codec. ble_altbeacon_decode is a pure offline parser over the
		// company ID + 0xBEAC + 20-byte ID + ref RSSI + reserved layout;
		// ble_altbeacon_encode is its generation-only inverse (advertises
		// nothing, no radio). Both round-trip + spec-example verified.
		"ble_altbeacon_decode",
		"ble_altbeacon_encode",
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
		// ndef_encode is the offline inverse — assembles the NDEF message
		// bytes (URI / Text records, prefix-abbreviated) from a record list,
		// round-trip-verified against ndef_decode. Generation only; it writes
		// nothing to a tag and transmits nothing, so it stays Low.
		"ndef_encode",
		// v0.213 (NATIVE-fit gap in the WiFi decode space): EAPOL-Key
		// frame dissector — WPA/WPA2/WPA3 4-way handshake. Header,
		// key-info bitfield, handshake-message ID (M1/M2/M3/M4),
		// KDE walker for RSN IE / GTK / MAC address etc. Pure offline
		// parser. Pairs with marauder_handoff_hashcat.
		"wifi_eapol_decode",
		// v0.390 (native replacement for the hcxpcapngtool shell-out in
		// the PMKID case): builds a hashcat mode-22000 PMKID line
		// (WPA*01*pmkid*ap*sta*essid***) in pure Go from fields the
		// operator already holds. Pure host-side string assembly — no
		// capture, no radio — anchored on hashcat's published example.
		"wifi_pmkid_hc22000",
		// v0.391 (NATIVE-fit WiFi recon gap): WPS / Wi-Fi Simple Config
		// data-element dissector — walks the WSC attribute TLVs in a WPS
		// IE (version, setup state, AP-setup-locked, device password ID,
		// config methods, device identity), the same fields wash/reaver
		// read. Pure offline parser; unknown attributes surfaced as raw
		// hex, never guessed. Pairs with wifi_80211.
		"wifi_wps_decode",
		// v0.400 (companion to wifi_wps_decode): wifi_wps_pin validates an
		// 8-digit WPS PIN's checksum or completes a 7-digit prefix with its
		// check digit (the reaver/bully wps_pin_checksum). Pure offline
		// math; vendor default-PIN databases deliberately not embedded.
		"wifi_wps_pin",
		// v0.392 (NATIVE-fit WiFi security-recon gap): RSN (WPA2/WPA3)
		// IE dissector — names the cipher + AKM suites, decodes the PMF
		// (MFPR/MFPC) capability bits, and derives the security posture
		// (WPA2-Personal / WPA3-SAE / transition / Enterprise / OWE).
		// The wifi_80211 decoder left suite naming + PMF to a follow-on;
		// this is it. Pure offline parser; vendor suites surfaced raw.
		"wifi_rsn_decode",
		"mac_classify",
		// v0.393 (defensive WiFi analyser): deauth/disassoc-flood
		// detector over a sequence of decoded 802.11 frames — flags
		// broadcast deauths (mass-disconnect), volume floods, and
		// targeted-client disconnects, with a named reason-code
		// histogram. Observation-not-verdict; no RF/TX. Sibling of
		// tpms_anomaly_detect / subghz_rollback_detect.
		"wifi_deauth_detect",
		// v0.394 (defensive WiFi analyser): rogue-AP / evil-twin
		// detector over a set of decoded beacons — flags an SSID
		// advertised with conflicting security postures (the downgrade
		// lure), a BSSID whose posture changed, and SSIDs on multiple
		// BSSIDs. Observation-not-verdict; no RF/TX. Composes with
		// wifi_rsn_decode.
		"wifi_rogue_ap_detect",
		// v0.399 (defensive BLE analyser): ble_spam_detect runs the
		// stateless advertisement classifier over a captured batch and
		// flags an active BLE-spam flood — many distinct (rotating) source
		// MACs emitting one spam signature (Apple Continuity / Swift Pair /
		// Fast Pair). Surfaces the cross-advertisement signal the single-
		// advert defense_classify_advertisement cannot. Observation-not-
		// verdict; no RF/TX.
		"ble_spam_detect",
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
		"ble_addr_classify",
		// v0.218 (NATIVE-fit gap in the contact-smart-card decode
		// space): ISO/IEC 7816-3 ATR (Answer To Reset) dissector —
		// what every PC/SC reader returns when a card is inserted.
		// TS convention + T0 + TA/TB/TC/TD interface-byte chain +
		// historical bytes + TCK validation. Pure offline parser.
		"iso7816_atr_decode",
		"iso7816_apdu_decode",
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
		// v0.222 (NATIVE-fit gap in the 2.4 GHz IoT decode space):
		// Zigbee APS (Application Support sublayer) frame dissector —
		// sits on top of Zigbee NWK. Frame Control (Data / Command /
		// Acknowledge / Inter-PAN + delivery mode + flags), addressing
		// (dest endpoint / group address + cluster + profile + source
		// endpoint with well-known profile name lookup), APS counter,
		// optional extended + aux security headers. Pure offline parser.
		// Pairs with ieee802154_decode + zigbee_nwk_decode.
		"zigbee_aps_decode",
		// v0.223 (NATIVE-fit gap in the BadUSB decode space):
		// DuckyScript / BadUSB syntax parser — line-by-line command
		// + argument validation. Catches unknown commands, invalid
		// argument types, and surfaces estimated execution time.
		// Pure offline parser. Pairs with badusb_validate (which
		// scans for malicious patterns).
		"badusb_script_parse",
		// v0.224 (NATIVE-fit gap in the NRF24 / Mousejack decode
		// space): NRF24L01 Enhanced Shockburst (ESB) packet
		// dissector — address + PCF (PayloadLen + PID + NO_ACK) +
		// payload + CRC walk. Logitech Unifying / Mousejack
		// report-type recognition (HID Boot Keyboard / Encrypted
		// Keyboard / Mouse / HID++ / Pairing). Pure offline parser.
		// Pairs with nrf24_sniff_start / nrf24_mousejack_start.
		"nrf24_packet_decode",
		// v0.225 (NATIVE-fit gap in the 2.4 GHz IoT decode space):
		// Zigbee Cluster Library (ZCL) frame dissector — the
		// application layer in the Zigbee stack (MAC → NWK → APS →
		// ZCL). Frame Control bitfield (Profile-wide vs Cluster-
		// specific + manufacturer-specific + direction + disable-
		// default-response), optional manufacturer code, transaction
		// sequence number, command ID with profile-wide command
		// name lookup. Pure offline parser. Completes the Zigbee
		// stack chain.
		"zigbee_zcl_decode",
		// v0.226 (NATIVE-fit gap in the Bluetooth decode space):
		// Bluetooth Class of Device (CoD) dissector — 24-bit
		// device-type identifier every BT Classic device advertises
		// during inquiry. Major + Minor Device Class lookup tables,
		// Service Class bitmap (Audio / Telephony / Networking /
		// Information / etc.). Pure offline parser. Pairs with the
		// BLE dissectors (ble_continuity_decode / ble_eddystone_decode
		// / ble_gap_decode).
		"bluetooth_cod_decode",
		// v0.227 (NATIVE-fit gap in the Sub-GHz time-signal decode
		// space): DCF77 time-signal dissector — 60-bit long-wave
		// (77.5 kHz Germany) time/date broadcast. Header + BCD
		// minute/hour/date + parity validation + CET/CEST timezone
		// + leap-second + DST-change announcement decode.
		// Pure offline parser.
		"dcf77_decode",
		// dcf77_synth is the offline inverse — builds the 60-bit DCF77
		// minute telegram (BCD + even parity) from a wall-clock time,
		// round-trip-verified against dcf77_decode. Generation only; it
		// does not transmit, so it stays Low like the decoder.
		"dcf77_synth",
		// v0.228 (NATIVE-fit gap in the IoT application-layer
		// decode space): MQTT v3.1.1 control packet dissector —
		// the IP-side application-layer protocol most IoT devices
		// speak to their brokers. Fixed header + per-packet-type
		// variable header + payload extraction. CONNECT / CONNACK
		// / PUBLISH / SUBSCRIBE / SUBACK / PINGREQ / DISCONNECT
		// + the PUB* / UNSUB* helpers. Pure offline parser.
		"mqtt_packet_decode",
		// v0.229 (NATIVE-fit extension of the Zigbee ZCL chain):
		// ZCL attribute value type dissector — extends
		// zigbee_zcl_decode by decoding typed attribute values
		// inside Read/Report/Write Attributes payloads. ~30 data
		// types from ZCL Spec §2.5.2 (boolean / bitmaps / int/
		// uint 8-64 / floats / strings / time / IEEE address).
		// Pure offline parser.
		"zigbee_zcl_attribute_decode",
		// v0.230 (NATIVE-fit gap in the DESFire decode space):
		// 3-byte Application Identifier (AID) dissector. Special
		// value detection (empty / MIFARE Classic emulation /
		// wildcard), MAD-formatted AID detection (high nibble
		// 0xF), function code category lookup (transit / banking
		// / retail / parking / etc.), well-known AID catalog.
		// Pure offline parser.
		"nfc_desfire_aid_decode",
		// v0.231 (NATIVE-fit gap in the IoT application-layer
		// decode space): CoAP (RFC 7252) packet dissector — the
		// constrained-IoT counterpart to MQTT, used in 6LoWPAN /
		// Thread / OpenThread / Zigbee IP. Header + token +
		// option list with delta+length nibble encoding +
		// per-option name lookup + payload extraction. Pure
		// offline parser. Pairs with mqtt_packet_decode.
		"coap_packet_decode",
		// v0.232 (NATIVE-fit gap in the BLE decode space):
		// Bluetooth SIG GATT UUID enumerator — comprehensive
		// lookup of Service/Characteristic/Descriptor UUIDs to
		// canonical names. ~75 Services, ~120 Characteristics,
		// ~16 Descriptors. Detects 128-bit base pattern for
		// short-form extraction; flags vendor-allocated UUIDs.
		// Pure offline lookup.
		"bluetooth_gatt_uuid_lookup",
		// v0.233 (NATIVE-fit gap in the automotive decode space):
		// SAE J1850 frame dissector — legacy OBD-II protocol used
		// by pre-2008 GM/Ford vehicles. Header + ECU address +
		// OBD-II Mode + PID decoding + CRC-8 validation. Pure
		// offline parser. Pairs with canbus_* tools to extend
		// automotive coverage backwards to classic-car restoration
		// workflows.
		"automotive_j1850_decode",
		// v0.234 (NATIVE-fit gap — host-side complement to the
		// existing hardware ibutton_* family): Dallas 1-Wire ROM
		// ID dissector for iButton dumps. 8-byte ROM layout +
		// ~45-entry Maxim family-code lookup table + Dallas
		// CRC-8 validation (poly 0x31 reflected). Pure offline
		// parser. Pairs with ibutton_read for live captures.
		"ibutton_decode",
		// v0.385 (offline inverse of ibutton_decode): builds a
		// well-formed 8-byte Dallas ROM ID from family + 48-bit
		// serial, computing the Maxim CRC-8 (shared with the
		// decoder). Host-side construction for cloning a contact
		// key; generation only — writes nothing, touches no
		// hardware (ibutton_write does the burn). Low like decode.
		"ibutton_encode",
		// v0.235 (NATIVE-fit gap in the aerospace decode space):
		// Mode S / ADS-B 1090 MHz frame dissector. Pure offline
		// parser — DF detection, ICAO 24-bit extraction, CRC-24
		// validation, DF17 TC dispatch (aircraft ID + callsign,
		// airborne position + altitude + raw CPR, airborne
		// velocity + heading + vertical rate, surface position).
		// Complements subghz_* coverage by extending decode to
		// 1090 MHz airborne / aerospace traffic.
		"adsb_mode_s_decode",
		// v0.236 (NATIVE-fit gap in the drone OSINT space):
		// ASTM F3411-22 Remote ID payload dissector — the
		// FAA-mandated (14 CFR Part 89) and EU-mandated broadcast
		// beacon every drone since 2023 must transmit over BLE /
		// WiFi. Pure offline parser covering Basic ID, Location,
		// Self-ID, System, Operator ID, and Message Pack. Pairs
		// with ble_* / ieee80211_* coverage of the transport
		// framing.
		"drone_remote_id_decode",
		// v0.237 (NATIVE-fit gap in the ham-radio decode space):
		// APRS / AX.25 packet dissector — the dominant ham
		// position + telemetry + messaging beacon family on
		// 144.39 MHz NA / 144.80 MHz EU. Pure offline parser
		// for both TNC2 text and raw AX.25 hex input forms.
		// Covers address parsing, info-field type dispatch,
		// uncompressed position with hemisphere + symbol
		// lookup, PHG antenna extension, status, message,
		// basic telemetry. Pairs with subghz_pocsag_decode for
		// the paging-dragnet workflow.
		"aprs_packet_decode",
		// v0.238 (NATIVE-fit gap in the maritime decode space):
		// AIS NMEA sentence dissector — the maritime AIS VHF
		// counterpart of ADS-B. Pure offline parser per
		// ITU-R M.1371-5 + NMEA 0183. Covers Types 1/2/3
		// (Position Class A), 4 (Base Station), 5 (Static &
		// Voyage, multi-fragment reassembly), 18 (Class B
		// position), 24 (Class B static). MMSI + lat/lon + nav
		// status + vessel name + IMO + ship type + dimensions
		// + destination. Companion to adsb_mode_s_decode.
		"ais_nmea_decode",
		// v0.239 (NATIVE-fit gap in the OT / ICS decode space):
		// Modbus RTU + Modbus TCP dissector — most-deployed
		// industrial control protocol; per Modbus Application
		// Protocol v1.1b3. Pure offline parser with envelope
		// auto-detection, RTU CRC-16 validation, function code
		// dispatch (read/write coils + registers, exception
		// responses with named codes). Foundation for any SCADA
		// / PLC pentest workflow.
		"modbus_decode",
		// v0.240 (NATIVE-fit gap in the building-automation /
		// OT decode space): BACnet/IP (ASHRAE 135 Annex J)
		// frame dissector — the dominant BMS protocol for HVAC,
		// lighting, energy meters, fire-alarm gateways, BMS
		// front-ends. Pure offline parser: BVLC + NPDU + APDU
		// envelope decode with confirmed + unconfirmed service
		// choice naming (~45 entries), reject/abort reason
		// lookup. Companion to modbus_decode for the full
		// OT-pentest workflow.
		"bacnet_ip_decode",
		// v0.356 (NATIVE-fit gap in the building-automation / OT
		// decode space): KNXnet/IP (KNX over UDP/3671) frame
		// dissector — the dominant European BMS bus for lighting,
		// HVAC, blinds, access control, room controllers. Pure
		// offline parser: KNXnet/IP header + HPAI + connection
		// header + cEMI L_Data telegram decode (source/dest KNX
		// addresses, GroupValue read/write APCI + payload).
		// Companion to bacnet_ip_decode + modbus_decode for the
		// full OT-pentest workflow.
		"knxnetip_decode",
		// v0.357 (NATIVE-fit gap in the OT / smart-metering decode
		// space): M-Bus (Meter-Bus, EN 13757) telegram dissector —
		// the dominant European meter bus (electricity, gas, water,
		// heat) and the wired sibling of Flipper-capturable wM-Bus
		// (868 MHz Sub-GHz). Pure offline parser: link-layer frame
		// classification + checksum, C/A/CI field naming, and the
		// Variable Data Structure header (BCD serial, FLAG
		// manufacturer, medium/device type). Raw DIF/VIF data records
		// surfaced, never value-decoded. Companion to knxnetip_decode
		// + bacnet_ip_decode + modbus_decode.
		"mbus_decode",
		// v0.358 (NATIVE-fit gap in the OT / industrial-Ethernet
		// decode space): EtherCAT (IEC 61158) datagram dissector —
		// the dominant real-time motion-control fieldbus (Beckhoff
		// TwinCAT, ET1100/ET1200 slaves). Pure offline parser:
		// EtherCAT header + datagram chain walk (command, ADP/ADO or
		// logical addressing, data length + flags, IRQ, working
		// counter). Data block surfaced as hex, never interpreted.
		// Companion to the PROFINET / Modbus / OPC UA decoders.
		"ethercat_decode",
		// v0.360 (gap-analysis §3 rank 6): subghz_tpms_decode is a
		// pure offline TPMS Sub-GHz bit-stream decoder — Manchester
		// line decode (both conventions/alignments) + CRC-8
		// convention disambiguation + 32-bit sensor-ID extraction.
		// No RF, no Flipper/Marauder I/O; operator brings a
		// pre-demodulated bit-stream. Sibling to subghz_pocsag_decode.
		// Manufacturer pressure/temp scaling NOT decoded (raw bytes
		// surfaced) — unverifiable without per-model captures.
		"subghz_tpms_decode",
		// subghz_tpms_synth is the offline inverse — builds the Manchester
		// + CRC-8 TPMS frame from a sensor ID + payload, round-trip-verified
		// against subghz_tpms_decode. Generation only; it transmits nothing
		// (the Sub-GHz TX is a separate risk-gated step), so it stays Low.
		"subghz_tpms_synth",
		// v0.361 (gap-analysis §3 rank 5): subghz_weather_decode is a
		// pure offline 433 MHz weather-station decoder for the
		// fixed-40-bit LaCrosse TX141TH-Bv2 + Acurite 609TXC families.
		// Checksum-gated interpretation — a reading is reported only
		// for a format whose checksum (8-bit sum / lfsr_digest8_reflect)
		// validates, disambiguating the family/scaling exactly as the
		// CRC-8 disambiguates the Manchester convention in the TPMS
		// decoder. No RF; operator brings a pre-demodulated frame.
		// Sibling to subghz_tpms_decode / subghz_pocsag_decode.
		"subghz_weather_decode",
		// subghz_weather_synth is the offline inverse — builds the 5-byte
		// LaCrosse/Acurite frame (field packing + checksum) from a reading,
		// round-trip-verified against subghz_weather_decode. Generation
		// only; it transmits nothing, so it stays Low like the decoder.
		"subghz_weather_synth",
		// v0.362 (gap-analysis §3 rank 17): canbus_fd_decode is a pure
		// offline CAN / CAN-FD frame decoder over the SocketCAN candump
		// grammar — identifier (11/29-bit), CAN-FD FDF/BRS/ESI flags +
		// ISO 11898-1:2015 DLC↔length table, and SAE J1939-21 PGN
		// decomposition of 29-bit IDs. No bus/MCP2515 I/O; operator
		// brings a captured frame. Companion to the live canbus_* Specs;
		// signal-level (DBC) decode deliberately not attempted.
		"canbus_fd_decode",
		// v0.409 (frame-layer inverse of canbus_fd_decode): canbus_fd_encode
		// builds a SocketCAN candump frame string (classic ID#data / remote
		// / CAN-FD ID##flags+data) from fields — the frame-layer complement
		// to isotp_encode for crafting an injectable request. Generation
		// only — emits a string, transmits nothing; round-trip-verified.
		"canbus_fd_encode",
		// v0.395 (NATIVE-fit automotive gap): obd2_pid_decode computes
		// the engineering value of an OBD-II / SAE J1979 Mode-01 response
		// (RPM, speed, coolant temp, MAF, …) from the public per-PID
		// formulas — the value the j1850/canbus decoders left as raw
		// bytes. Pure offline transform, transport-independent; unknown
		// PIDs surfaced raw, never guessed.
		"obd2_pid_decode",
		// v0.396 (companion to obd2_pid_decode): obd2_dtc_decode unpacks
		// an OBD-II Mode-03/07/0A trouble-code response into the canonical
		// SAE J2012 codes (P/C/B/U + 4 digits) — the values the j1850
		// decoder left raw. Deterministic bit-unpack; padding skipped,
		// no guessed fault descriptions.
		"obd2_dtc_decode",
		// v0.397 (NATIVE-fit automotive gap): uds_decode parses a UDS
		// (ISO 14229) diagnostic message — names the service, classifies
		// request / positive / negative response, decodes the NRC, the
		// sub-function (+ suppressPosRsp), and the data identifier. The
		// protocol behind modern ECU attacks; pure offline parser,
		// unknown values surfaced raw.
		"uds_decode",
		"vin_decode",
		// v0.411 (application-layer inverse of uds_decode): uds_encode
		// builds a UDS request/response PDU (SID + sub-function +
		// suppressPosRsp bit + DID + payload) — the top of the inject
		// chain (uds_encode -> isotp_encode -> canbus_fd_encode ->
		// canbus_inject). Generation only; round-trip-verified.
		"uds_encode",
		// v0.398 (the missing automotive transport layer): isotp_decode
		// decodes ISO-TP (ISO 15765-2) PCI (SF/FF/CF/FC) and reassembles
		// the multi-frame UDS/OBD-II message off a CAN capture — the link
		// between canbus_fd_decode (frame) and uds_decode/obd2_* (PDU).
		// Pure offline transform; sequence-number gaps noted.
		"isotp_decode",
		// v0.408 (transmit-side inverse of isotp_decode): isotp_encode
		// segments an application PDU into ISO-TP CAN frames (SF, or
		// FF + cycling-SN CFs, padded to 8) for injecting a multi-frame
		// UDS/OBD-II request. Generation only — emits frame bytes, sends
		// nothing; round-trip-verified against the reassembler.
		"isotp_encode",
		// v0.403 (NATIVE-fit automotive gap): kwp_decode parses a KWP2000
		// (ISO 14230) diagnostic message. Shares UDS's +0x40 / 0x7F
		// framing but a DISTINCT service-ID table (local-identifier +
		// comms-control services UDS lacks), so uds_decode would mislabel
		// KWP traffic. Pure offline parser; unknown values surfaced raw.
		"kwp_decode",
		// v0.412 (application-layer inverse of kwp_decode): kwp_encode
		// builds a KWP2000 request/response PDU (SID + param byte + payload)
		// — the legacy-vehicle counterpart of uds_encode, completing the
		// KWP inject chain. Generation only; round-trip-verified.
		"kwp_encode",
		// v0.406 (defensive LoRaWAN analyser): lorawan_replay_detect flags
		// frame-counter reuse / regression over a sequence of decoded
		// LoRaWAN frames — the replay the spec's FCnt check exists to stop.
		// Key-free (FCnt is cleartext FHDR), direction-aware (independent
		// up/down counters), observation-not-verdict. No RF/TX.
		"lorawan_replay_detect",
		// v0.407 (OpenSesame primitive): subghz_debruijn generates the
		// optimal de Bruijn brute-force bit sequence for an n-bit fixed-code
		// receiver — all 2^n codes in ~2^n bits (an n-fold speedup over a
		// naive sweep). Generation only — emits a bit stream, transmits
		// nothing (pair with an OOK/TX stage). Self-verifiable.
		"subghz_debruijn",
		// v0.367 (gap-analysis §3 rank 6): tpms_anomaly_detect is a pure
		// offline, defensive analyser over a sequence of decoded TPMS
		// frames — flags excess unique sensor IDs vs the vehicle wheel
		// count and CRC-invalid frames, framed as observations not
		// verdicts. No SDR/TX; analysis-only. Companion to
		// subghz_tpms_decode.
		"tpms_anomaly_detect",
		// v0.386 (gap-analysis §1.2 — subghz_rollback_detect, attacks
		// #5): pure offline, defensive analyser over a sequence of
		// captured rolling-code frames (KeeLoq / Security+ keyfobs).
		// Flags non-consecutive duplicate codes (the key-free replay /
		// RollBack signature; consecutive burst repeats are not flagged)
		// and, when decrypted counters are supplied, counter regressions
		// — both as observations, not verdicts. No RF/TX; analysis-only.
		"subghz_rollback_detect",
		// v0.241 (NATIVE-fit gap in the network-protocol decode
		// space): TLS handshake dissector per RFC 5246 + RFC 8446.
		// Pure offline parser for ClientHello / ServerHello: TLS
		// record envelope + handshake message dispatch +
		// ClientHello / ServerHello body fields + extensions
		// (SNI, ALPN, supported_versions, supported_groups,
		// signature_algorithms, key_share) + JA3 fingerprint
		// computation with GREASE stripping. SOC blue-team
		// primitive for plaintext SNI extraction + TLS-client
		// fingerprinting.
		"tls_handshake_decode",
		// v0.242 (NATIVE-fit gap completing the TLS-traffic-
		// analysis stack): X.509 certificate dissector per
		// RFC 5280. PEM + DER input, subject/issuer DN,
		// validity (with days_remaining/expired), public key
		// algorithm + size, SAN, key usage, EKU, basic
		// constraints, AIA, CRL distribution points, SKI/AKI,
		// SHA-1/SHA-256 fingerprints. Complements
		// tls_handshake_decode (whose Certificate body is raw
		// hex). Stdlib crypto/x509 for the ASN.1 DER walk.
		"x509_certificate_decode",
		// v0.243 (NATIVE-fit gap in the modern web-auth decode
		// space): JWT decoder per RFC 7519 + 7515 + 7516.
		// Three-segment JWS compact + five-segment JWE detection.
		// Header (alg + family classification, kid, x5t, jku, x5c,
		// crit), registered claims (iss/sub/aud/exp/nbf/iat/jti),
		// custom claims preserved. Security flags: alg_none
		// detection (CVE-2015-2951-class), signature_missing,
		// expired/not-yet-valid, hours_until_expiry. Pure decode,
		// no signature verification.
		"jwt_decode",
		"jwt_verify",
		"jwt_forge",
		// JWK/JWKS -> PEM converter (the /.well-known/jwks.json form
		// into the PEM jwt_verify wants). Offline JSON->PEM transform,
		// transmits nothing, so it is Low.
		"jwk_to_pem",
		"cisco_type7_decode",
		"crc_compute",
		"manchester_decode",
		"checksum_compute",
		"totp_generate",
		"hmac_compute",
		// v0.444 — WPA/WPA2-PSK PMK derivation
		// (PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32) per IEEE
		// 802.11i). Offline KDF compute from operator-supplied
		// strings — like totp_generate / hmac_compute it derives a
		// crypto value and transmits nothing (it is a single
		// derivation, not a cracking loop), so it is Low.
		"wpa_pmk_derive",
		// v0.445 — Windows NT (NTLM) hash compute
		// (MD4(UTF-16LE(password))). Offline crypto compute from an
		// operator-supplied string — like hmac_compute / totp_generate
		// it derives a value and transmits nothing, so it is Low.
		"nt_hash",
		// v0.447 — Unix md5crypt ($1$, also Cisco type 5) / Apache
		// apr1 ($apr1$) compute + verify. Offline crypto compute /
		// constant-time verify from operator-supplied strings — like
		// nt_hash / hmac_compute it derives a value and transmits
		// nothing, so it is Low.
		"md5crypt",
		// v0.448 — Unix $6$ sha512crypt / $5$ sha256crypt (the modern
		// /etc/shadow default) compute + verify. Offline crypto
		// compute / constant-time verify from operator-supplied
		// strings — like md5crypt / nt_hash, derives a value and
		// transmits nothing, so it is Low.
		"sha_crypt",
		// v0.449 — bcrypt ($2a/$2b/$2y) compute + verify, the
		// dominant web-app password hash. Offline compute /
		// constant-time verify from operator-supplied strings — like
		// the other credential computes it derives a value and
		// transmits nothing, so it is Low.
		"bcrypt",
		// v0.451 — Argon2 (argon2id/argon2i) compute + verify, the
		// OWASP-recommended modern password hash. Offline compute /
		// constant-time verify from operator-supplied strings — like
		// the other credential computes it derives a value and
		// transmits nothing, so it is Low.
		"argon2",
		// v0.244 (NATIVE-fit gap — most-traffic-bearing UDP/53
		// protocol): DNS packet dissector per RFC 1035 + 6891.
		// Header (txn + flags broken out + counts), question
		// section with compression-pointer resolution, RR
		// sections with type-specific decode (A/NS/CNAME/SOA/
		// PTR/MX/TXT/AAAA/SRV/OPT-EDNS/DNSKEY/DS/CAA) + name
		// decompression with pointer-loop DoS guard.
		"dns_packet_decode",
		// v0.245 (NATIVE-fit gap — second most-captured wired-
		// network protocol after DNS): DHCPv4 packet dissector
		// per RFC 2131 + 2132. BOOTP envelope + magic cookie
		// validation + options walker with type-specific decode
		// for ~50 documented options (message type, subnet,
		// router, DNS, NTP, lease time, parameter request list,
		// client FQDN, relay agent sub-options, domain search,
		// classless static routes, etc.). Companion to
		// dns_packet_decode for the core network-bootstrap stack.
		"dhcp_packet_decode",
		// v0.246 (NATIVE-fit gap in the network-management decode
		// space): SNMP v1/v2c/v3 packet dissector per RFC 1157
		// + 1905 + 3416 + 3411-3418. Hand-rolled BER walker;
		// envelope + community (v1/v2c) or v3 msgGlobalData +
		// security parameters; PDU dispatch covering 9 documented
		// types (Get/GetNext/Response/Set/Trap-v1/GetBulk/Inform/
		// TrapV2/Report) with named error-status; VarBindList
		// walker with type-specific value decode + well-known
		// OID name lookup. High OT/IT pentest value.
		"snmp_packet_decode",
		// v0.247 (NATIVE-fit gap — every networked device speaks
		// it): NTP/SNTP packet dissector per RFC 5905 + 1305 +
		// 4330. 48-byte header decode (LI/VN/Mode/Stratum/Poll/
		// Precision/RootDelay/RootDispersion + Reference ID with
		// stratum-dependent interpretation (Kiss-o'-Death codes
		// / primary source identifier / upstream IPv4) + 4 NTP
		// timestamps with NTP→Unix epoch conversion + RFC 3339
		// rendering. Optional NTPv4 extensions + MD5/SHA-1
		// authenticator. High defensive value for time-sync
		// forensics and NTP amplification DDoS detection.
		"ntp_packet_decode",
		// v0.248 (NATIVE-fit gap — lingua franca of log
		// aggregation): syslog message dissector for both
		// modern RFC 5424 IETF + legacy RFC 3164 BSD formats.
		// Auto-detect by post-PRI byte. PRI broken out into
		// facility (24 entries) + severity (8 levels). RFC
		// 5424 structured-data walker with backslash-escape
		// handling. RFC 3164 BSD timestamp + tag[PID] split.
		// Workhorse blue-team primitive for log triage,
		// SIEM correlation, alert generation.
		"syslog_message_decode",
		// v0.249 (NATIVE-fit gap — foundational network decode):
		// IPv4/IPv6 + TCP/UDP/ICMP/ICMPv6 raw packet dissector
		// per RFC 791/8200/9293/768/792/4443. Auto-detect IP
		// version + full header decode + protocol dispatch +
		// TCP flag breakout + TCP TLV options walker + ICMP/
		// ICMPv6 type+code naming. Every other application-layer
		// Spec sits on top of this.
		"ip_packet_decode",
		// v0.250 (NATIVE-fit gap in the encrypted-transport
		// fingerprinting space): SSH wire-protocol dissector
		// per RFC 4253. Two input modes: SSH-2.0 version
		// banner OR binary KEXINIT packet. KEXINIT body
		// walker (16-byte cookie + 10 name-lists +
		// first_kex_packet_follows + reserved) with HASSH /
		// HASSHServer fingerprint computation (MD5 of
		// kex;enc;mac;compression). SSH counterpart to TLS
		// JA3.
		"ssh_handshake_decode",
		// v0.251 (NATIVE-fit gap — binary JSON for IoT):
		// CBOR (Concise Binary Object Representation)
		// dissector per RFC 8949. Recursive walker handling
		// all 8 major types (unsigned/negative int, byte/text
		// string, array, map, tagged value, simple/float) +
		// indefinite-length containers + IEEE 754 half/single/
		// double floats + ~30-entry well-known tag table
		// (RFC 8949 standard tags + COSE + CTAP/WebAuthn).
		// Used by COSE, WebAuthn/CTAP, Bluetooth Mesh, CoAP.
		"cbor_decode",
		// v0.252 (NATIVE-fit gap — gRPC / Google APIs / modern
		// microservices): Protobuf wire-format dissector
		// without needing the .proto schema (mirrors protoc
		// --decode_raw). Walk top-level field tags, dispatch
		// 6 wire types (VARINT + zigzag, I64 + float64, LEN
		// + nested-message heuristic + UTF-8/hex fallback,
		// SGROUP/EGROUP deprecated, I32 + float32). Recursive
		// nested-message detection.
		"protobuf_decode",
		// v0.253 (NATIVE-fit gap — enterprise AAA): RADIUS
		// packet dissector per RFC 2865 (auth) + RFC 2866
		// (accounting) + supporting RFCs. 20-byte header +
		// 16-entry code name table + attribute TLV walker
		// with ~80-entry IANA RADIUS Types name lookup +
		// Vendor-Specific (26) deep decode with SMI PEN
		// lookup + integer-attribute enum-name lookup (Service-
		// Type, NAS-Port-Type, Acct-Status-Type, Tunnel-Type,
		// etc.). High pentest value.
		"radius_packet_decode",
		// v0.254 (NATIVE-fit gap — NAT traversal / WebRTC):
		// STUN/TURN packet dissector per RFC 5389 + 8489 +
		// 5766 + 8656. 20-byte header with method/class
		// split + magic cookie validation + ~30-entry
		// attribute name table covering STUN + TURN + ICE
		// extensions + XOR address un-masking + ERROR-CODE
		// with named codes. Companion to ip_packet_decode
		// for VoIP / WebRTC flow analysis.
		"stun_packet_decode",
		// v0.255 (NATIVE-fit gap — VoIP / WebRTC signaling):
		// SIP message dissector per RFC 3261. Auto-detect
		// request vs response start line + 14 documented
		// methods + ~40-entry status code name table across
		// all 6 classes + compact-form header expansion +
		// CSeq parsing + SDP body decode for media
		// negotiation. Companion to stun_packet_decode.
		"sip_message_decode",
		// v0.256 (NATIVE-fit gap — foundational web protocol):
		// HTTP/1.x message dissector per RFC 9112 + 9110.
		// Auto-detect request vs response + ~10 documented
		// methods (incl. WebDAV) + ~50-entry status code name
		// table + header parsing with case-insensitive match
		// + line continuation folding + typed envelope fields
		// (Host / User-Agent / Server / Content-* /
		// Authorization with scheme breakout / Cookie + Set-
		// Cookie with attribute map) + Content-Length /
		// chunked transfer-encoding body decoding.
		"http_message_decode",
		// v0.257 (NATIVE-fit gap — VoIP / WebRTC media decode):
		// RTP and RTCP packet dissector per RFC 3550 + 3551
		// + 4585 + 3611. Auto-detect RTP vs RTCP by PT byte;
		// RTP header with optional CSRC + extension + padding;
		// 23-entry static PT table (audio + video) plus
		// dynamic-PT recognition (96-127); RTCP composite
		// walker handling SR / RR / SDES / BYE / APP / RTPFB
		// / PSFB / XR with per-type body parsing (reception
		// reports, SDES item types, feedback FMT codes).
		// Completes the VoIP/WebRTC decode stack alongside
		// sip_message_decode + stun_packet_decode.
		"rtp_packet_decode",
		// v0.258 (NATIVE-fit gap — explicitly deferred from
		// http_message_decode iteration): WebSocket frame
		// dissector per RFC 6455. Header bit-pack (FIN / RSV
		// / opcode / MASK / payload-len) + extended 16-bit
		// and 64-bit length escape hatches + 4-byte mask key
		// + XOR demasking + 7-entry opcode table + Close-body
		// parsing with 14-entry status code table + RSV1
		// permessage-deflate flagging + multi-frame buffer
		// walking + fragmentation detection. Natural follow-on
		// to http_message_decode (which surfaces the Upgrade
		// handshake but stops at the 101 response).
		"websocket_frame_decode",
		// v0.259 (NATIVE-fit gap — top-30 #19, RFID PACS
		// payload dissector): HID Prox / iCLASS / EM PACS
		// formats per HID OEM spec sheets. Bit-string OR
		// hex+bit_length input; HID H10301 26-bit (canonical),
		// H10306 34-bit, H10304 37-bit, H10302 37-bit (no FC),
		// Corporate 1000 35-bit and 48-bit. Parity computation
		// + validation per format. Multi-candidate dispatch
		// when the bit length is ambiguous (37-bit → both
		// H10304 and H10302). Natural sibling to
		// wiegand_decode.
		"rfid_pacs_decode",
		// rfid_pacs_encode is the offline inverse — builds the Wiegand
		// bit-stream (FC + CN + parity) for H10301/H10306, round-trip-
		// verified against rfid_pacs_decode. Generation only; it writes
		// nothing and transmits nothing (the T5577 write is the separate
		// risk-gated rfid_write step), so it stays Low like the decoder.
		"rfid_pacs_encode",
		// v0.260 (NATIVE-fit gap — top-30 #8, BLE Apple
		// Continuity classifier): pure-decode dissector for
		// the Apple Continuity TLV stream advertised in BLE
		// Manufacturer Specific Data (Apple Company ID
		// 0x004C). Outer-envelope auto-detection (full AD
		// record / manufacturer data / raw TLV). 15-entry
		// type table with per-type body decoding for
		// iBeacon, Handoff, Nearby Info, Nearby Action,
		// AirDrop, Hey Siri, Proximity Pairing. Defensive
		// primitive — identifies Apple devices in range
		// without participating in their pairing flows.
		// Pairs with workflow_apple_continuity_audit.
		"ble_continuity_classify",
		// v0.261 (NATIVE-fit gap — foundational modern VPN):
		// WireGuard packet dissector per the official protocol
		// spec at wireguard.com/protocol. Four message types
		// — Handshake Initiation 148B, Handshake Response 92B,
		// Cookie Reply 64B, Transport Data variable. Per-type
		// fixed-layout binary header walker; MAC2 zero
		// detection (no-cookie flag); keep-alive detection
		// (empty inner plaintext). Cryptographic material
		// (Curve25519 / Blake2s / ChaCha20Poly1305 /
		// XChaCha20Poly1305) surfaced as hex for traceability.
		"wireguard_packet_decode",
		// v0.262 (NATIVE-fit gap — foundational IP error /
		// diagnostic protocol): ICMP (RFC 792) and ICMPv6
		// (RFC 4443 + 4861) packet dissector. Auto-detect
		// version by type-byte heuristic + explicit hint.
		// 17 ICMPv4 types with sub-code tables; 17 ICMPv6
		// types with sub-code tables. Per-type body
		// decoding for Echo Request/Reply, Destination
		// Unreachable / Time Exceeded / Parameter Problem
		// embedded-IP carry, Redirect gateway, Packet Too
		// Big MTU, Neighbor Solicit/Advertise, Router
		// Solicit/Advertise. NDP option TLV walker with
		// 9-entry option name table.
		"icmp_packet_decode",
		// v0.263 (NATIVE-fit gap — foundational web protocol):
		// HTTP/2 frame dissector per RFC 9113. Connection
		// preface auto-detect; 9-byte frame header; 10 frame
		// types with per-type body decoding (DATA / HEADERS /
		// PRIORITY / RST_STREAM / SETTINGS / PUSH_PROMISE /
		// PING / GOAWAY / WINDOW_UPDATE / CONTINUATION);
		// 14-entry error code table; 7-entry SETTINGS
		// parameter table; multi-frame walker; flags decoded
		// per frame type (END_STREAM / END_HEADERS / PADDED /
		// PRIORITY / ACK). Completes the HTTP/1.x + WebSocket
		// + HTTP/2 decode stack.
		"http2_frame_decode",
		// v0.264 (NATIVE-fit gap — closes HTTP/2 stack):
		// HPACK header decompression per RFC 7541. Five
		// representation types (indexed / literal incremental
		// / literal without indexing / literal never indexed
		// / dynamic table size update); N-bit prefix integer
		// encoding; Huffman decoder (Appendix B, 257 symbols);
		// 61-entry static table; per-call dynamic table with
		// eviction. Explicitly closes the gap noted in v0.263
		// http2_frame_decode.
		"hpack_decode",
		// v0.265 (NATIVE-fit gap — foundational datacenter
		// L2 discovery protocol): LLDP per IEEE 802.1AB-2009.
		// TLV walker over 9 documented types (Chassis ID +
		// Port ID + TTL + Port/System Description + System
		// Name + System Capabilities + Management Address +
		// End of LLDPDU + Organizationally Specific). 7
		// chassis/port ID subtypes; 11-bit System Capabilities
		// flag table; 5 OUI name table for Org Specific TLVs;
		// mandatory-TLV ordering check.
		"lldp_decode",
		// v0.266 (NATIVE-fit gap — Cisco-proprietary sibling
		// to LLDP): CDP packet dissector. 4-byte header
		// (version + TTL + checksum) + TLV walker over ~17
		// documented TLV types (Device ID / Addresses / Port
		// ID / Capabilities / Software Version / Platform /
		// VTP Mgmt Domain / Native VLAN / Duplex / VoIP VLAN
		// / Power Consumption / MTU / Trust Bitmap / System
		// Name / System OID / Management Address). 10-bit
		// capability flag table. Coexists with LLDP on the
		// same wire on Cisco-heavy networks.
		"cdp_decode",
		// v0.267 (NATIVE-fit gap — UDP equivalent of TLS):
		// DTLS record + handshake dissector per RFC 6347
		// (DTLS 1.2) and RFC 9147 (DTLS 1.3 legacy-form).
		// 13-byte record layer (CT + version + epoch + 48-bit
		// seq + length); 5 content types; 23-entry Alert
		// description name table; 12-byte handshake header
		// (msg_type + length + msg_seq + fragment_offset +
		// fragment_length); 13 handshake types; ClientHello /
		// ServerHello / HelloVerifyRequest body dissection;
		// Heartbeat with Heartbleed (CVE-2014-0160) pattern
		// detection; multi-record walker. Pairs with
		// tls_handshake_decode.
		"dtls_record_decode",
		// v0.268 (NATIVE-fit gap — foundational modern
		// transport protocol underpinning HTTP/3): QUIC long-
		// header packet dissector per RFC 9000. First-byte
		// dispatch (long vs short header) + 4 long-header
		// packet types (Initial / 0-RTT / Handshake / Retry)
		// + Variable-Length Integer decoder (4 prefix sizes)
		// + Version Negotiation detection (Version=0) + 4-
		// entry version name table with GREASE pattern
		// recognition. Connection-setup visibility without
		// needing TLS handshake secrets.
		"quic_long_header_decode",
		// v0.269 (NATIVE-fit gap — foundational L2-to-L3
		// binding protocol): ARP (RFC 826) + RARP (RFC 903) +
		// RFC 5227 IPv4 conflict-detection extensions
		// (gratuitous-ARP / ARP probe / ARP announcement).
		// 8-byte fixed header + 4 length-parameterised address
		// fields. 10-entry hardware type table, 4-entry
		// protocol type table, 10-entry operation table.
		// IPv4 + IPv6 protocol address formatting.
		"arp_decode",
		// v0.270 (NATIVE-fit gap — foundational L2 tag
		// protocol): IEEE 802.1Q (C-tag) + 802.1ad (S-tag,
		// QinQ) VLAN tag decoder. Tag walker with 5-entry
		// TPID table (0x8100, 0x88A8, plus legacy QinQ
		// TPIDs); TCI bit breakdown (3-bit PCP / 1-bit DEI
		// / 12-bit VID); 8-entry 802.1p priority name table;
		// VID special-value annotations (priority-tagged,
		// native, reserved); double-tag (QinQ) detection;
		// 10-entry inner EtherType table. Pairs with arp_decode
		// / lldp_decode / cdp_decode for full L2 visibility.
		"vlan_decode",
		// v0.271 (NATIVE-fit gap — datacenter overlay
		// protocol): VXLAN (RFC 7348) + Cisco GBP + GPE
		// variants. 8-byte header (Flags + 24-bit Reserved-1
		// + 24-bit VNI + 8-bit Reserved-2); variant
		// classification (standard / VXLAN-GBP / VXLAN-GPE /
		// non-VXLAN); RFC 7348 conformance check; inner
		// Ethernet peek with 13-entry EtherType name table.
		// Dominant in VMware NSX, OpenStack, Kubernetes
		// (Calico / Flannel / Cilium).
		"vxlan_decode",
		// v0.272 (NATIVE-fit gap — foundational tunneling
		// protocol): GRE per RFC 2784 + RFC 2890 (Key + Seq)
		// + RFC 2637 (PPTP Enhanced GRE V=1). 4-byte
		// mandatory header (C/R/K/S/s/Recur/Version flags +
		// Protocol Type); optional Checksum + Offset, Key,
		// Sequence Number, PPTP Ack Number; 8-entry Protocol
		// Type name table (IPv4 / IPv6 / TEB / PPP / MPLS /
		// Frame Relay / ARP); PPTP Enhanced GRE Call ID +
		// PayloadLength split.
		"gre_decode",
		// v0.273 (NATIVE-fit gap — next-gen datacenter
		// overlay protocol): Geneve per RFC 8926. 8-byte
		// fixed header (Version + 6-bit Option Length + O/C
		// flags + Protocol Type + 24-bit VNI + Reserved) +
		// TLV options walker (Class + Type with C-bit +
		// Length-in-words + Option Data); 6-entry Option
		// Class name table covering IETF + Linux/OVS + VMware
		// + Mellanox + Cisco + Oracle; inner Ethernet peek
		// for canonical TEB case. Rounds out overlay trio
		// with vxlan_decode + gre_decode.
		"geneve_decode",
		// v0.274 (NATIVE-fit gap — foundational service-
		// provider protocol): MPLS label stack dissector per
		// RFC 3032 + 5462. 4-byte-per-label walker (Label
		// 20-bit + TC 3-bit + S 1-bit + TTL 8-bit); iterates
		// until S=1 bottom-of-stack; 8-entry reserved label
		// name table (IPv4/IPv6 Explicit NULL, Router Alert,
		// ELI, GAL, OAM Alert, Extension); inner payload
		// heuristic (IPv4/IPv6/EoMPLS first-nibble);
		// Router-Alert-at-bottom violation note.
		"mpls_decode",
		// v0.275 (NATIVE-fit gap — foundational L2 loop-
		// prevention protocol): STP/RSTP/MSTP BPDU dissector
		// per IEEE 802.1D-2004 + 802.1Q-2014 §13. 4-byte
		// common header (Protocol ID + Version + Type); 31-
		// byte Configuration body (Flags + Root ID + Path
		// Cost + Bridge ID + Port ID + Message Age + Max Age
		// + Hello Time + Forward Delay); RSTP flag bits (TC
		// / Proposal / Port Role / Learning / Forwarding /
		// Agreement / TC Ack); Bridge ID priority + System
		// ID Extension + MAC split; 1/256-sec timer
		// formatting to ms.
		"stp_bpdu_decode",
		// v0.276 (NATIVE-fit gap — foundational cellular
		// telco protocol): GTP-U per 3GPP TS 29.281. 8-byte
		// mandatory header (Flags with V/PT/E/S/PN + Message
		// Type + Length + TEID); optional 4-byte block when
		// E|S|PN set (Seq + NPDU + NextType); typed extension
		// header walker with 9-entry name table (MBMS / MS
		// Info Change / Service Class / RAN Container / Long
		// PDCP / Xw RAN / NR RAN / PDU Session Container);
		// 6-entry Message Type name table (Echo Req/Rsp,
		// Error Indication, Supported Ext Hdrs Notification,
		// End Marker, G-PDU); inner IP heuristic. Used on
		// every cellular S1-U / N3 / N9 interface.
		"gtp_u_decode",
		// v0.277 (NATIVE-fit gap — foundational fixed-line
		// broadband protocol): PPPoE per RFC 2516. 6-byte
		// header (Version+Type + Code + Session ID + Length);
		// 6-entry Code name table (PADI / PADO / PADR / PADS
		// / PADT / Session); Discovery TLV walker with 10-
		// entry Tag Type name table (Service-Name / AC-Name /
		// Host-Uniq / AC-Cookie / Vendor-Specific / Relay-
		// Session-ID / 3 error tags / End-Of-List); Session-
		// stage PPP protocol-ID dispatch with 9-entry name
		// table (IPv4 / IPv6 / IPCP / IPv6CP / LCP / PAP /
		// CHAP / EAP variants).
		"pppoe_decode",
		// v0.278 (NATIVE-fit gap — foundational Internet
		// routing protocol): BGP-4 message dissector per RFC
		// 4271 + RFC 4760 (MP-BGP) + RFC 5492 (Capabilities)
		// + RFC 6793 (4-byte AS) + RFC 2918/7313 (Route
		// Refresh). 19-byte fixed header with all-FFs Marker
		// validation; 5-entry message type table (OPEN /
		// UPDATE / NOTIFICATION / KEEPALIVE / ROUTE-REFRESH);
		// OPEN body with Capability walker (7-entry name
		// table); UPDATE body (Withdrawn Routes + Path
		// Attributes with 13-entry type table + NLRI prefix
		// walker with IPv4 formatting); NOTIFICATION error
		// code + subcode tables; ROUTE-REFRESH AFI/SAFI
		// tables. Runs every ISP backbone / CDN edge / cloud
		// provider network.
		"bgp_message_decode",
		// v0.279 (NATIVE-fit gap — foundational interior
		// gateway routing protocol): OSPFv2 packet dissector
		// per RFC 2328. 24-byte common header (Version + Type
		// + Length + Router ID + Area ID + Checksum + AuType
		// + Auth); 5 packet types with per-type body dispatch
		// (Hello / DBD / LSR / LSU / LSAck); LSA Header
		// 20-byte struct with 9-entry LS Type name table
		// (Router / Network / Summary network / Summary ASBR
		// / AS-External / NSSA External / Opaque variants);
		// AuType 3-entry name table; OSPF Options bit
		// decoding (E / MC / NP / EA / DC / O / DN).
		"ospf_packet_decode",
		// v0.280 (NATIVE-fit gap — foundational link-failure-
		// detection protocol): BFD Control packet dissector
		// per RFC 5880. 24-byte mandatory header (Version +
		// Diagnostic + State + 6 flag bits + Detect Mult +
		// Length + My/Your Discriminators + 3 timing
		// intervals); optional Authentication Section (5
		// entry Auth Type table with Simple Password / Keyed
		// MD5 / Meticulous Keyed MD5 / Keyed SHA1 /
		// Meticulous Keyed SHA1); 9-entry Diagnostic name
		// table; 4-entry State name table; sub-second link
		// failure detection paired with OSPF/BGP/static.
		"bfd_control_decode",
		// v0.281 (NATIVE-fit gap — foundational gateway-
		// redundancy protocol): VRRP per RFC 5798 (v3) +
		// RFC 3768 (v2). 8-byte common header (Version +
		// Type + VRID + Priority + Count + version-specific
		// fields + Checksum); per-version body parsing;
		// IPv4/IPv6 virtual address list walker;
		// VRRPv2 Simple Text auth data decoded; priority
		// semantic notes (0 = withdraw, 100 = default
		// backup, 255 = IP owner).
		"vrrp_decode",
		// v0.282 (NATIVE-fit gap — foundational IPv4
		// multicast group-management protocol): IGMPv2
		// (RFC 2236) + IGMPv3 (RFC 3376). 8-byte v2 fixed
		// header (Type + Max Resp Time + Checksum + Group
		// Address); v3 Query body extension (S/QRV byte +
		// QQIC + Number of Sources + N × Source Addresses);
		// v3 Membership Report body (Number of Group
		// Records + Group Records walker with 6-entry
		// Record Type name table covering MODE_IS_INCLUDE /
		// MODE_IS_EXCLUDE / CHANGE_TO_INCLUDE_MODE /
		// CHANGE_TO_EXCLUDE_MODE / ALLOW_NEW_SOURCES /
		// BLOCK_OLD_SOURCES); auto-detect version from
		// Type + body length; Max Resp Code exp+mantissa
		// decoding per §4.1.1.
		"igmp_decode",
		// v0.283 (NATIVE-fit gap — foundational IPv4
		// multicast routing protocol): PIM-SM v2 per RFC
		// 7761. 4-byte common header (Version + Type +
		// Reserved + Checksum); 11-entry Type name table
		// (Hello / Register / Register-Stop / Join-Prune /
		// Bootstrap / Assert / Graft / Graft-Ack /
		// Candidate-RP / State Refresh / DF Election);
		// per-type body dispatch — Hello with TLV options
		// walker (5-entry option table: Holdtime / LAN
		// Prune Delay / DR Priority / Generation ID /
		// Address List); Register flags (B-bit + N-bit) +
		// encap IP version heuristic; Register-Stop with
		// Encoded Group + Source; Join/Prune with Encoded
		// Unicast Upstream Neighbor + per-group Encoded
		// Group + Joined/Pruned Encoded Source lists;
		// Bootstrap with Fragment Tag + Hash Mask Len +
		// BSR Priority + Encoded Unicast BSR Address;
		// Assert with Encoded Group + Source + RPT bit +
		// metric preference + metric. Pairs with
		// igmp_decode for the host-side multicast picture.
		"pim_decode",
		// v0.284 (NATIVE-fit gap — Cisco-proprietary
		// sibling to vrrp_decode): HSRPv1 per RFC 2281 +
		// HSRPv2 TLV extensions. v1 = 20-byte fixed
		// packet (Version + Op Code + State + Hellotime +
		// Holdtime + Priority + Group + Reserved + 8-byte
		// ASCII Auth Data + 4-byte Virtual IPv4); 3-entry
		// Op Code table (Hello / Coup / Resign); 6-entry
		// State name table (Initial / Learn / Listen /
		// Speak / Standby / Active); priority semantic
		// notes (0 = withdraw, 100 = default Cisco, 255 =
		// maximum). v2 = TLV envelope (3-entry type table:
		// Group State 40B / Text Auth 9B / MD5 Auth 28B)
		// with v2 Group State adding IPv6 support + 6-byte
		// router MAC ID + uint32 priority + sub-second
		// timers. Still extremely common in Cisco-heavy
		// enterprise + datacenter cores.
		"hsrp_decode",
		// v0.285 (NATIVE-fit gap — universal link-
		// aggregation control plane): LACP per IEEE
		// 802.1AX-2020 (formerly 802.3ad). Subtype byte +
		// 1-byte Version + TLV walker with 4-entry type
		// table (Terminator / Actor Information / Partner
		// Information / Collector Information); Actor +
		// Partner 18-byte body (System Priority + 6-byte
		// System ID MAC + Key + Port Priority + Port ID +
		// State bitfield with 8 named flags
		// LACP_Activity / LACP_Timeout / Aggregation /
		// Synchronization / Collecting / Distributing /
		// Defaulted / Expired + Reserved); Collector
		// 14-byte body (Max Delay in 10 µs units +
		// Reserved); Marker subtype 0x02 surfaced as a
		// Note rather than parsed. Closes a key L2
		// visibility gap alongside lldp_decode +
		// cdp_decode + stp_bpdu_decode.
		"lacp_decode",
		// v0.286 (NATIVE-fit gap — universal packet-
		// capture container): libpcap classic '.pcap'
		// file inspector. 24-byte global header with
		// 4-magic dispatch on endianness × timestamp
		// resolution (0xA1B2C3D4 LE-µs / 0xD4C3B2A1 BE-µs
		// / 0xA1B23C4D LE-ns / 0x4D3CB2A1 BE-ns) +
		// version 2.4 check + ~35-entry LINKTYPE_* name
		// table (NULL / ETHERNET / RAW / IEEE802_11 /
		// LINUX_SLL / RADIOTAP / BLUETOOTH_HCI_H4 /
		// IEEE802_15_4 / IPV4 / IPV6 / USBPCAP / NFLOG /
		// LINUX_SLL2 / ZWAVE_TAP and 20+ more); 16-byte
		// per-record header (ts_sec + ts_frac + caplen +
		// origlen) + N-byte payload preview;
		// configurable per-record + per-payload caps;
		// first/last timestamp + duration computed across
		// full file; truncation detection. Every other
		// decoder in the catalog ultimately consumes
		// bytes that came out of a pcap file — this is
		// the meta-tool that surfaces the container.
		"pcap_decode",
		// v0.287 (NATIVE-fit gap — pair to pcap_decode):
		// PCAPng (next-generation packet capture) file
		// inspector. Wireshark's default capture format
		// since 2018 and the emitted format of most
		// modern tcpdump builds. Block-based envelope
		// (4-byte Type + 4-byte Length + body + 4-byte
		// trailing Length back-pointer); per-section
		// endianness dispatch via SHB Byte-Order Magic
		// 0x1A2B3C4D; 9-entry block type table (SHB /
		// IDB / SPB obsolete / NRB / ISB / EPB / IRIG /
		// DSB / Custom); SHB body (BOM + version +
		// section length + options); IDB body (LinkType
		// resolved via the existing libpcap LINKTYPE_*
		// name table + SnapLen + options); EPB body
		// (Interface ID + 64-bit timestamp + caplen +
		// origlen + padded packet data + options);
		// options walker with plausible-text UTF-8
		// surfacing for SHB hardware/os/userappl + IDB
		// if_name/if_description; per-section block
		// summary + configurable record + payload caps.
		"pcapng_decode",
		// v0.288 (NATIVE-fit gap — universal flow-export
		// protocol): NetFlow v5 export packet dissector
		// per Cisco's public NetFlow v5 specification
		// (1996; still emitted by every Cisco / Juniper
		// / Arista router that runs classic NetFlow).
		// 24-byte header (Version + Count + SysUptime +
		// Unix Secs/Nsecs + Flow Sequence + Engine
		// Type/ID + Sampling Interval with 2-bit mode +
		// 14-bit interval) + N × 48-byte flow records
		// (SrcAddr/DstAddr/NextHop IPv4 + Input/Output
		// SNMP ifIndex + dPkts/dOctets + First/Last
		// SysUptime ms with duration derived + Src/DstPort
		// + 8-bit TCP Flags decoded into 8 named bits
		// FIN/SYN/RST/PSH/ACK/URG/ECE/CWR + Protocol with
		// 13-entry IANA name table + ToS + Src/DstAS
		// + Src/DstMask with derived CIDR prefixes).
		// High SIEM + capacity-planning + anomaly-
		// detection value; every NOC sees flows.
		"netflow_v5_decode",
		// v0.289 (NATIVE-fit gap — IPv6 sibling to the
		// existing dhcp_packet_decode): DHCPv6 per RFC
		// 8415. 4-byte fixed header (1-byte msg type +
		// 24-bit transaction ID) or 34-byte Relay-Forward
		// / Relay-Reply header (hop + IPv6 link-addr +
		// IPv6 peer-addr); 13-entry message type table
		// (SOLICIT / ADVERTISE / REQUEST / CONFIRM /
		// RENEW / REBIND / REPLY / RELEASE / DECLINE /
		// RECONFIGURE / INFORMATION-REQUEST / RELAY-FORW
		// / RELAY-REPL); TLV option walker with ~25-entry
		// code name table; DUID parsing (4-entry type
		// table: LLT / EN / LL / UUID) inside ClientID +
		// ServerID; IA_NA / IA_TA / IA_PD body parsing
		// with recursive sub-option walking for IAADDR +
		// IAPREFIX; Status Code with 7-entry name table;
		// DNS Servers + NTP Servers as IPv6 lists. Every
		// dual-stack network runs DHCPv6 alongside SLAAC.
		"dhcpv6_decode",
		// v0.290 (NATIVE-fit gap — IPv6 sibling to the
		// existing ospf_packet_decode): OSPFv3 per RFC
		// 5340. 16-byte common header (Version + Type +
		// Length + Router ID + Area ID + Checksum +
		// Instance ID + Reserved); drops OSPFv2's AuType
		// + Auth (IPv6 relies on IP AH/ESP). 5-entry
		// packet type table (Hello / DBD / LSR / LSU /
		// LSAck) with per-type body dispatch — Hello with
		// Interface ID + Priority + 6-named-bit Options
		// (V6 / E / MC / N / R / DC) + timers + DR/BDR +
		// Neighbor list; DBD with Options + MTU + I/M/MS
		// flags + DD seq; LSR/LSU/LSAck with 20-byte LSA
		// Header decoding (LS Type split into 3-bit
		// flooding scope + 13-bit function code with
		// 9-entry name table: Router / Network / Inter-
		// Area-Prefix / Inter-Area-Router / AS-External
		// / Group-Membership / NSSA / Link / Intra-Area-
		// Prefix). Pairs with ospf_packet_decode for the
		// complete IPv4 + IPv6 OSPF picture.
		"ospfv3_packet_decode",
		// v0.291 (NATIVE-fit gap — third-pillar IP
		// transport): SCTP per RFC 4960 + RFCs 4895 /
		// 5061 / 6525 / 4820 / 3758 for AUTH / ASCONF /
		// RE-CONFIG / PAD / FORWARD-TSN extensions. 12-
		// byte common header (Source Port + Destination
		// Port + Verification Tag + CRC32c Checksum) +
		// chunk walker (4-byte header padded to 4-byte
		// boundary). ~20-entry chunk type name table
		// covering DATA / INIT / INIT_ACK / SACK /
		// HEARTBEAT / ABORT / SHUTDOWN / ERROR / COOKIE_
		// ECHO + extensions. Per-type body decoders for
		// DATA (TSN + Stream ID + SSN + PPID with ~25-
		// entry name table covering M3UA / SUA / IUA /
		// Diameter / S1AP / NGAP / X2AP / XnAP + user
		// data); INIT/INIT_ACK (Initiate Tag + a_rwnd +
		// Outbound/Inbound Streams + Initial TSN + TLV
		// parameters); SACK (Cumulative TSN + a_rwnd +
		// Gap Ack Blocks + Duplicate TSNs); HEARTBEAT;
		// ABORT/ERROR with Error Cause TLV walker (13-
		// entry cause name table). Foundational for telco
		// signalling (SIGTRAN + 3GPP control plane) +
		// WebRTC data channels + multi-homed HA pairs.
		"sctp_packet_decode",
		// v0.292 (NATIVE-fit gap — RADIUS-successor 3GPP
		// AAA carried by SCTP): Diameter per RFC 6733.
		// 20-byte header (Version + 24-bit Length + 8-bit
		// Command Flags with 4 named bits R/P/E/T + 24-
		// bit Command Code + 32-bit Application ID + Hop-
		// by-Hop ID + End-to-End ID); ~20-entry Command
		// Code name table covering Diameter base (CER/CEA
		// / DWR/DWA / DPR/DPA / Re-Auth / Accounting /
		// Credit-Control / Abort-Session / Session-
		// Termination) + 3GPP S6a (Update-Location /
		// Authentication-Information / Cancel-Location /
		// Insert/Delete-Subscriber-Data / Purge-UE /
		// Reset / Notify); ~15-entry Application ID name
		// table (Diameter Base / NASREQ / Credit-Control
		// / 3GPP Cx/Dx / Sh / Rx / Gx / S6a / S13 / S6t
		// / T6a / EAP / SIP / Diameter Relay); AVP walker
		// with V/M/P flags + optional Vendor-ID + 4-byte
		// padding; ~35-entry AVP Code name table; type-
		// aware AVP value decoding (UTF8String / Unsigned
		// 32 / Address); Result-Code class mapping (1xxx
		// Informational / 2xxx Success / 3xxx Protocol
		// Error / 4xxx Transient Failure / 5xxx Permanent
		// Failure). Pairs with radius_packet_decode for
		// complete AAA coverage; carries signalling on
		// every modern cellular network.
		"diameter_packet_decode",
		// v0.293 (NATIVE-fit gap — third pillar AAA):
		// TACACS+ per RFC 8907. Cisco-proprietary AAA, the
		// most common router CLI access protocol on Cisco-
		// heavy networks. 12-byte header (Version major+
		// minor + Packet Type + Sequence Number + Flags +
		// Session ID + Length); 3-entry packet type table
		// (Authentication / Authorization / Accounting);
		// 2-bit flags (UNENCRYPTED, SINGLE_CONNECT). Body
		// dispatched by Type + Seq: AUTH START with Action
		// (LOGIN/CHPASS/SENDPASS/SENDAUTH) + Authen-Type
		// (ASCII/PAP/CHAP/MS-CHAP/ARAP) + Service (LOGIN/
		// ENABLE/PPP/...) + User/Port/RemAddr/Data; AUTH
		// REPLY with Status (PASS/FAIL/GETDATA/GETUSER/
		// GETPASS/RESTART/ERROR/FOLLOW) + Server-Msg; AUTH
		// CONTINUE with User-Msg + ABORT flag; AUTHOR
		// REQUEST/RESPONSE with Authen-Method + named arg
		// list; ACCT REQUEST/REPLY with START/STOP/
		// WATCHDOG flags + named arg list. Optional body
		// decryption per RFC 8907 §4.5 via MD5-derived XOR
		// pad when shared key is supplied. Completes the
		// AAA trio (RADIUS + Diameter + TACACS+) for
		// enterprise + telco + ISP coverage.
		"tacacs_plus_decode",
		// v0.294 (NATIVE-fit gap — foundational file-
		// transfer protocol): TFTP per RFC 1350 + option
		// extensions from RFC 2347 / 2348 / 2349 / 7440.
		// Universal in PXE / network boot, IoT firmware
		// updates, and Cisco / Juniper / Arista config
		// push. 2-byte opcode + 6-entry name table (RRQ /
		// WRQ / DATA / ACK / ERROR / OACK); per-opcode
		// body decoders — RRQ/WRQ with Filename + Mode
		// (netascii/octet/mail) + 4-entry option name
		// table (blksize / timeout / tsize / windowsize);
		// DATA with Block Number + payload (hex preview
		// capped + UTF-8 text surfacing for textual
		// content); ACK with Block Number; ERROR with
		// 9-entry error code name table; OACK with same
		// option layout as RRQ/WRQ.
		"tftp_decode",
		// v0.295 (NATIVE-fit gap — inter-domain
		// multicast): MSDP per RFC 3618. Completes the
		// multicast trio with igmp_decode (host↔router)
		// + pim_decode (intra-domain) + MSDP (inter-
		// domain across PIM-SM domains). 3-byte TLV
		// header (Type + Length); 6-entry message type
		// table (SA / SA Request / SA Response /
		// Keepalive / Notification / 7-8 deprecated
		// traceroute pair); per-type body decoders for
		// SA / SA Response (Entry Count + RP Address +
		// N × 12-byte (S, G) entries + optional
		// encapsulated bootstrap datagram); SA Request
		// (Group Address); Notification (O bit + 7-bit
		// Error Code with 7-entry name table covering
		// Message Header Error / SA-Request Error / SA-
		// Message/Response Error / Hold Timer Expired /
		// FSM Error / Notification / Cease + Subcode +
		// opaque data); Keepalive (empty body).
		"msdp_decode",
		// v0.296 (NATIVE-fit gap — packet-sampling
		// counterpart to NetFlow): sFlow v5 per the InMon
		// publicly-published spec (sflow.org). Dominant
		// monitoring telemetry on every modern datacenter
		// switch (Arista / Cisco Nexus / HP / Juniper QFX
		// / Mellanox / Cumulus); scales linearly with link
		// speed regardless of flow churn. Common datagram
		// header (Version=5 + IPv4/IPv6 agent + sub-agent
		// + sequence + uptime + sample count); sample
		// walker with 4-entry standard format table (Flow
		// Sample / Counter Sample / Expanded variants).
		// Flow Sample body with Sampling Rate (1-in-N) +
		// Source Class+Index + In/Out ifIndex + flow
		// records (Raw Packet Header with 17-entry header
		// protocol table; Ethernet Frame Data; IPv4/IPv6
		// Data). Counter Sample body with Generic
		// Interface Counters (full 19-field ifEntry-
		// equivalent body). Consumed by DDoS-detection +
		// capacity-planning + security-NDR platforms.
		"sflow_v5_decode",
		// v0.297 (NATIVE-fit gap — template-based flow
		// export): NetFlow v9 per RFC 3954. Template-
		// based flow-export format that superseded
		// NetFlow v5 (1996) and bridged to IPFIX (RFC
		// 7011); dominant NetFlow version on modern
		// (post-2010) Cisco / Juniper / Arista
		// enterprise + carrier gear. 20-byte header
		// (Version=9 + Count + SysUptime + UnixSecs +
		// Sequence Number + Source ID); FlowSet walker
		// with 3-kind table (Template / Options Template
		// / Data); Template FlowSet with field-spec
		// walker using ~40-entry IANA Information
		// Element name table covering IN_BYTES /
		// IN_PKTS / PROTOCOL / TCP_FLAGS / L4_*_PORT /
		// IPV4_*_ADDR / IPV6_*_ADDR / SRC/DST_AS /
		// FIRST/LAST_SWITCHED / ICMP_TYPE / SAMPLING_
		// INTERVAL / DIRECTION / FLOW_END_REASON + more;
		// Options Template; Data FlowSet (surfaced as
		// raw hex annotated with referencing Template ID
		// pending stateful template cache).
		"netflow_v9_decode",
		// v0.298 (NATIVE-fit gap — IETF standardization
		// of NetFlow v9): IPFIX per RFC 7011. Differs
		// from v9 in: 16-byte header (drops Source ID,
		// adds explicit Length, renames per-exporter ID
		// to Observation Domain ID); Enterprise-bit-
		// extended Field Specifiers (high bit of Field
		// Type signals 4-byte Enterprise Number after the
		// (15-bit Field Type, Length) pair); Set IDs
		// reserved 0-3 (2 Template, 3 Options Template,
		// 256+ Data). Used by Linux iptables/nftables
		// flow exporters, Cisco ASR/NCS, Juniper modern
		// routers, ntopng, akvorado, GoFlow2, pmacct,
		// every modern flow collector. ~45-entry IPFIX
		// IE name table (camelCase per IANA: octetDelta
		// Count / packetDeltaCount / sourceIPv4Address /
		// destinationIPv6Address / flowEndReason / etc.).
		// Options Template with scope/option field split.
		// Completes the v5 + v9 + IPFIX + sFlow flow-
		// telemetry quartet.
		"ipfix_decode",
		// v0.299 (NATIVE-fit gap — foundational
		// pseudowire encapsulation): L2TPv3 per RFC 3931
		// (UDP-encapsulated mode, port 1701). Pairs with
		// pppoe_decode for the complete broadband
		// subscriber-management story (PPPoE = access
		// side, L2TPv3 = backhaul tunnel to LNS).
		// Dominant transport for ISP lawful intercept
		// (LI), L2 VPN services (Ethernet / ATM / Frame
		// Relay / PPP / HDLC pseudowires), and wholesale
		// subscriber backhaul. 16-bit bit-packed common
		// header (T/L/x/S/x/Version=3); Control Message
		// (T=1) with Length + Connection ID + Ns + Nr +
		// AVP walker; Data Message (T=0) with Session ID
		// + opaque payload preview. ~20-entry IETF AVP
		// name table; 15-entry Message Type name table
		// (SCCRQ/SCCRP/SCCCN/StopCCN/HELLO/OCRQ/OCRP/
		// OCCN/ICRQ/ICRP/ICCN/CDN/WEN/SLI/ACK); Hidden
		// (encrypted) AVP detection.
		"l2tp_v3_decode",
		// v0.300 (NATIVE-fit gap — IPsec data-plane
		// protocols, milestone release): ESP per RFC
		// 4303 + AH per RFC 4302 in one internal/ipsec
		// package, two Specs. ESP: 8-byte plaintext
		// header (SPI + Sequence) + opaque encrypted
		// payload + trailer + ICV (surfaced as hex
		// preview). AH: 12-byte fixed header (Next
		// Header + Payload Length + Reserved + SPI +
		// Sequence) + variable-length ICV (size derived
		// from PL field). 13-entry Next Header IP-
		// protocol name table for AH (TCP/UDP/ICMP/
		// IPv4/IPv6 tunnel-mode/GRE/ESP/AH chained/
		// ICMPv6/OSPF/PIM/SCTP). SPI semantic notes (0
		// reserved, 1-255 IANA-reserved, ≥256
		// negotiated). Universal IPsec data-plane on
		// every site-to-site VPN + IPsec remote-access
		// deployment.
		"esp_decode",
		"ah_decode",
		// v0.301 (NATIVE-fit gap — IPsec control-plane
		// companion to ESP+AH): IKEv2 per RFC 7296.
		// Universal on every site-to-site VPN + IPsec
		// remote-access deployment. UDP port 500 (or 4500
		// with NAT-T marker stripped). 28-byte fixed
		// header (Initiator SPI + Responder SPI + Next
		// Payload + Version + Exchange Type + Flags +
		// Message ID + Length); 4-entry exchange type
		// table (IKE_SA_INIT / IKE_AUTH / CREATE_CHILD_SA
		// / INFORMATIONAL); 3-bit flag decode (R / V /
		// I). Chained payload walker via Next Payload +
		// 4-byte payload header; ~15-entry payload type
		// table (SA / KE / IDi / IDr / CERT / CERTREQ /
		// AUTH / Nonce / Notify / Delete / Vendor ID /
		// TSi / TSr / SK encrypted / CP / EAP). Notify
		// payload body decoded with ~30-entry message
		// type name table + Error/Status class. SK
		// payload surfaced as opaque hex with key-state
		// note.
		"ike_v2_decode",
		// v0.302 (NATIVE-fit gap — Windows auth on every
		// AD-joined network): NTLM (MS-NLMP) message
		// dissector. Auto-detect via 8-byte "NTLMSSP\0"
		// signature + 4-byte little-endian MessageType.
		// 3-entry message type table (NEGOTIATE / CHALLENGE
		// / AUTHENTICATE). Per-type body decoders: Type 1
		// with NegotiateFlags + Domain + Workstation
		// fields + optional Version; Type 2 with
		// TargetName + 8-byte ServerChallenge +
		// TargetInfo AV pair walker; Type 3 with
		// LmChallengeResponse + NtChallengeResponse (the
		// hashcat-crackable response) + DomainName +
		// UserName + Workstation + EncryptedSessionKey.
		// ~22-entry NegotiateFlags named-bit set; 10-
		// entry AvId name table; 8-byte Version structure
		// decode. Universal in SMB / HTTP / LDAP /
		// DCERPC on Windows-heavy enterprise + AD-joined
		// infrastructure. High pentest + DFIR value as
		// Type 2 + Type 3 messages feed directly into
		// hashcat for offline password recovery.
		"ntlm_decode",
		// v0.303 (NATIVE-fit gap — modern NAT/firewall
		// config protocol): PCP per RFC 6887. Supersedes
		// NAT-PMP (RFC 6886); adds IPv6 + peer-mapping +
		// TLV options. Universal in residential broadband
		// CPE + CGNAT enforcement; used by uTorrent /
		// Tailscale's libpcp / libnatpmp / miniupnpd.
		// UDP port 5351. 24-byte common header with R-bit
		// dispatch; 3-entry opcode table (ANNOUNCE / MAP
		// / PEER); request/response header decoders; MAP
		// body (Nonce + Protocol + Internal Port +
		// Suggested External Port + IPv6-mapped External
		// IP); PEER body (MAP + Remote Peer Port +
		// Address); 14-entry Result Code name table;
		// 5-entry option code name table (THIRD_PARTY /
		// PREFER_FAILURE / FILTER / NAT64_PREFIX /
		// PORT_SET); 10-entry IP-protocol name table.
		"pcp_decode",
		// v0.304 (NATIVE-fit gap — predecessor to PCP):
		// NAT-PMP per RFC 6886. Apple's 2008 design that
		// PCP superseded in 2013 but which remains widely
		// deployed in older residential broadband CPE
		// (Apple Airport / Time Capsule / early Asus /
		// Belkin / Linksys before ~2014). Modern P2P
		// applications try NAT-PMP first then fall back
		// to UPnP IGD. Tight 2/12/16-byte fixed-position
		// messages; 6-entry opcode name table covering
		// requests + responses for Public Address / Map
		// UDP / Map TCP; 6-entry Result Code name table
		// (SUCCESS / UNSUPP_VERSION / NOT_AUTHORIZED /
		// NETWORK_FAILURE / OUT_OF_RESOURCES /
		// UNSUPPORTED_OPCODE). Version=2 detection
		// (signals PCP, surfaces a pcp_decode pointer).
		"natpmp_decode",
		// v0.305 (NATIVE-fit gap — fourth-pillar IP
		// transport): DCCP per RFC 4340. Niche transport
		// alongside TCP/UDP/SCTP designed for real-time
		// media + interactive games that want UDP-style
		// unreliable delivery plus TCP-style congestion
		// control. Generic header (Source/Dest Port +
		// Data Offset + CCVal/CsCov + Checksum + Type/X
		// bits); 10-entry packet type name table (Request
		// / Response / Data / Ack / DataAck / CloseReq /
		// Close / Reset / Sync / SyncAck); short (X=0
		// 24-bit seq) vs extended (X=1 48-bit seq)
		// header dispatch; per-type body decoders for
		// Request/Response (Service Code), Ack-family
		// (8-byte Ack subheader), Reset (Ack subheader
		// + 12-entry Reset Code name table); IP protocol
		// 33.
		"dccp_packet_decode",
		// v0.306 native-fit gap: ptpv2_decode is a pure
		// offline dissector for PTPv2 (IEEE 1588-2008)
		// Precision Time Protocol packets — 34-byte common
		// header (transportSpecific + messageType + version
		// + length + domain + flagField + 64-bit
		// correctionField + 10-byte sourcePortIdentity +
		// sequenceId + controlField + logMessageInterval);
		// 10-entry messageType name table (Sync /
		// Delay_Req / Pdelay_Req / Pdelay_Resp / Follow_Up
		// / Delay_Resp / Pdelay_Resp_Follow_Up / Announce /
		// Signaling / Management); per-type body decoders
		// for timestamp-bearing event/general messages, the
		// 30-byte Announce body (with BMCA inputs:
		// priority1, clockQuality, grandmasterIdentity,
		// stepsRemoved, timeSource); timeSource +
		// clockAccuracy name tables; flagField decoded set.
		// UDP/319 (event) + UDP/320 (general) or EtherType
		// 0x88F7.
		"ptpv2_decode",
		// v0.307 native-fit gap: someip_decode is a pure
		// offline dissector for SOME/IP per AUTOSAR R23-11
		// — 16-byte header (Service ID + Method ID with
		// high-bit event marker + Length + Client ID +
		// Session ID + Protocol/Interface Version +
		// Message Type with TP-bit + Return Code); 8-entry
		// messageType name table (REQUEST /
		// REQUEST_NO_RETURN / NOTIFICATION / *_ACK /
		// RESPONSE / ERROR); 12-entry returnCode name
		// table (E_OK through E_E2E_REPEATED, plus
		// application-specific 0x20-0x5E); SOME/IP-SD body
		// decoder (Service 0xFFFF + Method 0x8100) with
		// Reboot/Unicast flags + Entries[] (Service +
		// Eventgroup variants with TTL=0 stop-semantics)
		// + Options[] (IPv4/IPv6 endpoint with L4 + port).
		// The automotive Ethernet RPC companion to
		// canbus_*.
		"someip_decode",
		// v0.308 native-fit gap: dnp3_decode is a pure
		// offline dissector for DNP3 per IEEE 1815-2012 —
		// 10-byte data-link header (Start sync + Length +
		// Control with DIR/PRM/FCB/FCV + Destination +
		// Source + Header CRC); 5-entry primary + 4-entry
		// secondary link function-code name tables; user-
		// data block walker that strips per-16-byte-block
		// CRCs; transport function byte (FIN/FIR + 6-bit
		// sequence); application header (Application
		// Control with FIR/FIN/CON/UNS + sequence +
		// Function Code + 16-bit IIN for responses); 20+
		// entry application function code name table
		// (CONFIRM / READ / WRITE / SELECT / OPERATE /
		// DIRECT_OPERATE / FREEZE / RESTART / ENABLE/
		// DISABLE_UNSOLICITED / DELAY_MEASURE /
		// RECORD_CURRENT_TIME / AUTHENTICATE_REQ /
		// RESPONSE / UNSOLICITED_RESPONSE /
		// AUTHENTICATE_RESP); 16-entry IIN-bit decoded set
		// (BROADCAST / CLASS_1-3_EVENTS / NEED_TIME /
		// LOCAL_CONTROL / DEVICE_TROUBLE / DEVICE_RESTART
		// + NO_FUNC_CODE_SUPPORT / OBJECT_UNKNOWN /
		// PARAMETER_ERROR / EVENT_BUFFER_OVERFLOW /
		// ALREADY_EXECUTING / CONFIG_CORRUPT). Dominant
		// utility-SCADA protocol in North American power-
		// grid, water, and oil-and-gas telemetry. Default
		// TCP port 20000.
		"dnp3_decode",
		// v0.309 native-fit gap: iec104_decode is a pure
		// offline dissector for IEC 60870-5-104 APDUs —
		// 6-byte APCI (0x68 sync + Length + 4-byte
		// Control field) + three frame formats (I/S/U
		// dispatched on low 2 bits of control byte 0);
		// U-format function bits (STARTDT/STOPDT/TESTFR
		// act+con); I-format 6-byte ASDU header (Type ID
		// + Variable Structure Qualifier + Cause of
		// Transmission with P/N + T bits + originator
		// address + Common Address); 40+ entry Type ID
		// name table; 20-entry Cause name table. The
		// EU/Asia counterpart to dnp3_decode; default TCP
		// port 2404; dominant on substation/control-
		// centre boundary in European + Asian power-grid
		// operators.
		"iec104_decode",
		// v0.310 native-fit gap: s7comm_decode is a pure
		// offline dissector for classic S7Comm PDUs over
		// ISO-on-TCP (RFC 1006, port 102) — 4-byte TPKT
		// header + variable COTP header + 10/12-byte S7
		// header (protoID 0x32 + ROSCTR + reserved + PDU
		// reference + parameter length + data length +
		// optional error class/code for Ack/Ack-Data); 9-
		// entry COTP PDU type name table; 4-entry ROSCTR
		// name table (Job_Request / Ack / Ack_Data /
		// Userdata); 15-entry function-code name table
		// (Read_Var / Write_Var / Setup_Communication /
		// PLC_Control / Start_Upload / Request_Download
		// ...); 9-entry Error Class name table.
		// Siemens S7-300/400/1200/1500 PLC protocol;
		// canonical Stuxnet target; dominant in
		// EU/Asian factory automation.
		"s7comm_decode",
		// v0.311 native-fit gap: goose_decode is a pure
		// offline dissector for IEC 61850-8-1 GOOSE
		// messages — 8-byte fixed header (APPID + Length
		// + Reserved1 + Reserved2) + ASN.1 BER-encoded
		// IECGoosePdu with context-class implicit tags
		// 0x80-0xAB (gocbRef / timeAllowedToLive /
		// datSet / goID / UtcTime / stNum / sqNum /
		// test / confRev / ndsCom / numDatSetEntries /
		// allData); BER length walker for short and
		// long form; signed BER INTEGER decode; UtcTime
		// 8-byte breakdown (4-byte secondsSinceEpoch +
		// 3-byte fractionOfSecond + 1-byte quality);
		// IEC 62351-6 security_trailer_hex surfacing.
		// Time-critical multicast Ethernet protocol
		// (EtherType 0x88B8) for protective-relay trip
		// signalling in modern digital substations;
		// 4 ms latency budget per IEC 61850-5 Type 1A.
		"goose_decode",
		// v0.312 native-fit gap: enip_decode is a pure
		// offline dissector for EtherNet/IP encapsulation
		// + CIP messages per ODVA CIP Vol 1/2 — 24-byte
		// LE encapsulation header (Command + Length +
		// Session Handle + Status + Sender Context +
		// Options); 9-entry Command name table (NOP /
		// ListServices / ListIdentity / ListInterfaces /
		// RegisterSession / UnRegisterSession /
		// SendRRData / SendUnitData / IndicateStatus /
		// Cancel); 7-entry Status name table; Common
		// Packet Format walker for SendRRData /
		// SendUnitData with 8-entry item type name
		// table (Null / ListIdentity_item /
		// Connected_Address / Connected_Data /
		// Unconnected_Data / ListServices_response /
		// Sockaddr_O2T/T2O); CIP message decoder for
		// Unconnected_Data items with 30+ entry
		// service code name table (Get_Attribute_Single
		// / Read_Tag / Write_Tag / Forward_Open ...) +
		// 20+ entry general status name table. The
		// dominant North American factory-floor PLC
		// protocol; Allen-Bradley/Rockwell / Omron /
		// Cognex; TCP/44818 explicit + UDP/2222
		// implicit (class 1).
		"enip_decode",
		// v0.313 native-fit gap: profinet_dcp_decode is
		// a pure offline dissector for Profinet DCP per
		// IEC 61158-6-10 — 2-byte FrameID with name
		// table (Hello / Get_Set / Identify_Request /
		// Identify_Response) + 10-byte fixed DCP header
		// (ServiceID + ServiceType + Xid +
		// ResponseDelay + DataLength) + TLV block
		// walker with Option/Suboption name tables (IP
		// / DeviceProperties / DHCP / LLDP /
		// ControlBlock / DeviceInitiative /
		// AllSelector); per-suboption decoders
		// surfacing MAC + IP/Mask/GW + Vendor +
		// NameOfStation + VendorID/DeviceID +
		// DeviceRole bitmask. EtherType 0x8892 L2-only;
		// bootstrap discovery protocol for Siemens
		// Profinet networks; pairs with s7comm_decode.
		"profinet_dcp_decode",
		// v0.314 native-fit gap (top-30 #10):
		// usb_badusb_classify is the defensive sibling
		// of the badusb_* family — reconstructs
		// keystrokes + a DuckyScript-style transcript
		// from a stream of USB HID Keyboard Boot
		// Protocol reports (8-byte reports: modifier
		// bitmap + 6 active HID Usage codes). 80+ entry
		// HID Usage code name + Shift-variant table;
		// key-down event detection by report-to-report
		// diffing; Caps Lock state tracking;
		// reconstructed text + DuckyScript v1-style
		// transcript with STRING folding + modifier/key
		// combinations + non-printable keyword mapping
		// (ENTER / ESC / GUI / CTRL / arrow keys /
		// F-keys). Forensic primitive for incident
		// response on suspected BadUSB attacks.
		"usb_badusb_classify",
		// v0.315 native-fit gap: zwave_decode is a pure
		// offline dissector for classic Z-Wave MAC-layer
		// frames per Sigma Designs SDS-12852 — 9-byte
		// fixed header (4-byte HomeID + 1-byte SourceNode
		// + 2-byte Frame Control with Header Type +
		// Routed/AckReq/LowPower/SpeedModified/Beam +
		// 4-bit Sequence + 1-byte Length + 1-byte
		// DestNode) + payload (Command Class + Command +
		// parameters) + 1-byte XOR checksum. 4-entry
		// Header Type name table (Singlecast / Multicast
		// / Ack / Explore); 30+ entry Command Class
		// name table (BASIC / SWITCH_BINARY /
		// SWITCH_MULTILEVEL / SENSOR_* / THERMOSTAT_* /
		// DOOR_LOCK / USER_CODE / CONFIGURATION /
		// ALARM / BATTERY / WAKE_UP / SECURITY S0 /
		// SECURITY_2 S2 ...). Sub-GHz IoT mesh
		// protocol (868/908/920 MHz on ITU-T G.9959
		// FSK PHY); pairs with Flipper Zero RF capture
		// for Yale / Kwikset / Schlage Z-Wave lock
		// attacks.
		"zwave_decode",
		// v0.316 native-fit gap: opcua_decode is a pure
		// offline dissector for OPC UA Binary messages
		// per IEC 62541-6 — 8-byte message header (3-
		// byte ASCII MessageType + 1-byte ChunkType +
		// 4-byte MessageSize LE); 7-entry MessageType
		// name table (HEL Hello / ACK Acknowledge /
		// ERR Error / MSG Message / OPN
		// OpenSecureChannel / CLO CloseSecureChannel /
		// RHE ReverseHello); 3-entry ChunkType name
		// table (Final / Intermediate / Abort); per-
		// MessageType body decoders for HEL (buffer
		// sizes + EndpointURL), ACK (mirrors HEL minus
		// URL), ERR (StatusCode + Reason), OPN
		// (asymmetric security header with
		// SecureChannelId + SecurityPolicyUri +
		// SenderCertificate + ReceiverThumbprint +
		// SequenceNumber + RequestId), MSG / CLO
		// (symmetric security header with
		// SecureChannelId + TokenId + SequenceNumber
		// + RequestId); UA String + UA ByteString
		// helpers with null-string handling. Modern
		// industrial-messaging protocol; sits ABOVE
		// the field-protocol family; default TCP port
		// 4840.
		"opcua_decode",
		// v0.317 native-fit gap: mqtt_sn_decode is a
		// pure offline dissector for MQTT-SN (MQTT for
		// Sensor Networks) v1.2 per OASIS spec — UDP
		// variant of MQTT for constrained IoT devices.
		// Variable-length header (1-byte short form
		// 1-255; 0x01 long-form indicator + uint16 BE
		// length); 28-entry MsgType name table
		// (ADVERTISE / SEARCHGW / GWINFO / CONNECT /
		// CONNACK / WILLTOPIC* / REGISTER / REGACK /
		// PUBLISH / PUBACK / SUBSCRIBE / SUBACK /
		// PINGREQ / PINGRESP / DISCONNECT ...); Flags
		// byte decode (DUP / QoS including MQTT-SN-
		// specific QoS=-1 fire-and-forget / Retain /
		// Will / CleanSession / TopicIdType); per-
		// MsgType body decoders for CONNECT, REGISTER,
		// PUBLISH, SUBSCRIBE, etc.; 4-entry ReturnCode
		// name table; topic-id-type name table.
		// Default UDP port 1883; common in LoRaWAN/
		// Zigbee/6LoWPAN gateway backhaul + industrial
		// sensor telemetry.
		"mqtt_sn_decode",
		// v0.318 native-fit gap: ssdp_decode is a pure
		// offline dissector for SSDP (Simple Service
		// Discovery Protocol) per UPnP Device
		// Architecture 1.1 — HTTP-over-UDP on multicast
		// 239.255.255.250:1900. Three message kinds
		// (M-SEARCH request / NOTIFY announcement /
		// HTTP/1.1 search response); case-insensitive
		// header parser surfacing canonical UPnP
		// fields (Host / Cache-Control with max-age
		// extraction / Location / Server / ST / USN
		// with usn_uuid + usn_nt deconstruction / NT /
		// NTS / MAN / MX / BOOTID.UPNP.ORG /
		// CONFIGID.UPNP.ORG / SEARCHPORT.UPNP.ORG);
		// vendor headers surfaced as generic
		// other_headers map. Foundational IoT/
		// consumer-network reconnaissance protocol;
		// common in CTF + home-network pentest + UPnP-
		// IGD attack chains.
		"ssdp_decode",
		// v0.319 native-fit gap: nbns_decode is a pure
		// offline dissector for NBNS (NetBIOS Name
		// Service) per RFC 1001 + RFC 1002 — UDP/137.
		// 12-byte DNS-style header (TxID + Flags +
		// QD/AN/NS/AR counts); flags decode (QR +
		// Opcode + AA + TC + RD + RA + Broadcast +
		// RCODE); 5-entry Opcode name table (QUERY /
		// REGISTRATION / RELEASE / WACK / REFRESH);
		// 8-entry RCODE name table (No_Error /
		// Format_Error / Server_Failure / Name_Error /
		// Not_Implemented / Refused_Error /
		// Active_Error / Conflict_Error); NetBIOS
		// name decoder (32-byte wire encoding → 15-
		// byte trimmed name + 1-byte suffix); 20+
		// entry NetBIOS suffix name table
		// (Workstation / Master_Browser / Messenger /
		// Domain_Master_Browser / Domain_Controllers
		// / File_Server / RAS_Server etc.); NB-type
		// resource record decoder with IPv4 list
		// extraction; RFC 1035 compression pointer
		// traversal. Canonical target of Responder.py
		// NBNS poisoning attacks; common in DEF CON
		// Recon Village + AD pentest engagements.
		"nbns_decode",
		// v0.320 native-fit gap: ndp_decode is a pure
		// offline dissector for ICMPv6 NDP per RFC
		// 4861 + 4191 + 8106. 4-byte ICMPv6 header +
		// 5-entry NDP type name table
		// (Router_Solicitation /
		// Router_Advertisement /
		// Neighbor_Solicitation /
		// Neighbor_Advertisement / Redirect); per-
		// type body decoders (RA: CurHopLimit + M/O/
		// H/Prf/Proxy flags + RouterLifetime +
		// ReachableTime + RetransTimer; NS/NA/
		// Redirect: TargetAddress + (NA R/S/O flags
		// + Redirect Destination Address)); NDP
		// Options TLV walker with 9-entry name
		// table (Source/Target_Link_Layer_Address /
		// Prefix_Information / Redirected_Header /
		// MTU / Nonce / Route_Information / RDNSS /
		// DNSSL); per-option decoders for LLA (MAC),
		// Prefix Info (prefix + L/A/R flags +
		// lifetimes), MTU, RDNSS (DNS server list
		// with lifetime), DNSSL (search-domain
		// list), Route Information. Foundational
		// IPv6 protocol; canonical mitm6 +
		// suddensix + fake_router6 pentest target.
		"ndp_decode",
		"ipv6_eui64_recover",
		// v0.321 native-fit gap: llmnr_decode is a
		// pure offline dissector for LLMNR (Link-
		// Local Multicast Name Resolution) per RFC
		// 4795 — UDP/5355 multicast 224.0.0.252 /
		// FF02::1:3. 12-byte DNS-style header with
		// LLMNR-specific Flags interpretation (QR +
		// Opcode=0 LLMNR_QUERY + bit 10 C Conflict
		// + TC + bit 8 T Tentative + RCODE); DNS
		// label-encoded name walker per RFC 4795
		// §2.1.7 (explicitly forbids compression
		// pointers — rejects 0xC0+ prefix as
		// malformed); per-RR-type RDATA decoders for
		// A (IPv4) / AAAA (IPv6) / PTR / CNAME +
		// other types surfaced as opaque hex. The
		// canonical Responder.py poisoning target
		// alongside NBNS for capturing NTLMv2
		// challenge-response hashes; common in DEF
		// CON Recon Village + AD pentest
		// engagements.
		"llmnr_decode",
		// v0.322 native-fit gap: mdns_decode is a pure
		// offline dissector for Multicast DNS per RFC
		// 6762 + DNS-SD per RFC 6763 — UDP/5353
		// multicast 224.0.0.251 / FF02::FB. 12-byte
		// DNS-style header with mDNS-specific Flags
		// interpretation; DNS label walker with full
		// compression-pointer support; question
		// records with QU bit (top bit of QCLASS —
		// Question Unicast response preferred); answer
		// records with Cache-Flush bit (top bit of
		// CLASS); 9+ entry RR-type name table (A / NS
		// / CNAME / SOA / PTR / MX / TXT / AAAA / SRV
		// / OPT / NSEC); per-RR-type RDATA decoders
		// for A → IPv4, AAAA → IPv6, PTR/CNAME →
		// name, SRV → priority + weight + port +
		// target, TXT → list of key=value pairs (DNS-
		// SD §6). Completes the Windows + Bonjour
		// name-resolution trio (nbns + llmnr + mdns);
		// canonical decode for AirDrop / AirPrint /
		// Chromecast / HomeKit / Spotify Connect /
		// Sonos enumeration.
		"mdns_decode",
		// v0.323 native-fit gap: openflow_decode is a
		// pure offline dissector for OpenFlow control-
		// channel messages per ONF specs 1.0/1.3/1.5 —
		// the canonical SDN control protocol over TCP/
		// 6653 (modern) / TCP/6633 (legacy) between SDN
		// controllers (ONOS / OpenDaylight / Ryu /
		// Floodlight / Faucet) and OpenFlow-capable
		// switches (Open vSwitch / Pica8 / Cisco
		// Catalyst OpenFlow / Arista). 8-byte common
		// header (Version + Type + Length + XID); 6-
		// entry Version name table; 35-entry Type name
		// table (HELLO / ERROR / ECHO_*/FEATURES_*/
		// GET_CONFIG_*/SET_CONFIG/PACKET_IN/OUT/
		// FLOW_MOD/FLOW_REMOVED/PORT_STATUS/GROUP_MOD/
		// METER_MOD/TABLE_MOD/MULTIPART_*/BARRIER_*/
		// ROLE_*/ASYNC_*/BUNDLE_*); per-Type body
		// decoders for HELLO (version bitmap TLVs),
		// ERROR (14-entry error-type name table),
		// FEATURES_REPLY (datapath_id + n_buffers +
		// n_tables + auxiliary_id + capabilities
		// bitmap with 7-entry decoded set), ECHO
		// (opaque payload); other types surfaced as
		// body_hex for downstream walkers. Common in
		// datacenter SDN research + OpenFlow-
		// controller fuzzing engagements.
		"openflow_decode",
		// v0.324 native-fit gap: gsmtap_decode is a
		// pure offline dissector for GSMTAP cellular
		// protocol tap encapsulation per Osmocom —
		// UDP/4729. 16-byte fixed pseudo-header
		// (Version + HeaderLen + PayloadType +
		// Timeslot + ARFCN with band/uplink bits +
		// Signal level signed dBm + SNR signed +
		// Frame Number + SubType + Antenna + SubSlot
		// + Reserved); 15+ entry PayloadType name
		// table (UM_L2 / ABIS / UM_BURST / SIM /
		// UMTS_RLC_MAC / LTE_RRC / LTE_MAC /
		// OSMOCORE_LOG / QC_DIAG / etc.); 17-entry
		// GSM Um L2 channel name table (BCCH / CCCH
		// / RACH / AGCH / PCH / SDCCH variants /
		// TCH_F/H / PACCH / CBCH / PDCH / PTCCH /
		// VOICE_F/H); LTE RRC channel direction
		// decode (even=DL, odd=UL); ARFCN band +
		// uplink/downlink bit extraction. Common in
		// DEF CON / Black Hat / HITB cellular CTFs
		// + SDR research + 5G IMSI-catcher
		// forensics.
		"gsmtap_decode",
		"imei_decode",
		// v0.325 native-fit gap: hart_ip_decode is a
		// pure offline dissector for HART-IP per HART
		// Foundation HCF_SPEC-085 — UDP/TCP port
		// 5094. 8-byte envelope header (Version +
		// Message Type + Message ID + Status Code +
		// Sequence Number + Byte Count); 4-entry
		// Message Type name table (Request /
		// Response / Publish / NAK); 6-entry Message
		// ID name table (Session_Initiate /
		// Session_Close / Keep_Alive / HART_PDU /
		// Direct_PDU / Publish_Burst_Notify);
		// encapsulated HART payload surfaced as
		// hart_payload_hex for downstream HART
		// command walkers. The process-automation
		// dissector for oil/gas/chemical/water
		// plants; pairs with the industrial protocol
		// family for full coverage from field
		// instruments through DCS/SCADA to MES.
		"hart_ip_decode",
		// v0.326 native-fit gap: rtsp_decode is a
		// pure offline dissector for RTSP per RFC
		// 7826 (RTSP 2.0) + RFC 2326 (RTSP 1.0) —
		// TCP/554. Three message kinds: Request
		// (METHOD URL RTSP/version), Response
		// (RTSP/version code reason), Interleaved
		// RTP (binary $ + channel + length +
		// payload). 11-entry Method name table
		// (OPTIONS / DESCRIBE / ANNOUNCE / SETUP /
		// PLAY / PAUSE / TEARDOWN / GET_PARAMETER /
		// SET_PARAMETER / REDIRECT / RECORD); HTTP-
		// style status code categorisation
		// (Informational / Success / Redirection /
		// Client_Error / Server_Error /
		// Vendor_Error); case-insensitive header
		// parser surfacing canonical RTSP fields
		// (CSeq / Session / Transport / Range /
		// Scale / Speed / Public / Allow / RTP-
		// Info / Content-Type/Length / User-Agent /
		// Server / Date / WWW-Authenticate /
		// Authorization). The canonical IP-camera
		// pentest entry point — Hikvision / Axis /
		// Dahua / Bosch / Vivotek / Pelco; pairs
		// with sdp_decode + rtp_decode for full
		// streaming-stack coverage.
		"rtsp_decode",
		// v0.327 native-fit gap: smtp_decode is a pure
		// offline dissector for SMTP per RFC 5321 —
		// TCP/25 (MTA) / 587 (submission STARTTLS) /
		// 465 (implicit-TLS SMTPS). Two message kinds
		// discriminated by first character: Server
		// Response (3-digit status code + - or space
		// continuation + text, multi-line aggregation
		// per §4.2.1); Client Command (verb + optional
		// argument). 14+ entry Verb name table (HELO /
		// EHLO / AUTH / MAIL / RCPT / DATA / RSET /
		// VRFY user-enum target / EXPN / QUIT /
		// STARTTLS / HELP / NOOP / BDAT); HTTP-style
		// status categorisation (Success /
		// Intermediate / Transient_Error /
		// Permanent_Error); EHLO multi-line extension
		// aggregation. Canonical decode for Exim /
		// Postfix / Sendmail / Exchange / O365 / Google
		// Workspace MTAs.
		"smtp_decode",
		// v0.328 native-fit gap: pop3_decode is a pure
		// offline dissector for POP3 per RFC 1939 + RFC
		// 2449 (CAPA) + RFC 2595 (STLS) + RFC 5034
		// (AUTH SASL) — TCP/110 cleartext / TCP/995
		// implicit-TLS POP3S. Two message kinds: Server
		// Response (+OK / -ERR + text; multi-line for
		// LIST/RETR/TOP/UIDL/CAPA with '.' terminator
		// and byte-stuffing removal per §3); Client
		// Command (verb + optional argument). 15+
		// entry Verb name table (USER / PASS / APOP /
		// STAT / LIST / RETR / DELE / NOOP / RSET /
		// QUIT / TOP / UIDL / STLS / CAPA / AUTH);
		// status indicator categorisation (Success /
		// Error); multi-line data aggregation with
		// byte-stuffing removal. Pairs with
		// smtp_decode for the email-protocol pair;
		// canonical decode for Dovecot / Courier /
		// qmail-pop3d / Exchange POP3 servers; common
		// in credential-spray + APOP timestamp-leakage
		// pentests.
		"pop3_decode",
		// v0.329 native-fit gap: imap4_decode is a pure
		// offline dissector for IMAP4rev1 per RFC 3501 +
		// RFC 2595 (STARTTLS) + RFC 2087 (QUOTA) + RFC
		// 2342 (NAMESPACE) + RFC 2177 (IDLE) + RFC 2971
		// (ID) — TCP/143 cleartext / 993 implicit-TLS
		// IMAPS. Four message kinds: Continuation (+ /
		// SASL multi-step prompt); Untagged Response (*
		// / data or status); Command + Tagged Response
		// (disambiguated by second token — OK/NO/BAD/
		// BYE/PREAUTH → Tagged Response, else Command).
		// 25+ entry Verb name table (LOGIN cleartext-
		// creds risk / AUTHENTICATE / SELECT / EXAMINE
		// / CREATE / DELETE / RENAME / SUBSCRIBE /
		// UNSUBSCRIBE / LIST / LSUB / STATUS / APPEND /
		// CHECK / CLOSE / EXPUNGE / SEARCH / FETCH
		// content-disclosure risk / STORE / COPY / UID
		// / NOOP / LOGOUT / CAPABILITY / STARTTLS /
		// IDLE / NAMESPACE / ID); 5-entry Status name
		// table (OK / NO / BAD / BYE / PREAUTH); 15+
		// entry Untagged Type name table; continuation
		// prompt extraction; numeric-prefix '* 12
		// EXISTS' detection. Completes the email-
		// protocol triad with smtp_decode + pop3_decode.
		"imap4_decode",
		// v0.330 native-fit gap: kerberos_decode is a pure
		// offline dissector for Kerberos v5 per RFC 4120 —
		// the authentication protocol underpinning every
		// Active Directory deployment + most enterprise SSO
		// stacks (MIT Kerberos, Heimdal, Microsoft AD, Apple
		// Open Directory, FreeIPA / IdM). UDP/88 + TCP/88.
		// Canonical AD-pentest decoder — the highest-value
		// AD dissector in the catalogue — because the wire
		// format leaks: username enumeration (every AS-REQ
		// carries cname in cleartext); AS-REP roasting (when
		// PA-ENC-TIMESTAMP is absent from padata, the
		// account is AS-REP-roastable — hashcat mode 18200);
		// encryption type downgrade audit (etype reveals
		// rc4-hmac support, weak); realm + SPN disclosure
		// (the Kerberoasting enumeration goldmine);
		// Kerberoasting recon (observing TGS-REQ traffic
		// pre-targets high-privilege service accounts).
		// 7-entry message type name table (AS-REQ / AS-REP
		// / TGS-REQ / TGS-REP / AP-REQ / AP-REP /
		// KRB-ERROR); AS-REQ / TGS-REQ body walker with
		// cname / realm / sname / etype extraction;
		// pre_auth_required boolean (PA-ENC-TIMESTAMP
		// presence detection); 11-entry Encryption Type
		// name table; 8-entry PA-DATA type name table;
		// AS-REP / TGS-REP body walker with ticket + enc-
		// part byte-length surfacing; KRB-ERROR body walker
		// with 13-entry error-code name table. Encrypted
		// ticket + enc-part NOT decrypted (offline hashcat
		// modes 18200 AS-REP + 13100 Kerberoast TGS are the
		// next step); PAC + PKINIT + GSS-API wrapping out
		// of scope.
		"kerberos_decode",
		// v0.331 native-fit gap: ldap_decode is a pure
		// offline dissector for LDAP v3 per RFC 4511 — the
		// canonical directory-service protocol used by
		// every Active Directory deployment + most
		// enterprise IAM stacks (Microsoft AD LDS,
		// OpenLDAP, 389 Directory Server, FreeIPA / IdM,
		// Apple Open Directory, Apache Directory Server,
		// Oracle Internet Directory, Novell eDirectory).
		// TCP/389 cleartext + TCP/636 LDAPS + UDP/389
		// CLDAP. Canonical AD-pentest decoder paired with
		// kerberos_decode for the complete AD directory-
		// attack dissector. Surfaces: cleartext credentials
		// via SimpleBind (BindRequest authentication
		// CHOICE [0] simple carries password in cleartext;
		// privacy-preserving: surfaces simple_bind_present
		// boolean + bind_password_bytes LENGTH only, NOT
		// the password); username + DN enumeration via
		// SearchRequest (baseObject reveals AD domain,
		// SearchResultEntry leaks every user/computer/
		// group DN); brute-force feedback via resultCode
		// (49 invalidCredentials = wrong password, 0
		// success = working credential); CLDAP NetLogon
		// enumeration (anonymous UDP/389 rootDSE leaks DC
		// site + GUID + DnsHostName); SASL mechanism
		// enumeration (GSSAPI / GSS-SPNEGO / DIGEST-MD5
		// / CRAM-MD5 / EXTERNAL / PLAIN). 22-entry
		// operation name table (BindRequest / BindResponse
		// / UnbindRequest / SearchRequest / SearchResult
		// Entry / SearchResultDone / ModifyRequest /
		// ModifyResponse / AddRequest / AddResponse /
		// DelRequest / DelResponse / ModifyDNRequest /
		// ModifyDNResponse / CompareRequest / Compare
		// Response / AbandonRequest / SearchResult
		// Reference / ExtendedRequest / ExtendedResponse
		// / IntermediateResponse); BindRequest body walker
		// with version / name / auth-choice classification;
		// BindResponse + SearchResultDone + Modify/Add/Del/
		// CompareResponse + ExtendedResponse via unified
		// LDAPResult code path; SearchRequest body walker
		// with baseObject + scope + sizeLimit + timeLimit;
		// SearchResultEntry objectName surfacing; 17-entry
		// resultCode name table; 4-entry search scope name
		// table. Filter parser + LDAPS/StartTLS + SASL
		// inner-decode (GSSAPI Kerberos AP-REQ handled by
		// kerberos_decode) + controls parsing + MS
		// NetLogon binary layout out of scope.
		"ldap_decode",
		// v0.332 native-fit gap: smb2_decode is a pure
		// offline dissector for SMB2 / SMB3 messages per
		// Microsoft Open Specifications [MS-SMB2] — the
		// canonical Windows file-share and lateral-movement
		// protocol. TCP/445 direct + TCP/139 NBSS framing.
		// Lateral-movement decoder for every Windows
		// pentest engagement; together with kerberos_decode
		// + ldap_decode + ntlm_decode forms the complete
		// AD-pentest dissector quartet. Surfaces: NTLM-
		// relay vulnerability (NEGOTIATE_RESPONSE
		// SecurityMode without SIGNING_REQUIRED = relay-
		// vulnerable; impacket ntlmrelayx target); SMB1
		// fallback / EternalBlue candidates (dialect
		// 0x02FF wildcard = client advertises SMB1, MS17-
		// 010 candidate); admin-share access (TREE_CONNECT
		// \\<host>\ADMIN$ / C$ / IPC$); named-pipe lateral-
		// movement vectors (CREATE \pipe\spoolss = Print
		// Nightmare CVE-2021-1675/34527, \pipe\netlogon =
		// ZeroLogon CVE-2020-1472, \pipe\lsarpc = LSA-
		// policy SAM dump, \pipe\samr = AD enumeration,
		// \pipe\srvsvc = NetSessionEnum); authentication
		// feedback (SESSION_SETUP_RESPONSE STATUS_LOGON
		// _FAILURE / STATUS_WRONG_PASSWORD / STATUS
		// _ACCOUNT_LOCKED_OUT / STATUS_PASSWORD_EXPIRED =
		// password-spray feedback; STATUS_MORE_PROCESSING
		// _REQUIRED = multi-step auth in progress); server
		// /client GUID disclosure (stable endpoint
		// fingerprint). 19-entry command name table
		// (NEGOTIATE / SESSION_SETUP / LOGOFF / TREE_
		// CONNECT / TREE_DISCONNECT / CREATE / CLOSE /
		// FLUSH / READ / WRITE / LOCK / IOCTL / CANCEL /
		// ECHO / QUERY_DIRECTORY / CHANGE_NOTIFY /
		// QUERY_INFO / SET_INFO / OPLOCK_BREAK); 6-entry
		// dialect name table (0x0202 SMB 2.0.2 / 0x0210
		// SMB 2.1 / 0x0300 SMB 3.0 / 0x0302 SMB 3.0.2 /
		// 0x0311 SMB 3.1.1 / 0x02FF wildcard SMB1 flag);
		// 15-entry NTSTATUS name table; NEGOTIATE_REQUEST
		// + NEGOTIATE_RESPONSE + TREE_CONNECT_REQUEST +
		// CREATE_REQUEST body walkers; SMB3 encryption
		// Transform header (0xFD 'S' 'M' 'B') surfaced as
		// type-flag only. NetBIOS framing + NTLMSSP /
		// Kerberos inner blob (handled by ntlm_decode +
		// kerberos_decode) + compound message chain + per-
		// command body decode beyond NEGOTIATE/TREE_CONNECT
		// /CREATE/SESSION_SETUP out of scope.
		"smb2_decode",
		// v0.333 native-fit gap: dcerpc_decode is a pure
		// offline dissector for DCE/RPC (Distributed
		// Computing Environment / Remote Procedure Call)
		// messages per DCE 1.1 + Microsoft [MS-RPCE] — the
		// Microsoft RPC framing layer that carries nearly
		// every Windows AD attack chain. TCP/135 Endpoint
		// Mapper + TCP/49152+ ephemeral RPC ports + inside
		// SMB2 named pipes. Completes the AD-pentest
		// dissector quintet with smb2_decode + kerberos
		// _decode + ldap_decode + ntlm_decode. Surfaces the
		// MS-RPC attack-vector identifier: BIND carries
		// the interface UUID + REQUEST carries the opnum.
		// 20+ interface UUIDs flagged with canonical attack
		// vectors: NETLOGON 12345678-1234-abcd-ef00-
		// 01234567cffb + opnum 30 = ZeroLogon CVE-2020-
		// 1472 (DC password reset); DRSUAPI e3514235-4b06-
		// 11d1-ab04-00c04fc2dcd2 + opnum 3 = DCSync
		// (extracts all AD password hashes via mimikatz
		// lsadump::dcsync + impacket secretsdump.py); SAMR
		// 12345778-1234-abcd-ef00-0123456789ab = AD user/
		// group enumeration; LSARPC 12345778-1234-abcd-
		// ef00-0123456789ac = LSA-policy + SAM secrets
		// dump; SVCCTL 367abb81-9844-35f1-ad32-
		// 98f038001003 = PsExec lateral move; SPOOLSS
		// 12345678-1234-abcd-ef00-0123456789ab + opnum 65
		// = PrintNightmare CVE-2021-1675/34527; ATSVC
		// 1ff70682-0a51-30e8-076d-740be8cee98b = Task
		// Scheduler lateral move; EFS c681d488-d850-
		// 11d0-8c52-00c04fd90f7e = PetitPotam coercion;
		// WKSSVC + SRVSVC = NetWkstaUserEnum +
		// NetSessionEnum; EPMAPPER afa8bd80-7d8a-11c9-
		// bef4-08002b102989 = RPC portmap on TCP/135. 14-
		// entry PTYPE name table (REQUEST/PING/RESPONSE/
		// FAULT/WORKING/NOCALL/REJECT/ACK/CL_CANCEL/FACK/
		// CANCEL_ACK/BIND/BIND_ACK/BIND_NAK/ALTER_CONTEXT/
		// ALTER_CONTEXT_RESP/SHUTDOWN/CO_CANCEL/ORPHANED/
		// AUTH3); 6-entry pfc_flags name table; 16-byte
		// common header with byte-order discrimination via
		// drep[0] bit 4; BIND + ALTER_CONTEXT + REQUEST +
		// FAULT body walkers; 9-entry NCA fault status
		// name table. NDR parameter marshalling + IDL
		// inner-decode + DCOM ORPCTHIS chains + sec
		// _trailer parsing (handled by ntlm_decode +
		// kerberos_decode) + per-interface opnum-to-
		// function name mapping (1000+ interfaces) out of
		// scope.
		"dcerpc_decode",
		// v0.334 native-fit gap: tds_decode is a pure
		// offline dissector for TDS (Tabular Data Stream)
		// packets per Microsoft Open Specifications
		// [MS-TDS] — the Microsoft SQL Server protocol.
		// TCP/1433 default + TCP dynamic for named
		// instances + UDP/1434 SQL Server Browser.
		// Canonical SQL Server pentest dissector that
		// extends the Microsoft-stack pentest surface
		// beyond the AD-pentest quintet. Surfaces:
		// cleartext username via Login7 (TDS7_LOGIN
		// OffsetLength UTF-16LE — canonical credential
		// disclosure on TCP/1433 without TLS); password
		// length only (XOR-obfuscated 0xA5 deliberately
		// NOT deobfuscated — privacy-preserving); TLS-
		// downgrade vulnerability via Pre-Login
		// ENCRYPTION token (NOT_SUP = TLS-downgrade
		// vector when client expected TLS); SQL Server
		// version disclosure via TDSVersion field
		// (0x70000000 7.0 / 0x71000001 2000 SP1 /
		// 0x72090002 2005 / 0x730A0003 2008 / 0x730B0003
		// 2008 R2 / 0x74000004 2012/2014/2016/2017/2019/
		// 2022 — canonical version-fingerprint for CVE
		// selection); database + AppName disclosure
		// (Login7 carries requested database name + app
		// identification — sqlmap / SSMS / SqlClient /
		// SQLCMD / osql); named-instance hostnames via
		// Login7 ServerName. 12-entry packet type name
		// table (SQL_BATCH / PRE_TDS7_LOGIN / RPC /
		// TABULAR_RESULT / ATTENTION / BULK_LOAD_DATA /
		// TRANSACTION_MANAGER / TDS7_LOGIN / SSPI /
		// PRE_LOGIN / FEDERATED_AUTH_TOKEN); 5-entry
		// Status flags name table; 8-entry Pre-Login
		// token-type name table (VERSION / ENCRYPTION /
		// INSTOPT / THREADID / MARS / TRACEID /
		// FEDAUTHREQUIRED / NONCEOPT); 4-entry ENCRYPTION
		// mode name table (ENCRYPT_OFF / ENCRYPT_ON /
		// ENCRYPT_NOT_SUP downgrade flag / ENCRYPT_REQ
		// hardened); Pre-Login TLV token walker; Login7
		// fixed-field + OffsetLength variable-data
		// walker; 6-entry TDS version-to-SQL-Server
		// name table. TABULAR_RESULT token-stream
		// parsing (30+ token types) + SSPI inner blob
		// (handled by ntlm_decode + kerberos_decode) +
		// TLS/TDS encryption handshake + Federated
		// Authentication Token + RPC parameter
		// marshalling + bulk load data + password
		// deobfuscation (deliberately omitted) + SQL
		// Server Browser UDP/1434 [MS-SQLR] enumeration
		// out of scope.
		"tds_decode",
		// v0.335 native-fit gap: postgres_decode is a pure
		// offline dissector for PostgreSQL frontend/backend
		// protocol v3 per the PostgreSQL documentation
		// (Part VIII). TCP/5432 default. Sibling decoder
		// to tds_decode; extends the database-protocol
		// pentest surface across MSSQL + PostgreSQL.
		// Second-largest open-source database pentest
		// target after MySQL (RDS / Aurora / Cloud SQL /
		// Crunchy / Supabase / Neon / Timescale Cloud /
		// bare-metal). Surfaces: cleartext username +
		// database via StartupMessage (user + database
		// keys sent cleartext UTF-8 — canonical PostgreSQL
		// credential disclosure on TCP/5432 without TLS);
		// authentication method enumeration via Auth
		// Request (0 AuthenticationOk = trust/no password,
		// 3 CleartextPassword = MITM-capturable, 5
		// MD5Password = offline-crackable hashcat mode 12,
		// 10 SASL = SCRAM-SHA-256 modern hardened); brute-
		// force feedback via ErrorResponse SQLSTATE (28P01
		// invalid_password = canonical wrong-password
		// response; 3D000 invalid_catalog_name = database
		// enumeration feedback; 42P01 undefined_table =
		// post-auth enumeration); PostgreSQL version
		// disclosure via ParameterStatus (server_version
		// GUC = canonical version-fingerprint); SSL / GSS
		// pre-handshake detection (SSLRequest 0x04D2162F /
		// GSSENCRequest 0x04D21630 / CancelRequest
		// 0x04D21631); application_name client tool
		// identification. 15-entry frontend message type
		// name table + 24-entry backend message type name
		// table; StartupMessage body walker; Authentication
		// Request body walker with 11-entry sub-type name
		// table; ErrorResponse TLV walker with 18-entry
		// field-tag name table + 8-entry canonical SQLSTATE
		// name table; ParameterStatus body walker. Bind /
		// Parse parameter marshalling + RowDescription
		// type-OID parsing + DataRow body + extended query
		// protocol multi-message flow + COPY streaming +
		// TLS / GSSAPI handshake + SASL inner-mechanism
		// decode (SCRAM-SHA-256 base64 blobs) + NOTIFY /
		// LISTEN payload semantics out of scope.
		"postgres_decode",
		// v0.336 native-fit gap: mysql_decode is a pure
		// offline dissector for MySQL / MariaDB client/
		// server protocol per the MySQL documentation
		// (Chapter 4 — Client/Server Protocol). TCP/3306
		// default. Compatible with MariaDB which uses the
		// same wire format with minor extensions.
		// Completes the database-protocol pentest trio
		// with tds_decode + postgres_decode (MSSQL +
		// PostgreSQL + MySQL/MariaDB). The largest open-
		// source database pentest target — deployed
		// everywhere from cloud-managed MySQL (RDS /
		// Aurora / Cloud SQL / Azure Database /
		// PlanetScale) to bare-metal to containerized
		// side-cars to every shared-hosting cPanel
		// deployment. Surfaces: server fingerprint via
		// Handshake v10 (server_version string —
		// canonical CVE-selection fingerprint: 5.7.42 /
		// 8.0.35 / 10.11.5-MariaDB / Percona Server);
		// authentication plugin negotiation (auth_plugin
		// _name reveals security posture: mysql_native
		// _password SHA1-weak offline-crackable hashcat
		// mode 11200/300; caching_sha2_password modern
		// MySQL 8 default; sha256_password RSA-encrypted
		// requires SSL; mysql_clear_password CLEARTEXT
		// MITM-capturable; auth_socket Unix peer-creds;
		// windows_native_password SSPI/NTLM; dialog
		// interactive Percona PAM / MariaDB Cracklib);
		// TLS support detection via CLIENT_SSL capability
		// bit (0x00000800 — server advertises SSL; client
		// without TLS upgrade sends username + auth data
		// cleartext on TCP/3306); cleartext username +
		// database via HandshakeResponse41 (canonical
		// credential-disclosure); brute-force feedback
		// via ERR packet 1045 ER_ACCESS_DENIED_ERROR;
		// database enumeration via 1049 ER_BAD_DB_ERROR;
		// connection ID disclosure. 25-entry capability
		// flags name table; 5-entry status flags name
		// table; 8-entry auth plugin description table
		// with security-posture flagging; 11-entry error
		// code name table. Command-specific bodies (COM
		// _QUERY / COM_INIT_DB / COM_STMT_PREPARE / etc.
		// — 32 entries) + result-set parsing + binary-
		// protocol prepared-statement parameter
		// marshalling + compressed packet format + SSL
		// handshake + caching_sha2_password full-auth
		// RSA exchange + LOAD DATA LOCAL INFILE 0xFB
		// abuse vector + MariaDB-specific extensions +
		// XA/GTID/replication semantics out of scope.
		"mysql_decode",
		// v0.337 native-fit gap: redis_decode is a pure
		// offline dissector for Redis RESP (REdis
		// Serialization Protocol) v2 + v3 per the Redis
		// documentation. TCP/6379 default; 6380/6381
		// Sentinel; 16379/26379 Cluster bus. Third-largest
		// open-source database pentest target after MySQL
		// + PostgreSQL — every modern web-app stack uses
		// Redis for caching/sessions/queues/pub-sub. Cloud-
		// managed: ElastiCache / MemoryDB / Cloud
		// Memorystore / Azure Cache / Upstash / Redis
		// Enterprise. Canonical "exposed-to-internet
		// without auth" pentest target — default
		// deployments have NO auth (requirepass unset,
		// protected-mode disabled + bound to 0.0.0.0 =
		// 100,000+ unauthenticated instances per Shodan).
		// Multiple RCE primitives even after auth: CONFIG
		// SET dir/dbfilename + SAVE = SSH authorized_keys
		// / cron / webshell write; MODULE LOAD = direct
		// native-code RCE; SCRIPT/EVAL = Lua sandbox
		// escape CVE-2022-0543 Debian Redis; SLAVEOF/
		// REPLICAOF = replication-RCE via attacker-crafted
		// RDB with malicious module. Surfaces: AUTH with
		// cleartext password (password_bytes LENGTH only,
		// privacy-preserving); HELLO with embedded AUTH
		// (RESP3 inline credentials); dangerous-command
		// flagging (CONFIG / DEBUG / MODULE / SCRIPT /
		// EVAL / SLAVEOF / REPLICAOF / SHUTDOWN / FLUSH*
		// / CLIENT KILL); brute-force feedback via error
		// responses (-NOAUTH pre-auth signal; -WRONGPASS
		// canonical wrong-password; -PERMISSION ACL
		// denied; -MOVED/-ASK Cluster redirection;
		// -LOADING/-BUSY operational state). 5-entry
		// RESP2 type table + 8-entry RESP3 type table;
		// CRLF frame walker with length-prefixed Bulk
		// Strings + count-prefixed Arrays; 13-entry
		// dangerous-command classification table; 11-
		// entry error category table. RDB persistence
		// format + AOF format + Cluster slot map binary
		// encoding + module command IDLs (RediSearch /
		// RedisJSON / RedisGraph / RedisTimeSeries /
		// RedisBloom) + sub-array deep recursion + TLS
		// handshake (Redis 6+) + RESP3 attribute prefix +
		// client tracking push messages + full key-value
		// content out of scope.
		"redis_decode",
		// v0.338 native-fit gap: mongodb_decode is a pure
		// offline dissector for MongoDB wire-protocol
		// messages per the MongoDB documentation. TCP/27017
		// default (mongod); TCP/27018 mongos; TCP/27019
		// config servers. Compatible with FerretDB (Postgres-
		// backed proxy) + AWS DocumentDB. High-value NoSQL
		// pentest target with exposure profile similar to
		// Redis — historical Mongo 2.x/3.x defaulted to "no
		// auth, bind to 0.0.0.0"; Shodan finds tens of
		// thousands of unauthenticated instances on TCP/
		// 27017. Modern Mongo 4.x+ defaults to localhost +
		// SCRAM-SHA-256. Surfaces: MongoDB version + auth-
		// mechanism enumeration via isMaster/hello (driver
		// always sends on connect; reply includes
		// saslSupportedMechs SCRAM-SHA-1 weak / SCRAM-SHA-256
		// modern / PLAIN cleartext / MONGODB-X509 / GSSAPI /
		// MONGODB-AWS / MONGODB-OIDC); database + collection
		// namespace cleartext (OP_QUERY fullCollectionName
		// or OP_MSG $db top-level field); SASL auth exchange
		// (saslStart + saslContinue — surfaces mechanism +
		// payload_bytes LENGTH only, privacy-preserving;
		// offline-crackable hashcat mode 24100 SCRAM-SHA-1 /
		// 24200 SCRAM-SHA-256 once captured); dangerous-
		// command flagging (createUser/updateUser/dropUser
		// = backdoor primitive; dropDatabase/dropCollection
		// = destruction; listDatabases/listCollections =
		// enumeration; eval / $where / $expr = server-side
		// JS RCE primitive REMOVED in 4.4 but legacy 3.x/
		// 4.0/4.2 still deployed; shutdown/replSetStepDown
		// = operational destructive); build info disclosure
		// via buildInfo (version + gitVersion + modules +
		// openssl + storageEngines = canonical CVE-selection
		// fingerprint). 12-entry opCode name table (OP_REPLY
		// legacy / OP_MSG_DEPRECATED / OP_UPDATE legacy /
		// OP_INSERT legacy / OP_QUERY legacy but used for
		// initial isMaster/hello probe / OP_GET_MORE /
		// OP_DELETE / OP_KILL_CURSORS / OP_COMMAND server-
		// internal / OP_COMMANDREPLY / OP_COMPRESSED Snappy/
		// zlib/zstd / OP_MSG modern MongoDB 3.6+ default);
		// 18-entry BSON element-type name table; OP_MSG +
		// OP_QUERY body walkers; BSON top-level document
		// walker. Full BSON value parsing + Binary subtypes
		// + OP_COMPRESSED decompression + TLS handshake +
		// SDAM topology monitoring + Change Streams oplog
		// + GridFS + per-driver client metadata + CSFLE
		// encrypted-field BinData out of scope.
		"mongodb_decode",
		// v0.339 native-fit gap: rdp_x224_decode is a pure
		// offline dissector for the initial-handshake
		// frames of Microsoft RDP (Remote Desktop Protocol)
		// per [MS-RDPBCGR] — TPKT-wrapped X.224 COTP
		// Connection Request / Connection Confirm PDUs
		// plus embedded RDP_NEG_REQ / RDP_NEG_RSP /
		// RDP_NEG_FAILURE structures. TCP/3389 default.
		// Universal Windows pentest entry point — every
		// Windows Server + Windows desktop deployment
		// exposes 3389 at some layer (LAN, jump host,
		// Citrix gateway, RD Gateway, AWS Workspaces,
		// Azure Virtual Desktop). Extends the Windows-
		// stack pentest surface alongside the AD-pentest
		// quintet (kerberos + ldap + ntlm + smb2 +
		// dcerpc). Surfaces: username cleartext via RDP
		// Cookie (Cookie: mstshash=<username> sent by
		// mstsc.exe / Remmina / FreeRDP / rdesktop / AWS
		// Workspaces client; canonical pre-auth username
		// enumeration without sending credentials!);
		// routing token disclosure (Cookie: msts=<token>
		// alternative form); NLA / CredSSP hardening
		// posture via requestedProtocols bitmask
		// (PROTOCOL_RDP=0 standard no-TLS vulnerable to
		// passive MITM = BlueKeep CVE-2019-0708 target;
		// PROTOCOL_SSL=1 TLS 1.0+; PROTOCOL_HYBRID=2
		// CredSSP NLA modern hardened default;
		// PROTOCOL_RDSTLS=4; PROTOCOL_HYBRID_EX=8 CredSSP
		// + EarlyUserAuthorizationResult; PROTOCOL_RDSAAD
		// =16 Microsoft Entra ID AAD); server hardening
		// enforcement via NEG_FAILURE (SSL_REQUIRED_BY
		// _SERVER = TLS hardening; HYBRID_REQUIRED_BY
		// _SERVER = canonical NLA-hardened response —
		// CredSSP mandated pre-auth credential check);
		// selected-protocol confirmation via NEG_RSP
		// (selectedProtocol=0 on internet-reachable
		// server = high-severity BlueKeep candidate);
		// Restricted Admin Mode detection (NEG_REQ flags
		// 0x01 = Windows 8.1+ login without sending creds
		// to remote host). 4-byte TPKT header (RFC 1006)
		// + X.224 COTP header (ITU-T X.224 / RFC 905) +
		// 5-entry PDU-type name table (CR / CC / DT /
		// DR / ER); RDP Cookie cstring-prefix walker;
		// RDP_NEG_REQ + NEG_RSP + NEG_FAILURE walkers;
		// 6-entry requestedProtocols name table; 3-entry
		// NEG_REQ flags name table; 3-entry NEG_RSP
		// flags name table; 6-entry failureCode name
		// table. MCS Connect Initial / GCC ClientCoreData
		// + CredSSP TSRequest (handled by ntlm_decode +
		// kerberos_decode) + RDP Security Layer + virtual
		// channels (RDPDR / RDPSND / CLIPRDR / RAIL /
		// RemoteFX / DYNVC) + RDP licensing + FastPath
		// PDUs + multi-segment fragmented X.224 data +
		// NeGEx2 / SCard auth variants out of scope.
		"rdp_x224_decode",
		// v0.340 native-fit gap: vnc_rfb_decode is a pure
		// offline dissector for VNC RFB (Remote Framebuffer)
		// Protocol handshake messages per RFC 6143 plus the
		// RealVNC / TightVNC / VeNCrypt / Apple ARD
		// extensions. TCP/5900-5999 default (display offset
		// = port - 5900); TCP/5800-5899 Java applet HTTP
		// wrapper. Universal remote-access pentest target —
		// RealVNC / TightVNC / TigerVNC / UltraVNC / x11vnc
		// / Vino (GNOME) / KRfb (KDE) / Apple Remote Desktop
		// (macOS built-in TCP/5900) / embedded device VNC
		// (printers / ATMs / industrial HMIs / KVM-over-IP
		// boxes Raritan / Avocent / iLO / iDRAC / IPMI BMC
		// / digital signage / DVR-NVR) / cloud-managed VNC
		// consoles (AWS Workspaces / Azure Bastion / GCP VM
		// serial-console-over-VNC). Pairs with
		// rdp_x224_decode for complete remote-access pentest
		// surface. Surfaces: ProtocolVersion banner (12-byte
		// "RFB 003.NNN\\n" — 003.008 RFC-6143 conformant /
		// 003.007 legacy TightVNC 1.x / 003.003 very
		// legacy); security-type enumeration via security
		// types list (RFB 3.7+ 1-byte count + N security-
		// type bytes; RFB 3.3 single 4-byte type); 13-entry
		// security-type name table with vulnerability
		// classification: 0 Invalid / 1 None NO
		// AUTHENTICATION REQUIRED exposed! / 2 VNC Auth
		// weak 8-byte truncated DES offline-crackable
		// hashcat mode 26200 / 5 RA2 / 6 RA2ne / 16 Tight /
		// 17 Ultra UltraVNC MS-Logon / 18 TLS / 19 VeNCrypt
		// multi-mechanism / 20 SASL / 21 MD5 hash UltraVNC
		// MS-Logon II / 22 xvp Xen / 30 Apple Diffie-Hellman
		// ARD; brute-force feedback via SecurityResult
		// Failed reason (RFB 3.8 + 1 + length-prefixed
		// reason — hydra vnc / medusa vnc / ncrack vnc
		// consume); hostname disclosure via ServerInit
		// desktop name ("<USER>'s Mac" / machine hostname /
		// "dc01.corp.example.com" / TigerVNC default); 16-
		// byte pixel-format walker (bpp + depth + big-endian
		// + true-colour flag + RGB max+shift). Auto-
		// discrimination between message kinds by leading-
		// byte inspection. Framebuffer update encodings
		// (Raw / CopyRect / RRE / Hextile / TRLE / ZRLE /
		// Tight / 30+ encodings) + mouse + keyboard event
		// PDUs + VNC password decryption (deliberately
		// omitted — DES challenge requires offline hashcat)
		// + VeNCrypt sub-handshake (TLS / X.509) + SASL
		// inner-decode (GSSAPI via kerberos_decode; others
		// deferred) + Apple ARD DH key exchange details +
		// TightVNC sub-auth list + HTTP-tunneled VNC TCP/
		// 5800-5899 out of scope.
		"vnc_rfb_decode",
		// v0.341 native-fit gap: amqp091_decode is a pure
		// offline AMQP 0-9-1 wire-protocol parser — no
		// network I/O, no Flipper/Marauder interaction.
		// Decodes RabbitMQ / AMQP 0-9-1 frames from hex;
		// surfaces Connection.Start version fingerprint,
		// SASL PLAIN cleartext credential exposure flag,
		// vhost/exchange/queue topology disclosure. SASL
		// response payload NEVER decoded (length only).
		"amqp091_decode",
		// v0.341 native-fit gap: kafka_decode is a pure
		// offline Kafka wire-protocol parser — no network
		// I/O, no Flipper/Marauder interaction. Decodes
		// Apache Kafka request frames from hex; surfaces
		// ApiVersions version fingerprint, SaslHandshake
		// mechanism enumeration, SASL PLAIN cleartext flag,
		// topic/group topology disclosure. SASL auth bytes
		// NEVER decoded (length only).
		"kafka_decode",
		// v0.341 native-fit gap: memcached_decode is a pure
		// offline Memcached binary-protocol parser — no
		// network I/O, no Flipper/Marauder interaction.
		// Decodes Memcached binary frames from hex; surfaces
		// cache key names, SET extras (flags/expiration),
		// INCR/DECR extras, SASL auth detection, operation
		// classification. Cached values + SASL credentials
		// NEVER surfaced (length only).
		"memcached_decode",
		// v0.342 native-fit gap: ipmi_decode is a pure
		// offline IPMI RMCP/RMCP+ wire-protocol parser — no
		// network I/O, no Flipper/Marauder interaction.
		// Decodes IPMI session headers, Get Channel Auth
		// Capabilities (auth enumeration), Get Device ID
		// (version fingerprint), RMCP+ RAKP exchange,
		// cipher suite zero detection. Auth codes NEVER
		// decoded (presence only).
		"ipmi_decode",
		// v0.342 native-fit gap: rip_decode is a pure
		// offline RIP v1/v2 wire-protocol parser — no
		// network I/O, no Flipper/Marauder interaction.
		// Decodes RIP header + route entries + auth entries;
		// surfaces route topology, cleartext password auth
		// flag, infinity metric detection. Passwords NEVER
		// extracted (flag only).
		"rip_decode",
		// v0.342 native-fit gap: eigrp_decode is a pure
		// offline EIGRP wire-protocol parser — no network
		// I/O, no Flipper/Marauder interaction. Decodes
		// EIGRP header + TLVs (Parameters K-values,
		// Software Version, Auth, Internal/External Routes);
		// surfaces AS number, hold time, route topology.
		// Auth data NEVER decoded (type only).
		"eigrp_decode",
		// v0.343 native-fit gap: ldp_decode is a pure
		// offline LDP (Label Distribution Protocol) wire-
		// protocol parser per RFC 5036 — no network I/O,
		// no Flipper/Marauder interaction. Decodes LDP PDU
		// header (version, lsr_id, label_space) + message
		// header (type, id) + TLVs (Common Hello Params,
		// Transport Address, Session Params, Generic Label);
		// surfaces LSR topology, targeted-Hello flag,
		// label bindings. Auth at TCP layer; not in PDU.
		"ldp_decode",
		// native-fit gap: isis_decode is a pure offline IS-IS wire-protocol
		// parser per ISO 10589 + RFC 1195 — no network I/O, no
		// Flipper/Marauder interaction. Decodes IS-IS common header,
		// per-PDU-type fixed fields (LAN IIH / P2P IIH / LSP / CSNP /
		// PSNP), and TLVs (Area Addresses, Authentication, IP Interface
		// Address, Dynamic Hostname); surfaces topology, auth type,
		// system IDs. Auth data NEVER decoded (type only).
		"isis_decode",
		// v0.343 native-fit gap: rtmp_decode is a pure
		// offline RTMP wire-protocol parser — no network
		// I/O, no Flipper/Marauder interaction. Decodes
		// RTMP handshake (C0/S0 version, RTMPE detection),
		// chunk headers (fmt, cs_id, message type), AMF0
		// command extraction (connect/play/publish). Stream
		// keys + credentials NEVER extracted.
		"rtmp_decode",
		// v0.344 native-fit gap: grpc_decode is a pure
		// offline gRPC Length-Prefixed Message parser — no
		// network I/O, no Flipper/Marauder interaction.
		// Decodes gRPC framing (compressed flag + message
		// length) + best-effort protobuf field tag walk.
		// Message content NEVER interpreted beyond field
		// structure.
		"grpc_decode",
		// v0.344 native-fit gap: rsvpte_decode is a pure
		// offline RSVP-TE wire-protocol parser — no network
		// I/O, no Flipper/Marauder interaction. Decodes
		// RSVP common header + object walker (SESSION, HOP,
		// LABEL, ERO, RRO, SESSION_ATTRIBUTE, etc.). MPLS
		// TE signalling for LSP establishment.
		"rsvpte_decode",
		// v0.344 native-fit gap: xmpp_decode is a pure
		// offline XMPP XML stanza parser — no network I/O,
		// no Flipper/Marauder interaction. Decodes stream
		// opening, stream features, SASL auth (PLAIN
		// cleartext flagged), message/presence/iq stanzas.
		// Auth data + message content NEVER extracted.
		"xmpp_decode",
		// v0.345 native-fit gap: es_transport_decode is a pure
		// offline Elasticsearch internal transport protocol
		// parser (TCP/9300 inter-node binary framing). No
		// network I/O, no Flipper/Marauder interaction. Decodes
		// ES magic marker, request_id, status flags (request/
		// response/error/compressed/handshake), transport_version,
		// and action name. Action names NEVER decoded beyond
		// string extraction (no index data surfaced).
		"es_transport_decode",
		// v0.345 native-fit gap: zmtp_decode is a pure offline ZMTP
		// wire-protocol parser — no network I/O, no Flipper/Marauder
		// interaction. Decodes ZMTP handshake + message frames.
		// Frame content NEVER decoded (length only).
		"zmtp_decode",
		// v0.345 native-fit gap: cassandra_decode is a pure offline
		// Cassandra CQL binary protocol parser — no network I/O,
		// no Flipper/Marauder interaction. Decodes CQL frame header,
		// STARTUP CQL version, QUERY text (first 200 chars),
		// AUTHENTICATE class name, ERROR code + message.
		// AUTH_RESPONSE bytes NEVER decoded (length only).
		"cassandra_decode",
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
