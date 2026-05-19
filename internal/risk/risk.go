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
