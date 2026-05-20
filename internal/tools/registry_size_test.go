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
	// v0.244.0 added dns_packet_decode (DNS message dissector
	// per RFC 1035 + 6891 — header + flags + counts +
	// question + RR sections with type-specific decode for
	// A/NS/CNAME/SOA/PTR/MX/TXT/AAAA/SRV/OPT/DNSKEY/DS/CAA
	// + compression-pointer resolution + DoS-loop guard).
	// v0.245.0 added dhcp_packet_decode (DHCPv4 dissector
	// per RFC 2131 + 2132 — BOOTP envelope + magic cookie +
	// options walker with type-specific decode for ~50
	// documented options including 53 msg type, 55 parameter
	// request list with named codes, 81 FQDN, 82 relay agent
	// sub-options, 119 domain search, 121 classless routes).
	// v0.246.0 added snmp_packet_decode (SNMP v1/v2c/v3
	// dissector per RFC 1157/1905/3416/3411-3418 — hand-rolled
	// BER walker; envelope + community (v1/v2c) or v3
	// msgGlobalData; PDU dispatch covering 9 types; VarBindList
	// walker with type-specific value decode; well-known OID
	// name lookup; named error-status + generic-trap).
	// v0.247.0 added ntp_packet_decode (NTP/SNTP dissector
	// per RFC 5905 + 1305 + 4330 — 48-byte header with LI/
	// VN/Mode/Stratum/Poll/Precision + Root Delay/Dispersion
	// + Reference ID with stratum-dependent decode (KoD /
	// primary source / upstream IPv4) + 4 NTP timestamps
	// with NTP→Unix epoch conversion + optional MD5/SHA-1
	// authenticator).
	// v0.248.0 added syslog_message_decode (RFC 5424 IETF +
	// RFC 3164 BSD format dissector — auto-detect by
	// post-PRI byte; PRI broken out into facility + severity
	// name lookup; 5424 structured-data walker with escape
	// handling; 3164 BSD timestamp + tag[PID] split).
	// v0.249.0 added ip_packet_decode (raw IPv4/IPv6 + TCP/
	// UDP/ICMP/ICMPv6 dissector per RFC 791/8200/9293/768/
	// 792/4443 — auto-detect IP version + protocol dispatch
	// + TCP flag breakout + TLV options walker + ICMP/ICMPv6
	// type+code naming. Foundational network primitive).
	// v0.250.0 added ssh_handshake_decode (SSH wire-protocol
	// dissector per RFC 4253 — version banner + binary
	// packet envelope + 27-entry message-type table +
	// KEXINIT body decode with 10 name-lists + HASSH /
	// HASSHServer fingerprint computation. SSH counterpart
	// to TLS JA3).
	// v0.251.0 added cbor_decode (CBOR dissector per RFC
	// 8949 — recursive walker for all 8 major types +
	// indefinite-length containers + IEEE 754 half/single/
	// double floats + ~30-entry tag table including COSE
	// and CTAP/WebAuthn vendor tags).
	// v0.252.0 added protobuf_decode (Protocol Buffers
	// wire-format dissector without .proto schema — mirrors
	// protoc --decode_raw. Walk field tags, dispatch 6 wire
	// types with VARINT zigzag, I64 float64, LEN with
	// nested-message heuristic, I32 float32. Recursive).
	// v0.253.0 added radius_packet_decode (RADIUS AAA
	// protocol dissector per RFC 2865 + 2866 — 20-byte
	// header + attribute TLV walker with ~80-entry IANA
	// name lookup + Vendor-Specific deep decode with SMI
	// PEN naming + enum-name lookup for Service-Type,
	// NAS-Port-Type, Acct-Status-Type, Tunnel-Type, etc.).
	// v0.254.0 added stun_packet_decode (STUN/TURN dissector
	// per RFC 5389 + 8489 + 5766 + 8656 — 20-byte header
	// with method/class split + magic cookie validation +
	// ~30-entry attribute name table + XOR address
	// un-masking + ERROR-CODE with named codes).
	// v0.255.0 added sip_message_decode (SIP message
	// dissector per RFC 3261 — request/response auto-detect
	// + 14 documented methods + ~40-entry status code table
	// across all 6 classes + compact-form header expansion
	// + CSeq parsing + SDP body decode).
	// v0.256.0 added http_message_decode (HTTP/1.x request +
	// response dissector per RFC 9112 + 9110 — auto-detect
	// request/response + ~50-entry status code table across
	// all 5 classes + typed envelope fields with
	// Authorization scheme breakout + Cookie/Set-Cookie
	// attribute parsing + Content-Length / chunked body
	// decoding).
	// v0.257.0 added rtp_packet_decode (RTP + RTCP packet
	// dissector per RFC 3550 + 3551 + 4585 + 3611 — auto-
	// detect RTP vs RTCP by PT byte, RTP header with optional
	// CSRC + extension + padding, 23-entry static PT table
	// plus dynamic-PT recognition, RTCP composite walker with
	// SR / RR / SDES / BYE / APP / RTPFB / PSFB / XR per-type
	// body parsing). Completes the VoIP/WebRTC decode stack
	// alongside sip_message_decode + stun_packet_decode.
	// v0.258.0 added websocket_frame_decode (WebSocket frame
	// dissector per RFC 6455 — header bit-pack + extended
	// 16/64-bit length forms + 4-byte mask key with XOR
	// demask + 7-entry opcode table + Close-body parsing
	// with 14-entry status code table + RSV1 deflate flag
	// + multi-frame walker + fragmentation detection).
	// Natural follow-on to http_message_decode.
	// v0.259.0 added rfid_pacs_decode (HID Prox PACS format
	// dissector — H10301 26-bit, H10306 34-bit, H10304 +
	// H10302 37-bit, Corporate 1000 35-bit + 48-bit; parity
	// computation and validation per format; multi-candidate
	// dispatch for ambiguous bit widths). Top-30 gap #19;
	// natural sibling to wiegand_decode.
	// v0.260.0 added ble_continuity_classify (Apple Continuity
	// BLE advertisement dissector — outer-envelope auto-detect,
	// TLV walker, 15-entry type table with per-type body
	// decoding for iBeacon / Handoff / Nearby Info / Nearby
	// Action / AirDrop / Hey Siri / Proximity Pairing).
	// Top-30 gap #8; defensive primitive sourced from
	// furiousMAC + AppleJuice + apple_bleee research.
	// v0.261.0 added wireguard_packet_decode (WireGuard UDP
	// packet dissector per the official protocol spec at
	// wireguard.com/protocol — 4 message types: Handshake
	// Initiation / Response / Cookie Reply / Transport Data;
	// MAC2 zero detection; keep-alive detection; reserved-
	// byte abuse flagging). Foundational modern VPN protocol.
	// v0.262.0 added icmp_packet_decode (ICMP RFC 792 + ICMPv6
	// RFC 4443 + NDP RFC 4861 packet dissector — auto-detect
	// version, 17+17 type tables, per-type body decoding
	// for Echo / DestUnreach / Redirect / Packet Too Big /
	// NS+NA / RS+RA, NDP option TLV walker). Foundational
	// network-layer diagnostic protocol; companion to
	// ip_packet_decode.
	// v0.263.0 added http2_frame_decode (HTTP/2 frame dissector
	// per RFC 9113 — connection preface auto-detect, 10 frame
	// types with per-type body decoding, 14-entry error code
	// table, 7-entry SETTINGS parameter table, multi-frame
	// walker, flags decoded per frame type). Completes the
	// HTTP/1.x + WebSocket + HTTP/2 decode stack.
	// v0.264.0 added hpack_decode (HPACK header decompression
	// per RFC 7541 — 5 representation types, N-bit prefix
	// integers, full Huffman codec from Appendix B 257-symbol
	// table, 61-entry static table, per-call dynamic table
	// with eviction). Explicitly closes the gap noted in
	// v0.263 http2_frame_decode.
	// v0.265.0 added lldp_decode (LLDP per IEEE 802.1AB-2009 —
	// TLV walker over 9 documented types: Chassis ID, Port ID,
	// TTL, Port/System Description, System Name, System
	// Capabilities, Management Address, End of LLDPDU, Org
	// Specific; 7 chassis/port ID subtypes; 11-bit capability
	// flag table; 5 OUI name table). Foundational datacenter
	// L2 discovery.
	// v0.266.0 added cdp_decode (Cisco Discovery Protocol —
	// 4-byte header, TLV walker over 17 documented types,
	// 10-bit capability flag table). Cisco-proprietary
	// sibling to LLDP; coexists on Cisco-heavy networks.
	// v0.267.0 added dtls_record_decode (DTLS 1.2/1.3 record +
	// handshake dissector per RFC 6347 / RFC 9147 — 13-byte
	// record layer, 5 content types, 23-entry Alert table,
	// 12-byte handshake header, 13 handshake types, ClientHello
	// / ServerHello / HelloVerifyRequest bodies, Heartbleed
	// detection, multi-record walker). UDP equivalent of TLS;
	// pairs with tls_handshake_decode.
	// v0.268.0 added quic_long_header_decode (QUIC long-header
	// packet dissector per RFC 9000 — 4 long-header packet
	// types: Initial / 0-RTT / Handshake / Retry; Variable-
	// Length Integer decoder; Version Negotiation detection;
	// 4-entry version name table with GREASE pattern
	// recognition). Foundational modern transport underpinning
	// HTTP/3.
	// v0.269.0 added arp_decode (ARP RFC 826 + RARP RFC 903 +
	// RFC 5227 IPv4 conflict-detection extensions — 8-byte
	// fixed header + 4 length-parameterised address fields;
	// 10-entry hardware type table, 4-entry protocol type
	// table, 10-entry operation table; gratuitous-ARP / ARP
	// probe / ARP announcement detection). Foundational
	// L2-to-L3 binding protocol.
	// v0.270.0 added vlan_decode (IEEE 802.1Q + 802.1ad VLAN
	// tag walker — TPID + TCI breakdown (PCP / DEI / VID);
	// 5-entry TPID table; 8-entry 802.1p priority table;
	// VID special-value annotations; QinQ double-tag
	// detection; 10-entry inner EtherType table).
	// Foundational L2 tag protocol.
	// v0.271.0 added vxlan_decode (VXLAN RFC 7348 + Cisco GBP
	// + GPE variants — 8-byte header, variant classification,
	// RFC 7348 conformance check, inner Ethernet peek with
	// 13-entry EtherType table). Datacenter overlay protocol
	// dominant in VMware NSX / OpenStack / Kubernetes CNIs.
	// v0.272.0 added gre_decode (GRE per RFC 2784 + RFC 2890
	// + RFC 2637 PPTP Enhanced — 4-byte mandatory header with
	// C/R/K/S/s/Recur/Version flags + 8-entry Protocol Type
	// table; optional Checksum/Offset, Key, Sequence Number,
	// PPTP Ack Number; PPTP Enhanced GRE Call ID + PayloadLen
	// split). Foundational IP tunneling protocol; pairs with
	// vxlan_decode.
	// v0.273.0 added geneve_decode (Geneve per RFC 8926 — 8-
	// byte fixed header, TLV options walker, 6-entry Option
	// Class name table, inner Ethernet peek for TEB).
	// Next-generation datacenter overlay; rounds out the trio
	// with vxlan_decode + gre_decode.
	// v0.274.0 added mpls_decode (MPLS label stack per RFC
	// 3032 + 5462 — 4-byte-per-label walker; 8-entry reserved
	// label table; inner payload heuristic; Router-Alert-at-
	// bottom violation note). Foundational service-provider
	// label-switching protocol.
	// v0.275.0 added stp_bpdu_decode (STP/RSTP/MSTP BPDU per
	// IEEE 802.1D-2004 + 802.1Q-2014 §13 — 4-byte common
	// header + 31-byte Configuration body + per-version
	// dispatch; flags decoded; Bridge ID priority + System ID
	// Extension + MAC split; timer formatting). Foundational
	// L2 loop-prevention protocol.
	// v0.276.0 added gtp_u_decode (GTP-U per 3GPP TS 29.281
	// — 8-byte mandatory header + optional 4-byte sequence/
	// NPDU/ext block + typed extension chain with 9-entry
	// name table + 6-entry message type table + inner IP
	// heuristic). Foundational cellular telco protocol
	// (S1-U / N3 / N9 user-plane wrapping).
	// v0.277.0 added pppoe_decode (PPPoE per RFC 2516 — 6-
	// byte header, 6-entry Code name table, Discovery TLV
	// walker with 10-entry Tag Type table, Session-stage PPP
	// protocol-ID dispatch with 9-entry name table).
	// Foundational fixed-line broadband protocol; universal
	// in DSL/FTTH BNG deployments.
	// v0.278.0 added bgp_message_decode (BGP-4 per RFC 4271
	// + extensions — 19-byte header with all-FFs Marker
	// validation, 5-entry message type table; OPEN body with
	// Capability walker; UPDATE body with Path Attribute and
	// NLRI walkers; NOTIFICATION error code+subcode tables;
	// ROUTE-REFRESH AFI/SAFI tables). Foundational Internet
	// inter-AS routing protocol.
	// v0.279.0 added ospf_packet_decode (OSPFv2 per RFC 2328
	// — 24-byte common header, 5 packet types with per-type
	// bodies (Hello/DBD/LSR/LSU/LSAck), LSA Header with 9-
	// entry LS Type name table, AuType+Options decoded).
	// Foundational IGP routing protocol; pairs with
	// bgp_message_decode for inside-plus-outside routing.
	// v0.280.0 added bfd_control_decode (BFD Control packet
	// per RFC 5880 — 24-byte mandatory header with Version +
	// Diagnostic + State + 6 flag bits + Detect Mult +
	// Length + My/Your Discriminators + 3 timing intervals;
	// optional Authentication Section with 5-entry Auth Type
	// table; 9-entry Diagnostic name table; 4-entry State
	// name table). Sub-second link-failure detection.
	// v0.281.0 added vrrp_decode (VRRP per RFC 5798 v3 + RFC
	// 3768 v2 — 8-byte common header with per-version body
	// parsing, IPv4/IPv6 virtual address list walker, VRRPv2
	// Simple Text auth decoded, priority semantic notes for
	// 0/100/255). Foundational gateway-redundancy protocol.
	// v0.282.0 added igmp_decode (IGMPv2 per RFC 2236 +
	// IGMPv3 per RFC 3376 — auto-detect version from Type +
	// body length; v2 8-byte fixed header + v3 Query body
	// extension (S/QRV + QQIC + Source Addresses) + v3
	// Membership Report Group Records walker with 6-entry
	// Record Type name table; Max Resp Code exp+mantissa
	// decoding per §4.1.1). Foundational IPv4 multicast
	// group-management protocol.
	// v0.283.0 added pim_decode (PIM-SM v2 per RFC 7761 —
	// 4-byte common header with 11-entry Type name table;
	// Hello body TLV walker with 5-entry option table;
	// Register/Register-Stop/Join-Prune/Bootstrap/Assert
	// per-type bodies; RFC 7761 §4.9.1 Encoded Unicast /
	// Group / Source address parsing with IPv4 + IPv6
	// support). Foundational router↔router multicast
	// routing protocol; pairs with igmp_decode (host
	// ↔router) for the complete IPv4 multicast picture.
	// v0.284.0 added hsrp_decode (HSRPv1 per RFC 2281 +
	// Cisco HSRPv2 TLV extensions — 20-byte v1 fixed packet
	// with 3-entry Op Code table + 6-entry State name table
	// + priority semantic notes; v2 TLV envelope with
	// 3-entry type table covering Group State 40B (IPv4 +
	// IPv6) / Text Auth 9B / MD5 Auth 28B). Cisco-
	// proprietary sibling to vrrp_decode; still extremely
	// common in Cisco-heavy enterprise + datacenter cores.
	// v0.285.0 added lacp_decode (LACP per IEEE 802.1AX-
	// 2020 — Slow Protocols subtype + Version + TLV walker
	// with 4-entry type table; Actor + Partner 18-byte body
	// with 8-bit State bitfield decoded into 8 named flags;
	// Collector 14-byte body). Closes a key L2 visibility
	// gap alongside lldp_decode + cdp_decode + stp_bpdu_
	// decode for the complete control-plane picture.
	// v0.286.0 added pcap_decode (libpcap classic '.pcap'
	// file inspector — 24-byte global header with 4-magic
	// dispatch + ~35-entry LINKTYPE_* name table + 16-byte
	// per-record header walker + N-byte payload preview;
	// configurable record + payload caps; first/last
	// timestamp + duration). Universal packet-capture
	// container behind every tcpdump / Wireshark file;
	// meta-tool that surfaces the container so operators
	// can extract metadata + frames to feed into the 80+
	// existing protocol-specific decoders.
	// v0.287.0 added pcapng_decode (PCAPng next-generation
	// packet capture file inspector — block-based envelope
	// with per-section endianness dispatch via SHB BOM;
	// 9-entry block type table; SHB / IDB / EPB body
	// decoders; options walker with text surfacing;
	// per-section block summary + record + payload caps).
	// Pair to pcap_decode for the complete packet-capture
	// container coverage; PCAPng is Wireshark's default
	// since 2018.
	// v0.288.0 added netflow_v5_decode (NetFlow v5 export
	// packet dissector — 24-byte header + N × 48-byte
	// flow records with TCP flag bitfield decoded into 8
	// named flags + 13-entry IP protocol name table +
	// duration derivation from First/Last SysUptime +
	// CIDR prefix derivation from addr+mask + sampling
	// mode breakdown). Universal flow-export protocol;
	// every NOC sees flows from every Cisco / Juniper /
	// Arista router for traffic accounting + anomaly
	// detection + SIEM correlation.
	// v0.289.0 added dhcpv6_decode (DHCPv6 per RFC 8415 —
	// 4-byte header or 34-byte Relay header; 13-entry
	// message type table; TLV option walker with ~25-
	// entry code name table; DUID parsing with 4-entry
	// type table; IA_NA / IA_PD recursive sub-option
	// walking; Status Code 7-entry name table; DNS / NTP
	// server IPv6 lists). IPv6 sibling to dhcp_packet_
	// decode; every dual-stack network runs DHCPv6
	// alongside SLAAC for stateful address assignment +
	// prefix delegation + DNS / NTP configuration.
	// v0.290.0 added ospfv3_packet_decode (OSPFv3 per RFC
	// 5340 — 16-byte common header (drops OSPFv2's AuType
	// + Auth); 5-entry packet type table with per-type
	// bodies; 6-named-bit Options decode; 20-byte LSA
	// Header with 3-bit Flooding Scope + 13-bit Function
	// Code (9-entry name table). IPv6 sibling to ospf_
	// packet_decode; used in every IPv6-routed network.
	// v0.291.0 added sctp_packet_decode (SCTP per RFC
	// 4960 + extensions — 12-byte common header + chunk
	// walker with 4-byte alignment padding; ~20-entry
	// chunk type table; per-type body decoders for DATA
	// (with ~25-entry PPID name table) / INIT / INIT_ACK
	// / SACK / HEARTBEAT / ABORT / ERROR; TLV parameter
	// walker for INIT; Gap Ack Block + Duplicate TSN
	// arrays for SACK; Error Cause TLV walker with 13-
	// entry name table). Third-pillar IP transport;
	// foundational for telco signalling + WebRTC data
	// channels + multi-homed HA pairs.
	// v0.292.0 added diameter_packet_decode (Diameter
	// per RFC 6733 — 20-byte header with R/P/E/T command
	// flags + ~20-entry Command Code name table (Base +
	// 3GPP S6a) + ~15-entry Application ID name table;
	// AVP walker with V/M/P flags + optional Vendor-ID;
	// ~35-entry AVP Code name table; type-aware value
	// decoding (UTF8String / Unsigned32 / Address);
	// Result-Code class mapping). RADIUS-successor 3GPP
	// AAA protocol carried by SCTP on every modern
	// cellular network; pairs with radius_packet_decode
	// + sctp_packet_decode for complete telco-AAA
	// coverage.
	// v0.293.0 added tacacs_plus_decode (TACACS+ per RFC
	// 8907 — 12-byte header + 3-entry packet type table +
	// per-type body decoders for AUTH START/REPLY/CONTINUE
	// / AUTHOR REQUEST/RESPONSE / ACCT REQUEST/REPLY with
	// 6-entry Authen-Type / 10-entry Service / 8-entry
	// AUTH REPLY status name tables; named arg list
	// surfacing for AUTHOR + ACCT; optional MD5-derived
	// XOR body decryption when shared key supplied).
	// Third pillar AAA protocol completing the RADIUS +
	// Diameter + TACACS+ trio; the dominant router CLI
	// access protocol on Cisco-heavy networks; only AAA
	// option that supports per-command authorization.
	// v0.294.0 added tftp_decode (TFTP per RFC 1350 +
	// option extensions from RFC 2347 / 2348 / 2349 /
	// 7440 — 2-byte opcode + 6-entry name table; per-
	// opcode body decoders for RRQ/WRQ with Filename +
	// Mode + 4-entry option name table; DATA with Block
	// Number + payload preview; ACK; ERROR with 9-entry
	// error code name table; OACK). Foundational
	// minimal file-transfer protocol; universal in PXE /
	// network boot, IoT firmware updates, and Cisco /
	// Juniper / Arista config push.
	// v0.295.0 added msdp_decode (MSDP per RFC 3618 —
	// 3-byte TLV header + 6-entry message type table;
	// per-type body decoders for SA / SA Request / SA
	// Response (with N × (S, G) entries + optional
	// encapsulated bootstrap datagram) / Keepalive /
	// Notification with 7-entry error code name table).
	// Inter-domain multicast protocol completing the
	// IGMP + PIM + MSDP trio; runs over TCP port 639
	// between Rendezvous Points across PIM-SM domains.
	// v0.296.0 added sflow_v5_decode (sFlow v5 per InMon
	// spec — datagram common header + sample walker with
	// 4-entry standard format table; Flow Sample body
	// with Source Class+Index + Sampling Rate + In/Out
	// ifIndex + flow records walker (Raw Packet Header
	// with 17-entry header protocol table; Ethernet
	// Frame Data; IPv4/IPv6 Data); Counter Sample body
	// with Generic Interface Counters 19-field decode).
	// Packet-sampling counterpart to netflow_v5_decode;
	// dominant monitoring telemetry on datacenter
	// switches; consumed by DDoS-detection / capacity
	// planning / security-NDR platforms.
	// v0.297.0 added netflow_v9_decode (NetFlow v9 per
	// RFC 3954 — 20-byte header + FlowSet walker with
	// 3-kind table (Template / Options Template / Data);
	// Template FlowSet with field-spec walker using ~40-
	// entry IANA Information Element name table; per-
	// template record_size_bytes derivation; Data
	// FlowSet surfaced as raw hex annotated with
	// referencing Template ID). Template-based flow-
	// export format superseding v5 and bridging to
	// IPFIX; dominant on post-2010 Cisco/Juniper/Arista
	// enterprise + carrier gear; completes the netflow
	// _v5 + netflow_v9 + sflow_v5 telemetry trio.
	// v0.298.0 added ipfix_decode (IPFIX per RFC 7011 —
	// IETF standardization of NetFlow v9; 16-byte
	// header + Set walker with 3-kind table; Template
	// Set with enterprise-bit-extended field specifiers
	// + ~45-entry IPFIX IE camelCase name table; Options
	// Template Set with scope/option field split; Data
	// Set surfaced as raw hex annotated with referencing
	// Template ID). Used by Linux iptables/nftables flow
	// exporters, Cisco ASR/NCS, ntopng, akvorado,
	// GoFlow2, pmacct, every modern flow collector;
	// completes the v5 + v9 + IPFIX + sFlow flow-
	// telemetry quartet.
	// v0.299.0 added l2tp_v3_decode (L2TPv3 per RFC 3931
	// UDP mode — 16-bit bit-packed common header with
	// T/L/S/Version dispatch; Control Message with
	// Length + Connection ID + Ns + Nr + AVP walker;
	// Data Message with Session ID + payload preview;
	// ~20-entry IETF AVP name table; 15-entry Message
	// Type name table covering SCCRQ/SCCRP/SCCCN/
	// StopCCN/HELLO/ICRQ/ICRP/ICCN/CDN/WEN/SLI/ACK;
	// Hidden AVP detection). Pseudowire encapsulation
	// pairing with pppoe_decode for ISP broadband
	// subscriber backhaul + LI + L2 VPN services.
	// v0.300.0 (milestone) added esp_decode + ah_decode
	// (IPsec ESP per RFC 4303 + AH per RFC 4302 in one
	// internal/ipsec package; two Specs — +2 registry).
	// ESP: 8-byte SPI+Sequence header + opaque encrypted
	// payload preview. AH: 12-byte fixed header (Next
	// Header + PayloadLength + Reserved + SPI +
	// Sequence) + variable-length ICV (size derived
	// from PL); 13-entry Next Header IP-protocol name
	// table; SPI semantic notes. Universal IPsec data-
	// plane protocols on every site-to-site VPN + IPsec
	// remote-access deployment.
	// v0.301.0 added ike_v2_decode (IKEv2 per RFC 7296
	// — control-plane companion to esp_decode + ah_
	// decode. 28-byte fixed header with 4-entry exchange
	// type table (IKE_SA_INIT / IKE_AUTH / CREATE_CHILD_
	// SA / INFORMATIONAL) + 3-bit flag decode; chained
	// payload walker with ~15-entry payload type table;
	// Notify body decoded with ~30-entry message type
	// name table + Error/Status class; SK encrypted
	// payload surfaced as opaque hex with key-state
	// note). Universal on every site-to-site VPN +
	// IPsec remote-access deployment.
	// v0.302.0 added ntlm_decode (NTLM / MS-NLMP message
	// dissector — auto-detect by NTLMSSP\0 signature +
	// MessageType; 3-entry message type table NEGOTIATE
	// / CHALLENGE / AUTHENTICATE; per-type body decoders
	// with Field triple resolution; ~22-entry
	// NegotiateFlags named-bit set; 10-entry AV pair
	// AvId name table; Version structure decode).
	// Universal Windows authentication on every AD-
	// joined network; embedded in SMB / HTTP / LDAP /
	// DCERPC; high pentest + DFIR value as Type 2 + 3
	// messages feed directly into hashcat for offline
	// password recovery.
	// v0.303.0 added pcp_decode (PCP per RFC 6887 — 24-
	// byte common header with R-bit + 3-entry opcode
	// table (ANNOUNCE / MAP / PEER); request/response
	// header decoders; MAP/PEER opcode bodies with
	// IPv6-mapped addresses; 14-entry Result Code name
	// table; 5-entry option code name table; 10-entry
	// IP-protocol name table). Modern NAT/firewall
	// config protocol on UDP port 5351 — supersedes
	// NAT-PMP; universal in residential broadband CPE +
	// CGNAT enforcement; consumed by uTorrent /
	// Tailscale / libpcp / libnatpmp / miniupnpd.
	// v0.304.0 added natpmp_decode (NAT-PMP per RFC
	// 6886, predecessor to PCP — tight 2/12/16-byte
	// fixed-position messages; 6-entry opcode name
	// table covering requests + responses for Public
	// Address / Map UDP / Map TCP; 6-entry Result Code
	// name table; PCP version-2 detection note).
	// Apple's 2008 design still deployed in older
	// residential broadband CPE; tried first by modern
	// P2P clients before falling back to UPnP IGD.
	// v0.305.0 added dccp_packet_decode (DCCP per RFC
	// 4340 — generic header + 10-entry packet type name
	// table; short vs extended sequence-number header
	// dispatch via X bit; per-type body decoders for
	// Request/Response/Ack-family/Reset with 12-entry
	// Reset Code name table). Fourth-pillar IP transport
	// alongside TCP/UDP/SCTP; niche but well-defined;
	// used in WebRTC fallbacks + embedded game-server
	// protocols.
	// v0.306.0 added ptpv2_decode (PTPv2 per IEEE
	// 1588-2008 — 34-byte common header with 4-bit
	// messageType field + 10-entry messageType name
	// table; per-type body decoders for Sync /
	// Delay_Req / Pdelay_Req / Pdelay_Resp / Follow_Up
	// / Delay_Resp / Pdelay_Resp_Follow_Up; 30-byte
	// Announce body with BMCA inputs (priority1/2,
	// grandmaster clockClass + clockAccuracy +
	// offsetScaledLogVariance + grandmasterIdentity +
	// stepsRemoved + timeSource); timeSource +
	// clockAccuracy name tables; flagField bit decode
	// set including Announce-only timeProperties bits).
	// The wire-time-sync companion to NTP decoders for
	// 5G/telecom fronthaul, finance HFT timestamping,
	// industrial TSN (IEEE 802.1AS gPTP), power-grid
	// IEC 61850, and SMPTE ST 2110 broadcast media.
	// v0.307.0 added someip_decode (SOME/IP per AUTOSAR
	// R23-11 — 16-byte header with Service ID + Method
	// ID + Length + Client/Session ID + Protocol/
	// Interface Version + Message Type with TP-bit +
	// Return Code; 8-entry messageType name table
	// REQUEST through ERROR including *_ACK variants;
	// 12-entry returnCode name table E_OK through
	// E_E2E_REPEATED; SOME/IP-SD body decoder for
	// Service Discovery on UDP/30490 with Reboot/
	// Unicast flags, Entries[] (Service + Eventgroup
	// variants with TTL=0 stop-semantics), Options[]
	// (IPv4/IPv6 endpoint family decoded into IP + L4
	// + port); 8-entry SD entry type name table; 8-
	// entry SD option type name table). The automotive
	// Ethernet RPC + pub/sub bus alongside CAN/CAN-FD;
	// drives ADAS sensor feeds, IVI/cluster signalling,
	// inter-domain controller traffic in zonal
	// architectures (Tesla, Rivian, VW MEB+, BMW Neue
	// Klasse).
	// v0.308.0 added dnp3_decode (DNP3 per IEEE
	// 1815-2012 — 10-byte data-link header with
	// 0x0564 sync + Length + Control field
	// (DIR/PRM/FCB/FCV/code) + Dest + Src + header
	// CRC; 5-entry primary + 4-entry secondary link
	// function-code name tables; user-data block
	// walker stripping per-16-byte-block CRCs;
	// transport function byte FIN/FIR/seq;
	// application header with Application Control
	// (FIR/FIN/CON/UNS/seq) + Function Code + IIN for
	// responses; 20+ entry application function code
	// name table; 16-entry IIN-bit decoded set). The
	// dominant utility-SCADA protocol in North
	// American power-grid, water, and oil-and-gas
	// telemetry; pairs with modbus_decode for full
	// industrial coverage; complements PTPv2's IEC
	// 61850 substation positioning.
	// v0.309.0 added iec104_decode (IEC 60870-5-104
	// per IEC TC57 — 6-byte APCI (0x68 sync + Length
	// + 4-byte Control field) with I/S/U-format
	// dispatch on the low 2 bits of control byte 0;
	// I-format 15-bit Send/Receive sequence numbers;
	// U-format STARTDT/STOPDT/TESTFR act+con function
	// bit name set; 6-byte ASDU header (Type ID +
	// Variable Structure Qualifier with SQ +
	// numElements + 2-byte Cause of Transmission with
	// P/N + T bits + originator address + 2-byte
	// Common Address LE); 40+ entry Type Identification
	// name table (M_SP/DP/ME/IT_*/C_SC/DC/SE/IC/CS_*/
	// F_FR/SR/SC/LS/AF/SG/DR_*); 20-entry Cause of
	// Transmission name table (per/cyc / spont / act /
	// actcon / inrogen / reqcogen / unknown_*). The
	// European/Asian utility-SCADA counterpart to
	// DNP3; dominant on substation/control-centre
	// boundary in EU + Asia power-grid operators.
	// v0.310.0 added s7comm_decode (classic S7Comm
	// PDUs over ISO-on-TCP per RFC 1006, port 102 —
	// 4-byte TPKT header + variable COTP header
	// (Length Indicator + PDU Type + optional TPDU
	// number with EOT bit) + 10-or-12-byte S7 header
	// (Protocol ID 0x32 + ROSCTR + 2-byte Reserved
	// + 2-byte PDU Reference + 2-byte Parameter
	// Length + 2-byte Data Length + optional Error
	// Class + Code); 9-entry COTP PDU type name
	// table (CR/CC/DT/DR/DC/ED/EA/RJ/ER); 4-entry
	// ROSCTR name table (Job_Request / Ack /
	// Ack_Data / Userdata); 15-entry function-code
	// name table (CPU_services / Read_Var / Write_Var
	// / Request_Download / Download_Block /
	// Download_Ended / Start_Upload / Upload /
	// End_Upload / PLC_Control / PLC_Stop /
	// Setup_Communication); 9-entry Error Class
	// name table (No_Error / Application_Relationship
	// / Object_Definition / No_Resources_Available
	// / Error_On_Service_Processing /
	// Error_On_Supplies / Access_Error). The Siemens
	// S7-300/400/1200/1500 PLC protocol; canonical
	// Stuxnet target; dominant on the factory floor
	// in EU/Asian manufacturing.
	// v0.311.0 added goose_decode (IEC 61850-8-1
	// GOOSE messages — 8-byte fixed header (APPID +
	// Length + Reserved1 + Reserved2) + ASN.1 BER-
	// encoded IECGoosePdu with outer tag 0x61 and
	// 12 context-class IMPLICIT fields tagged 0x80-
	// 0xAB: gocbRef VISIBLE-STRING / timeAllowedToLive
	// INTEGER / datSet / goID / UtcTime (8-byte split
	// into 4-byte secondsSinceEpoch + 3-byte
	// fractionOfSecond + 1-byte quality) / stNum /
	// sqNum / test BOOLEAN / confRev / ndsCom /
	// numDatSetEntries / allData SEQUENCE OF Data;
	// BER length walker for short and long form;
	// IEC 62351-6 trailing security bytes surfaced).
	// The time-critical multicast Ethernet protocol
	// (EtherType 0x88B8, 4 ms latency budget per
	// IEC 61850-5 Type 1A) carrying protective-
	// relay trip signals in modern digital
	// substations; completes the substation trio
	// PTPv2 + IEC 104 + GOOSE.
	// v0.312.0 added enip_decode (EtherNet/IP +
	// CIP per ODVA CIP Vol 1+2 — 24-byte LE
	// encapsulation header (Command + Length +
	// Session Handle + Status + Sender Context +
	// Options); 9-entry Command name table (NOP /
	// ListServices / ListIdentity / ListInterfaces
	// / RegisterSession / UnRegisterSession /
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
	// / Read_Tag / Write_Tag / Forward_Open ...)
	// + 20+ entry general status name table. The
	// dominant North American factory-floor PLC
	// protocol; Allen-Bradley/Rockwell ControlLogix
	// / CompactLogix / MicroLogix; completes the
	// factory PLC trifecta with modbus + s7comm.
	// v0.313.0 added profinet_dcp_decode (Profinet
	// DCP per IEC 61158-6-10 — 2-byte FrameID with
	// 4-entry name table (Hello / Get_Set /
	// Identify_Request / Identify_Response); 10-byte
	// DCP header (ServiceID + ServiceType + Xid +
	// ResponseDelay + DataLength); 7-entry Option
	// name table (IP / DeviceProperties / DHCP /
	// LLDP / ControlBlock / DeviceInitiative /
	// AllSelector); TLV block walker with 16-bit
	// alignment padding; per-suboption decoders for
	// MAC + IP_Parameter + NameOfStation + Vendor +
	// VendorID/DeviceID + DeviceRole bitmask (IO-
	// Device / IO-Controller / IO-Multidevice / PN-
	// Supervisor)). Bootstrap discovery protocol for
	// Siemens Profinet networks; EtherType 0x8892
	// L2-only; pairs with s7comm_decode for full
	// Siemens-shop ICS pentest coverage.
	// v0.314.0 added usb_badusb_classify
	// (top-30 #10 from docs/catalog/gap-analysis.md
	// — sole forensic-side native-fit primitive on
	// the list). Reconstructs keystrokes + a
	// DuckyScript-style transcript from a stream of
	// USB HID Keyboard Boot Protocol reports (8-byte
	// reports: modifier bitmap + reserved + 6 HID
	// Usage codes). 80+ entry HID Usage code name +
	// Shift-variant table covering a..z / 1..9 0 /
	// Enter / Escape / Backspace / Tab / Space /
	// punctuation row / Caps Lock / F1..F12 / Home
	// / PageUp / Delete / End / PageDown / arrow
	// keys; key-down event detection by report-to-
	// report diffing; Caps Lock state tracking;
	// reconstructed text + DuckyScript v1-style
	// transcript with STRING folding for consecutive
	// printable characters + non-printable keyword
	// mapping (ENTER / ESC / TAB / GUI / CTRL +
	// arrow + F-keys) + modifier+key combos. The
	// defensive sibling of the badusb_* generation
	// family; incident-response forensics on
	// suspected BadUSB attacks from a usbmon pcap.
	// v0.315.0 added zwave_decode (classic Z-Wave
	// MAC-layer frames per Sigma Designs SDS-12852
	// — 9-byte fixed header (4-byte HomeID + 1-byte
	// SourceNodeID + 2-byte Frame Control with
	// Header Type + Routed/AckReq/LowPower/
	// SpeedModified/Beam flags + 4-bit Sequence
	// Number + 1-byte Length + 1-byte
	// DestinationNodeID) + payload (Command Class +
	// Command + parameters) + 1-byte XOR checksum;
	// 4-entry Header Type name table (Singlecast /
	// Multicast / Ack / Explore); 30+ entry
	// Command Class name table covering BASIC /
	// SWITCH_BINARY/MULTILEVEL/ALL/TOGGLE / SCENE /
	// SENSOR_BINARY/MULTILEVEL / METER /
	// THERMOSTAT_MODE/OPERATING/SETPOINT/FAN /
	// MULTI_CHANNEL / DOOR_LOCK / USER_CODE /
	// CONFIGURATION / ALARM / MANUFACTURER /
	// POWERLEVEL / PROTECTION / NODE_NAMING /
	// BATTERY / CLOCK / HAIL / WAKE_UP /
	// ASSOCIATION / VERSION / INDICATOR /
	// TIME_PARAMETERS / SECURITY S0 / SECURITY_2
	// S2). Sub-GHz IoT mesh protocol (868/908/920
	// MHz on ITU-T G.9959 FSK PHY); the dominant
	// "smart home" controller protocol; pairs with
	// Flipper Zero RF capture for Yale / Kwikset /
	// Schlage Z-Wave lock attacks + SmartThings hub
	// enumeration + battery-drain DoS targeting
	// WAKE_UP-frame-flooded sensors.
	// v0.316.0 added opcua_decode (OPC UA Binary
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
	// SecureChannelId + TokenId + SequenceNumber +
	// RequestId); UA String + UA ByteString
	// helpers). Modern industrial-messaging
	// protocol that supersedes OPC Classic; the
	// vendor-neutral lingua franca of MES + SCADA
	// + historian + IIoT gateway stacks; sits
	// ABOVE the field-protocol family already
	// covered by modbus/dnp3/iec104/s7comm/enip/
	// profinet_dcp; default TCP port 4840.
	// v0.317.0 added mqtt_sn_decode (MQTT-SN
	// v1.2 per OASIS spec — UDP variant of MQTT
	// for constrained IoT devices). Variable-
	// length header (1-byte short form 1-255;
	// 0x01 long-form indicator + uint16 BE length
	// for ≥256 byte messages); 28-entry MsgType
	// name table (ADVERTISE / SEARCHGW / GWINFO /
	// CONNECT / CONNACK / WILLTOPICREQ /
	// WILLTOPIC / WILLMSGREQ / WILLMSG /
	// REGISTER / REGACK / PUBLISH / PUBACK /
	// PUBCOMP / PUBREC / PUBREL / SUBSCRIBE /
	// SUBACK / UNSUBSCRIBE / UNSUBACK / PINGREQ /
	// PINGRESP / DISCONNECT / WILLTOPICUPD /
	// WILLTOPICRESP / WILLMSGUPD / WILLMSGRESP);
	// Flags byte decode (DUP + 2-bit QoS with
	// MQTT-SN-specific QoS=-1 fire-and-forget +
	// Retain + Will + CleanSession + 2-bit
	// TopicIdType: normal / predefined /
	// short_name / reserved); per-MsgType body
	// decoders for CONNECT (Flags + ProtocolId +
	// Duration + ClientId), CONNACK (ReturnCode),
	// REGISTER (TopicId + MsgId + TopicName),
	// PUBLISH (Flags + TopicId + MsgId + Data),
	// SUBSCRIBE (Flags + MsgId + TopicId or
	// TopicName), SUBACK (Flags + TopicId + MsgId
	// + ReturnCode), DISCONNECT (optional sleep
	// Duration), ADVERTISE / GWINFO; 4-entry
	// ReturnCode name table (Accepted /
	// Rejected_congestion / Rejected_invalid_topic_ID
	// / Rejected_not_supported). UDP/1883;
	// complements mqtt_packet_decode for full
	// MQTT-family coverage; common in
	// LoRaWAN/Zigbee/6LoWPAN gateway backhaul +
	// industrial sensor telemetry.
	// v0.318.0 added ssdp_decode (Simple Service
	// Discovery Protocol per UPnP Device
	// Architecture 1.1 — HTTP-over-UDP on
	// multicast 239.255.255.250:1900). Three
	// message kinds (M-SEARCH / NOTIFY /
	// HTTP/1.1 response); case-insensitive header
	// parser surfacing canonical UPnP fields
	// (Host / Cache-Control with max-age
	// extraction / Location / Server / ST
	// (Search Target) / USN with usn_uuid +
	// usn_nt deconstruction / NT (Notification
	// Type) / NTS (Notification Subtype:
	// ssdp:alive / ssdp:byebye / ssdp:update) /
	// MAN / MX / BOOTID.UPNP.ORG /
	// CONFIGID.UPNP.ORG / SEARCHPORT.UPNP.ORG);
	// vendor / non-standard headers surfaced as a
	// generic other_headers map. Foundational
	// UPnP / consumer-IoT discovery layer used by
	// smart TVs, streaming receivers, media
	// servers, NAS units, network printers,
	// routers (UPnP-IGD), smart-home hubs; common
	// in DEF CON Wireless / Recon Village CTFs +
	// home-network pentests + UPnP-IGD WAN-port-
	// forwarding attack chains.
	// v0.319.0 added nbns_decode (NetBIOS Name
	// Service per RFC 1001 + RFC 1002 — UDP/137).
	// 12-byte DNS-style header (TxID + Flags +
	// QD/AN/NS/AR counts); flags decode (QR +
	// Opcode + AA + TC + RD + RA + Broadcast +
	// RCODE); 5-entry Opcode name table (QUERY /
	// REGISTRATION / RELEASE / WACK / REFRESH);
	// 8-entry RCODE name table (No_Error /
	// Format_Error / Server_Failure / Name_Error
	// / Not_Implemented / Refused_Error /
	// Active_Error / Conflict_Error); NetBIOS
	// name decoder (32-byte wire encoding →
	// 15-byte trimmed name + 1-byte suffix); 20+
	// entry NetBIOS suffix name table
	// (Workstation / Master_Browser / Messenger
	// / RAS_Server / Domain_Master_Browser /
	// Domain_Controllers / Master_Browser per
	// subnet / Browser_Election / NetDDE /
	// File_Server / RAS_Client / MS_Exchange
	// family / Lotus_Notes / Modem_Sharing /
	// SMS_Client / MS_Exchange_MTA/IMC /
	// Network_Monitor_Agent/App); NB-type
	// resource record decoder with IPv4 list
	// extraction; RFC 1035 compression pointer
	// traversal up to 5 hops deep. Canonical
	// target of Responder.py NBNS poisoning
	// attacks; common in DEF CON Recon Village +
	// AD pentest engagements; pairs with future
	// llmnr_decode + mdns_decode for the
	// Windows/Bonjour name-resolution trio.
	// v0.320.0 added ndp_decode (ICMPv6 NDP per
	// RFC 4861 + 4191 + 8106). 4-byte ICMPv6
	// header (Type/Code/Checksum); 5-entry NDP
	// type name table (Router_Solicitation /
	// Router_Advertisement / Neighbor_Solicitation
	// / Neighbor_Advertisement / Redirect); per-
	// type fixed-field decoders (RA: CurHopLimit
	// + M/O/H/Prf flags + RouterLifetime +
	// ReachableTime + RetransTimer; NS/NA: Target
	// Address; NA additionally R/S/O flags;
	// Redirect: Target + Destination Address);
	// NDP Options TLV walker; 9-entry option
	// type name table (Source/Target
	// Link-Layer Address / Prefix Information /
	// Redirected Header / MTU / Nonce / Route
	// Information / RDNSS / DNSSL); per-option
	// decoders for LLA → MAC, Prefix Info →
	// prefix + L/A/R flags + lifetimes, MTU,
	// RDNSS → IPv6 DNS server list + lifetime,
	// DNSSL → length-prefixed search-domain
	// list, Route Information → prefix + Prf +
	// route lifetime. Foundational IPv6
	// signalling layer; canonical mitm6 /
	// suddensix / fake_router6 SLAAC-poisoning
	// pentest target.
	// v0.321.0 added llmnr_decode (Link-Local
	// Multicast Name Resolution per RFC 4795 —
	// UDP/5355). 12-byte DNS-style header with
	// LLMNR-specific Flags interpretation (QR +
	// Opcode=0 LLMNR_QUERY + bit 10 C Conflict +
	// TC + bit 8 T Tentative + RCODE); 6-entry
	// RCODE name table; 9+ entry RR-type name
	// table (A / NS / CNAME / SOA / PTR / MX /
	// TXT / AAAA / SRV); DNS label-encoded name
	// walker per RFC 4795 §2.1.7 (explicitly
	// forbids compression pointers — rejects
	// 0xC0+ prefix as malformed); per-RR-type
	// RDATA decoders for A → IPv4, AAAA → IPv6,
	// PTR / CNAME → name, other types → opaque
	// hex. The canonical Responder.py poisoning
	// target alongside NBNS — NTLMv2-hash-
	// capture entry point on Windows networks
	// where DNS is locked down; pairs with
	// nbns_decode for the Windows name-
	// resolution duo and future mdns_decode for
	// the consumer-IoT/Bonjour case.
	// v0.322.0 added mdns_decode (Multicast DNS
	// per RFC 6762 + DNS-SD per RFC 6763 —
	// UDP/5353 multicast 224.0.0.251 / FF02::FB).
	// 12-byte DNS-style header with mDNS-specific
	// Flags interpretation; DNS label-encoded
	// name walker WITH full RFC 1035 §4.1.4
	// compression-pointer support (unlike LLMNR
	// which forbids them); question records with
	// QU bit (top bit of QCLASS — Question
	// Unicast response preferred); answer
	// records with Cache-Flush bit (top bit of
	// CLASS); 9+ entry RR-type name table (A /
	// NS / CNAME / SOA / PTR / MX / TXT / AAAA /
	// SRV / OPT / NSEC); per-RR-type RDATA
	// decoders for A → IPv4, AAAA → IPv6,
	// PTR/CNAME → name (with compression
	// traversal), SRV → priority + weight +
	// port + target (DNS-SD instance →
	// host:port), TXT → list of length-prefixed
	// strings split on '=' into key=value pairs
	// per DNS-SD §6 canonical metadata format.
	// Completes the Windows + Bonjour name-
	// resolution trio with nbns_decode +
	// llmnr_decode + mdns_decode; canonical
	// decode for AirDrop / AirPrint / AirPlay /
	// Chromecast / HomeKit / Spotify Connect /
	// Sonos / Plex enumeration; common in DEF
	// CON Recon Village + home-network pentests
	// + IoT enumeration workflows.
	// v0.323.0 added openflow_decode (OpenFlow
	// per ONF spec 1.0/1.3/1.5 — TCP/6653
	// modern / TCP/6633 legacy). 8-byte common
	// header (Version + Type + Length + XID);
	// 6-entry Version name table (OF 1.0
	// through 1.5); 35-entry Type name table
	// covering HELLO / ERROR / ECHO_*/
	// FEATURES_*/GET_CONFIG_*/SET_CONFIG/
	// PACKET_IN/OUT/FLOW_MOD/FLOW_REMOVED/
	// PORT_STATUS/GROUP_MOD/METER_MOD/TABLE_MOD/
	// MULTIPART_*/BARRIER_*/ROLE_*/ASYNC_*/
	// BUNDLE_*; per-Type body decoders for
	// HELLO (Version Bitmap TLV walker), ERROR
	// (14-entry error-type name table —
	// HELLO_FAILED / BAD_REQUEST / BAD_ACTION /
	// BAD_INSTRUCTION / BAD_MATCH /
	// FLOW_MOD_FAILED / GROUP_MOD_FAILED /
	// PORT_MOD_FAILED / TABLE_MOD_FAILED /
	// QUEUE_OP_FAILED / SWITCH_CONFIG_FAILED /
	// ROLE_REQUEST_FAILED / METER_MOD_FAILED /
	// TABLE_FEATURES_FAILED + EXPERIMENTER),
	// FEATURES_REPLY (datapath_id + n_buffers
	// + n_tables + auxiliary_id + capabilities
	// bitmap with 7-entry decoded set:
	// FLOW_STATS / TABLE_STATS / PORT_STATS /
	// GROUP_STATS / IP_REASM / QUEUE_STATS /
	// PORT_BLOCKED), ECHO (opaque payload);
	// other types surfaced as body_hex for
	// downstream walkers. The canonical SDN
	// control protocol; common in datacenter
	// SDN research + OpenFlow-controller
	// fuzzing engagements.
	// v0.324.0 added gsmtap_decode (GSMTAP
	// cellular protocol tap per Osmocom —
	// UDP/4729). 16-byte fixed pseudo-header
	// (Version + HeaderLen + PayloadType +
	// Timeslot + ARFCN with band/uplink bits +
	// Signal level signed dBm + SNR signed +
	// Frame Number BE + SubType + Antenna +
	// SubSlot + Reserved); 15+ entry PayloadType
	// name table (UM / UM_L2 / ABIS / UM_BURST
	// / SIM / TETRA / WMX_BURST / GB_LLC /
	// GB_SNDCP / GMR1_UM / UMTS_RLC_MAC /
	// LTE_RRC / LTE_MAC / LTE_MAC_FRAMED /
	// OSMOCORE_LOG / QC_DIAG); 17-entry GSM Um
	// L2 channel name table (BCCH / CCCH /
	// RACH / AGCH / PCH / SDCCH / SDCCH4 /
	// SDCCH8 / TCH_F / TCH_H / PACCH / CBCH52
	// / PDCH / PTCCH / CBCH51 / VOICE_F /
	// VOICE_H); LTE RRC channel direction
	// (even=DL, odd=UL Osmocom convention);
	// ARFCN band + uplink/downlink bit
	// extraction. The canonical encapsulation
	// for cellular protocol captures; common
	// in DEF CON / Black Hat / HITB cellular
	// CTFs + SDR research + 5G IMSI-catcher
	// forensics.
	// v0.325.0 added hart_ip_decode (HART-IP
	// per HART Foundation HCF_SPEC-085 —
	// UDP/TCP port 5094). 8-byte envelope
	// header (Version + Message Type + Message
	// ID + Status Code + Sequence Number +
	// Byte Count); 4-entry Message Type name
	// table (Request / Response / Publish /
	// NAK); 6-entry Message ID name table
	// (Session_Initiate / Session_Close /
	// Keep_Alive / HART_PDU / Direct_PDU /
	// Publish_Burst_Notify); encapsulated HART
	// payload surfaced as hart_payload_hex
	// for downstream HART command walkers
	// (Cmd 0 Read Unique Identifier /
	// Cmd 13/18 Read Tag/Descriptor /
	// Cmd 42 Device Reset / Cmd 48 Read
	// Additional Device Status etc.). The
	// process-automation dissector for
	// oil/gas/chemical/water plants — Emerson
	// DeltaV / Honeywell Experion / ABB
	// Ability / Yokogawa CENTUM / Schneider
	// Foxboro Evo on the DCS/SCADA side;
	// Rosemount / Endress+Hauser / Yokogawa
	// EJX / ABB / Honeywell SmartLine field
	// instruments. Targets DEF CON ICS Village
	// CTFs + S4 Symposium + process-pentest
	// engagements.
	// v0.326.0 added rtsp_decode (RTSP per RFC
	// 7826 RTSP 2.0 + RFC 2326 RTSP 1.0 —
	// TCP/554). Three message kinds: Request
	// (METHOD URL RTSP/version), Response
	// (RTSP/version code reason), Interleaved
	// RTP (binary `$` + channel + length +
	// payload). 11-entry Method name table
	// (OPTIONS / DESCRIBE / ANNOUNCE / SETUP /
	// PLAY / PAUSE / TEARDOWN / GET_PARAMETER
	// / SET_PARAMETER / REDIRECT / RECORD);
	// HTTP-style status code categorisation
	// (Informational / Success / Redirection /
	// Client_Error / Server_Error /
	// Vendor_Error); case-insensitive header
	// parser surfacing canonical RTSP fields
	// (CSeq / Session / Transport / Range /
	// Scale / Speed / Public / Allow /
	// RTP-Info / Content-Type/Length /
	// User-Agent / Server / Date /
	// WWW-Authenticate / Authorization); body
	// surfacing per Content-Length. The
	// canonical IP-camera pentest entry point
	// (Hikvision / Axis / Dahua / Bosch /
	// Vivotek / Pelco) + streaming-server
	// fingerprint (Wowza / GStreamer / Live555
	// / VLC); pairs with the existing
	// sdp_decode + rtp_decode Specs for full
	// streaming-stack coverage.
	// v0.327.0 added smtp_decode (SMTP per RFC
	// 5321 — TCP/25 MTA, 587 submission
	// STARTTLS, 465 implicit-TLS SMTPS). Two
	// message kinds: Server Response (3-digit
	// status code + - continuation or space +
	// text, multi-line aggregation per §4.2.1);
	// Client Command (verb + optional
	// argument). 14+ entry Verb name table
	// (HELO / EHLO / AUTH / MAIL / RCPT / DATA
	// / RSET / VRFY / EXPN / QUIT / STARTTLS /
	// HELP / NOOP / BDAT); HTTP-style status
	// categorisation (Success / Intermediate /
	// Transient_Error / Permanent_Error);
	// multi-line response aggregation with
	// final_line_text extraction; EHLO
	// extension list aggregation (STARTTLS /
	// AUTH / SIZE / 8BITMIME /
	// ENHANCEDSTATUSCODES). Foundational mail-
	// server pentest tool — open-relay testing,
	// user enumeration via VRFY/EXPN/RCPT,
	// STARTTLS downgrade audit, SASL mechanism
	// enumeration; canonical decode for Exim /
	// Postfix / Sendmail / Exchange / Office
	// 365 / Google Workspace / Mailcow MTAs.
	// v0.328.0 added pop3_decode (POP3 per RFC
	// 1939 + RFC 2449 CAPA + RFC 2595 STLS +
	// RFC 5034 AUTH SASL — TCP/110 cleartext,
	// 995 implicit-TLS POP3S). Two message
	// kinds: Server Response (+OK / -ERR + text;
	// multi-line for LIST/RETR/TOP/UIDL/CAPA
	// with '.' terminator and byte-stuffing
	// removal per §3); Client Command (verb +
	// optional argument). 15+ entry Verb name
	// table (USER / PASS / APOP / STAT / LIST /
	// RETR / DELE / NOOP / RSET / QUIT / TOP /
	// UIDL / STLS / CAPA / AUTH); status
	// indicator categorisation (Success /
	// Error); multi-line data aggregation with
	// byte-stuffing removal. The mail-retrieval
	// counterpart to SMTP; canonical decode for
	// Dovecot / Courier / qmail-pop3d / Exchange
	// POP3 / O365 POP3 servers; common in
	// credential-spray + APOP timestamp-leakage
	// + STLS-downgrade pentests + USER/PASS
	// error-divergence username enumeration.
	// v0.329.0 added imap4_decode (IMAP4rev1
	// per RFC 3501 + RFC 2595 STARTTLS + RFC
	// 2087 QUOTA + RFC 2342 NAMESPACE + RFC
	// 2177 IDLE + RFC 2971 ID — TCP/143
	// cleartext / 993 implicit-TLS IMAPS).
	// Four message kinds: Continuation (+ /
	// SASL multi-step prompt); Untagged
	// Response (* / data or status); Command
	// + Tagged Response (disambiguated by
	// second token — OK/NO/BAD/BYE/PREAUTH →
	// Tagged Response, else Command). 25+
	// entry Verb name table (LOGIN cleartext-
	// creds / AUTHENTICATE / SELECT / EXAMINE
	// / CREATE / DELETE / RENAME / SUBSCRIBE /
	// UNSUBSCRIBE / LIST / LSUB / STATUS /
	// APPEND / CHECK / CLOSE / EXPUNGE /
	// SEARCH / FETCH content-disclosure /
	// STORE / COPY / UID / NOOP / LOGOUT /
	// CAPABILITY / STARTTLS / IDLE server-push
	// / NAMESPACE / ID); 5-entry Status name
	// table (OK / NO / BAD / BYE / PREAUTH);
	// 15+ entry Untagged Type name table
	// (CAPABILITY / LIST / LSUB / STATUS /
	// SEARCH / FLAGS / FETCH / EXISTS / RECENT
	// / EXPUNGE / NAMESPACE / QUOTA / QUOTAROOT
	// / ID / ESEARCH); continuation prompt
	// extraction; numeric-prefix '* 12 EXISTS'
	// detection. Completes the email-protocol
	// triad with smtp_decode + pop3_decode +
	// imap4_decode; the dominant modern mail-
	// access protocol used by Exchange / Office
	// 365 / Google Workspace / Dovecot / Cyrus
	// / Courier / Zimbra / FastMail / Apple
	// Mail / Thunderbird / iOS Mail / Outlook.
	const expected = 407
	if initialRegistrySize != expected {
		t.Errorf("registry names at init = %d, want %d (wave-by-wave checked in §D of runbook)",
			initialRegistrySize, expected)
	}
}
