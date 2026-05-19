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
	const expected = 358
	if initialRegistrySize != expected {
		t.Errorf("registry names at init = %d, want %d (wave-by-wave checked in §D of runbook)",
			initialRegistrySize, expected)
	}
}
