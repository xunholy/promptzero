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
	// v0.330.0 added kerberos_decode (Kerberos
	// v5 per RFC 4120 — the authentication
	// protocol underpinning every Active
	// Directory deployment + most enterprise
	// SSO stacks; MIT Kerberos / Heimdal /
	// Microsoft AD / Apple Open Directory /
	// FreeIPA-IdM; UDP/88 + TCP/88). The
	// highest-value AD-pentest dissector in
	// the catalogue: username enumeration
	// (cname leaked in every AS-REQ); AS-REP
	// roasting detection (pre_auth_required
	// false = hashcat mode 18200 candidate);
	// encryption-type downgrade audit (rc4-
	// hmac etype 23 flagged weak); SPN +
	// realm disclosure (Kerberoasting target
	// goldmine); Kerberoasting recon (TGS-REQ
	// surfaces actively-requested SPNs).
	// 7-entry message type name table (AS-REQ
	// / AS-REP / TGS-REQ / TGS-REP / AP-REQ /
	// AP-REP / KRB-ERROR); 11-entry Encryption
	// Type name table (des-cbc-crc / des-cbc-
	// md4 / des-cbc-md5 / des3-cbc-sha1 / aes
	// 128 + 256 cts-hmac-sha1-96 / aes128 +
	// 256 cts-hmac-sha256 + 384 / rc4-hmac /
	// rc4-hmac-exp / camellia128 + 256 cts-
	// cmac); 8-entry PA-DATA name table (PA-
	// TGS-REQ / PA-ENC-TIMESTAMP preauth / PA-
	// PW-SALT / PA-ETYPE-INFO / PA-PK-AS-REQ
	// PKINIT / PA-ETYPE-INFO2 / PA-PAC-REQUEST
	// / PA-FOR-USER S4U2self); 13-entry KRB-
	// ERROR error-code name table including
	// KDC_ERR_C_PRINCIPAL_UNKNOWN (username
	// enum) + KDC_ERR_PREAUTH_REQUIRED (canon
	// "NOT AS-REP roastable") + KDC_ERR_PREAUTH
	// _FAILED (wrong password). Encrypted
	// ticket + enc-part NOT decrypted (byte
	// counts only — offline hashcat is the
	// next step); PAC + PKINIT inner CMS +
	// GSS-API wrapping + cross-realm referrals
	// out of scope.
	// v0.331.0 added ldap_decode (LDAP v3 per RFC
	// 4511 — the canonical directory-service
	// protocol used by every Active Directory
	// deployment + most enterprise IAM stacks;
	// TCP/389 cleartext + TCP/636 LDAPS + UDP/389
	// CLDAP). AD-pentest counterpart to kerberos
	// _decode — together they form the complete
	// AD directory-attack dissector pair.
	// Surfaces cleartext credentials via SimpleBind
	// (simple_bind_present flag + bind_password
	// _bytes LENGTH only — privacy-preserving);
	// username + DN enumeration via SearchRequest
	// (baseObject + SearchResultEntry objectName
	// — every user/computer/group DN leaked);
	// brute-force feedback via resultCode (49
	// invalidCredentials = wrong password, 0
	// success = working credential); SASL
	// mechanism enumeration (GSSAPI / GSS-SPNEGO /
	// DIGEST-MD5 / CRAM-MD5 / EXTERNAL / PLAIN).
	// 22-entry operation name table (BindRequest
	// APP 0 / BindResponse APP 1 / UnbindRequest
	// / SearchRequest / SearchResultEntry /
	// SearchResultDone / Modify/Add/Del/ModifyDN
	// /Compare/Extended Request+Response pairs /
	// AbandonRequest / SearchResultReference /
	// IntermediateResponse APP 25); 17-entry
	// resultCode name table; 4-entry search scope
	// name table (baseObject / singleLevel /
	// wholeSubtree canonical full-dump / sub
	// ordinateSubtree). Filter parser + LDAPS/
	// StartTLS + SASL inner-decode (GSSAPI carries
	// Kerberos AP-REQ already handled by kerberos
	// _decode) + controls + MS NetLogon binary
	// layout out of scope.
	// v0.332.0 added smb2_decode (SMB2 / SMB3
	// per Microsoft Open Specifications [MS-SMB2]
	// — the canonical Windows file-share and
	// lateral-movement protocol; TCP/445 direct
	// + TCP/139 NBSS framing). Completes the AD-
	// pentest dissector quartet with kerberos
	// _decode + ldap_decode + ntlm_decode. Lateral-
	// movement decoder for every Windows pentest
	// engagement; surfaces NTLM-relay vulnerability
	// (NEGOTIATE_RESPONSE SigningRequired flag),
	// EternalBlue candidates (dialect 0x02FF
	// wildcard = SMB1 advertise), admin-share
	// access (TREE_CONNECT ADMIN$/C$/IPC$),
	// named-pipe lateral-movement vectors (CREATE
	// \pipe\spoolss PrintNightmare / \pipe\
	// netlogon ZeroLogon / \pipe\lsarpc LSA SAM
	// dump / \pipe\samr AD enum / \pipe\srvsvc
	// NetSessionEnum), authentication feedback
	// (STATUS_LOGON_FAILURE password-spray signal).
	// 19-entry command name table (NEGOTIATE /
	// SESSION_SETUP / LOGOFF / TREE_CONNECT /
	// TREE_DISCONNECT / CREATE / CLOSE / FLUSH /
	// READ / WRITE / LOCK / IOCTL / CANCEL / ECHO
	// / QUERY_DIRECTORY / CHANGE_NOTIFY / QUERY
	// _INFO / SET_INFO / OPLOCK_BREAK); 6-entry
	// dialect name table; 15-entry NTSTATUS name
	// table; NEGOTIATE_REQUEST + NEGOTIATE_RESPONSE
	// + TREE_CONNECT_REQUEST + CREATE_REQUEST body
	// walkers; SMB3 encryption Transform header
	// detection. NetBIOS framing + NTLMSSP/Kerberos
	// inner blob (handled by ntlm_decode + kerberos
	// _decode) + compound message chain + per-
	// command body decode beyond key 4 commands +
	// lease/durable handle state out of scope.
	// v0.333.0 added dcerpc_decode (DCE/RPC per
	// DCE 1.1 + Microsoft [MS-RPCE] — the MS-RPC
	// framing layer that carries nearly every
	// Windows AD attack chain; TCP/135 EPM +
	// TCP/49152+ ephemeral + inside SMB2 named
	// pipes). Completes the AD-pentest dissector
	// quintet with smb2_decode + kerberos_decode
	// + ldap_decode + ntlm_decode. Surfaces BIND
	// interface UUID + REQUEST opnum — the
	// canonical attack-vector identifier. 20+
	// interface UUIDs flagged with canonical
	// attack vectors: netlogon (ZeroLogon
	// CVE-2020-1472) / drsuapi (DCSync — mimikatz
	// lsadump::dcsync + impacket secretsdump) /
	// samr (AD enum) / lsarpc (SAM secrets) /
	// svcctl (PsExec) / spoolss (PrintNightmare
	// CVE-2021-1675/34527) / atsvc (Task Scheduler
	// lateral move) / efs (PetitPotam coercion) /
	// wkssvc + srvsvc (NetWkstaUserEnum +
	// NetSessionEnum) / epmapper (RPC portmap).
	// 14-entry PTYPE name table (REQUEST / PING /
	// RESPONSE / FAULT / WORKING / NOCALL /
	// REJECT / ACK / CL_CANCEL / FACK / CANCEL
	// _ACK / BIND / BIND_ACK / BIND_NAK / ALTER
	// _CONTEXT / ALTER_CONTEXT_RESP / SHUTDOWN /
	// CO_CANCEL / ORPHANED / AUTH3); 6-entry pfc
	// _flags name table; 16-byte common header
	// with byte-order discrimination via drep[0]
	// bit 4; BIND + REQUEST + FAULT body walkers;
	// 9-entry NCA fault status name table. NDR
	// parameter marshalling + IDL inner-decode +
	// DCOM ORPCTHIS + sec_trailer (NTLM/Kerberos
	// auth_value handled by ntlm_decode + kerberos
	// _decode) + per-interface opnum-name mapping
	// (1000+ interfaces) out of scope.
	// v0.334.0 added tds_decode (TDS / Tabular
	// Data Stream per Microsoft Open
	// Specifications [MS-TDS] — the Microsoft SQL
	// Server protocol; TCP/1433 default + dynamic
	// TCP/49152+ for named instances + UDP/1434
	// SQL Server Browser). Canonical SQL Server
	// pentest dissector that extends the
	// Microsoft-stack pentest surface beyond the
	// AD-pentest quintet. Surfaces: cleartext
	// username via Login7 OffsetLength UTF-16LE;
	// password length only (XOR-obfuscated 0xA5
	// deliberately NOT deobfuscated — privacy-
	// preserving); TLS-downgrade vulnerability
	// via Pre-Login ENCRYPTION token NOT_SUP; SQL
	// Server version disclosure via TDSVersion
	// field (canonical CVE-selection fingerprint);
	// database + AppName disclosure (sqlmap / SSMS
	// / SqlClient / SQLCMD identification); named-
	// instance hostnames via ServerName. 12-entry
	// packet type name table (SQL_BATCH / PRE
	// _TDS7_LOGIN / RPC / TABULAR_RESULT /
	// ATTENTION / BULK_LOAD_DATA / TRANSACTION
	// _MANAGER / TDS7_LOGIN / SSPI / PRE_LOGIN /
	// FEDERATED_AUTH_TOKEN); 5-entry Status flags
	// name table; 8-entry Pre-Login token-type
	// name table (VERSION / ENCRYPTION / INSTOPT
	// / THREADID / MARS / TRACEID / FEDAUTH
	// REQUIRED / NONCEOPT); 4-entry ENCRYPTION
	// mode name table (OFF / ON / NOT_SUP
	// downgrade flag / REQ hardened); Pre-Login
	// TLV token walker; Login7 fixed-field +
	// OffsetLength variable-data walker; 6-entry
	// TDS version-to-SQL-Server name table (7.0 /
	// 2000 SP1 / 2005 / 2008 / 2008 R2 / 2012-
	// 2022). TABULAR_RESULT token-stream parsing
	// (30+ tokens) + SSPI inner blob (ntlm/
	// kerberos) + TLS handshake + FEDAUTH +
	// password deobfuscation (deliberately
	// omitted) + UDP/1434 [MS-SQLR] enumeration
	// out of scope.
	// v0.335.0 added postgres_decode (PostgreSQL
	// frontend/backend protocol v3 per the
	// PostgreSQL documentation Part VIII; TCP/5432
	// default). Sibling decoder to tds_decode;
	// extends the database-protocol pentest surface
	// across MSSQL + PostgreSQL. Second-largest
	// open-source database pentest target after
	// MySQL. Surfaces: cleartext username +
	// database via StartupMessage; authentication
	// method enumeration via AuthenticationRequest
	// (CleartextPassword = MITM-capturable, MD5
	// Password = offline-crackable hashcat mode 12,
	// SASL SCRAM-SHA-256 = modern hardened); brute-
	// force feedback via ErrorResponse SQLSTATE
	// (28P01 invalid_password = canonical wrong-
	// password response; 3D000 invalid_catalog
	// _name = database enumeration); PostgreSQL
	// version disclosure via ParameterStatus
	// server_version GUC; SSL / GSS pre-handshake
	// detection (SSLRequest / GSSENCRequest /
	// CancelRequest magic payloads); application
	// _name client tool ID (psql / pgAdmin /
	// DBeaver / sqlmap). 15-entry frontend message
	// type name table + 24-entry backend message
	// type name table; StartupMessage body walker;
	// AuthenticationRequest 11-entry sub-type name
	// table; ErrorResponse TLV walker with 18-
	// entry field-tag name table + 8-entry
	// canonical SQLSTATE name table; Parameter
	// Status body walker. Bind/Parse parameter
	// marshalling + RowDescription type-OID
	// parsing + DataRow body + extended query
	// protocol + COPY streaming + TLS/GSSAPI
	// handshake + SASL inner-mechanism decode
	// (SCRAM-SHA-256 base64 blobs) + NOTIFY/LISTEN
	// payload semantics out of scope.
	// v0.336.0 added mysql_decode (MySQL /
	// MariaDB client/server protocol per the
	// MySQL documentation Chapter 4; TCP/3306
	// default; compatible with MariaDB). Completes
	// the database-protocol pentest trio with
	// tds_decode + postgres_decode (MSSQL +
	// PostgreSQL + MySQL/MariaDB). The largest
	// open-source database pentest target —
	// cloud-managed MySQL / RDS / Aurora / Cloud
	// SQL / Azure Database / PlanetScale / bare-
	// metal / containerized / cPanel. Surfaces:
	// server fingerprint via Handshake v10
	// server_version (canonical CVE-selection
	// fingerprint); authentication plugin
	// negotiation (mysql_native_password = SHA1-
	// weak offline-crackable hashcat mode 11200/
	// 300; caching_sha2_password = MySQL 8 modern
	// default; sha256_password = RSA requires SSL;
	// mysql_clear_password = CLEARTEXT MITM-
	// capturable; auth_socket = Unix peer-creds);
	// TLS support via CLIENT_SSL capability bit;
	// cleartext username + database via Handshake
	// Response41; brute-force feedback via ERR
	// 1045 ER_ACCESS_DENIED_ERROR + database
	// enumeration via 1049 ER_BAD_DB_ERROR. 25-
	// entry capability flags name table; 5-entry
	// status flags name table; 8-entry auth plugin
	// description table with security-posture
	// flagging; 11-entry error code name table.
	// Command-specific bodies + result-set parsing
	// + binary-protocol prepared-statement marshal
	// + compressed packet format + SSL handshake +
	// caching_sha2_password full-auth RSA exchange
	// + LOAD DATA LOCAL INFILE abuse vector +
	// MariaDB-specific extensions + XA/GTID/
	// replication semantics out of scope.
	// v0.337.0 added redis_decode (Redis RESP /
	// REdis Serialization Protocol v2 + v3 per
	// the Redis documentation; TCP/6379 default).
	// Third-largest open-source database pentest
	// target after MySQL + PostgreSQL — every
	// modern web-app stack uses Redis for
	// caching / sessions / queues / pub-sub.
	// Cloud-managed: ElastiCache / MemoryDB /
	// Cloud Memorystore / Azure Cache / Upstash
	// / Redis Enterprise. Canonical "exposed-
	// to-internet without auth" target —
	// 100,000+ unauthenticated instances per
	// Shodan. Multiple RCE primitives: CONFIG
	// SET dir/dbfilename = SSH authorized_keys
	// write; MODULE LOAD = direct native-code
	// RCE; SCRIPT/EVAL = Lua sandbox escape
	// CVE-2022-0543; SLAVEOF/REPLICAOF =
	// replication-RCE. Surfaces: AUTH cleartext
	// password (password_bytes length only —
	// privacy-preserving); HELLO with embedded
	// AUTH (RESP3 inline credentials);
	// dangerous-command flagging (CONFIG /
	// DEBUG / MODULE / SCRIPT / EVAL / SLAVEOF
	// / REPLICAOF / SHUTDOWN / FLUSH* / CLIENT
	// KILL); brute-force feedback via error
	// responses (-NOAUTH pre-auth signal; -
	// WRONGPASS canonical wrong-password; -
	// PERMISSION ACL denied; -MOVED/-ASK
	// Cluster redirection; -LOADING/-BUSY
	// operational state). 5-entry RESP2 type
	// table + 8-entry RESP3 type table; CRLF
	// frame walker; 13-entry dangerous-command
	// classification; 11-entry error category
	// table. RDB / AOF / Cluster slot map /
	// module command IDLs / sub-array recursion
	// / TLS handshake / RESP3 attributes /
	// client tracking / full key-value content
	// out of scope.
	// v0.338.0 added mongodb_decode (MongoDB wire
	// protocol per MongoDB documentation; TCP/
	// 27017 mongod / 27018 mongos / 27019 config).
	// Compatible with FerretDB (Postgres proxy) +
	// AWS DocumentDB. High-value NoSQL pentest
	// target with exposure profile similar to
	// Redis — historical Mongo 2.x/3.x defaulted
	// to no auth + bind 0.0.0.0; Shodan finds tens
	// of thousands of unauthenticated instances.
	// Modern Mongo 4.x+ defaults to localhost +
	// SCRAM-SHA-256. Surfaces: MongoDB version +
	// auth-mechanism enumeration via isMaster/
	// hello (driver always sends on connect);
	// database + collection namespace cleartext
	// (OP_QUERY fullCollectionName + OP_MSG $db);
	// SASL auth exchange via saslStart/
	// saslContinue (mechanism + payload_bytes
	// LENGTH only — privacy-preserving; offline-
	// crackable hashcat mode 24100/24200 once
	// captured); dangerous-command flagging
	// (createUser/dropDatabase/listDatabases/eval
	// historical RCE primitive REMOVED in 4.4 but
	// legacy still deployed); build info
	// disclosure via buildInfo. 12-entry opCode
	// name table (OP_REPLY / OP_MSG_DEPRECATED /
	// OP_UPDATE / OP_INSERT / OP_QUERY / OP_GET
	// _MORE / OP_DELETE / OP_KILL_CURSORS / OP
	// _COMMAND / OP_COMMANDREPLY / OP_COMPRESSED
	// Snappy/zlib/zstd / OP_MSG modern); 18-entry
	// BSON element-type name table; OP_MSG +
	// OP_QUERY body walkers; BSON top-level
	// document walker. Full BSON value parsing +
	// Binary subtypes + OP_COMPRESSED decompression
	// + TLS handshake + SDAM topology monitoring +
	// Change Streams oplog + GridFS + CSFLE
	// encrypted-field BinData out of scope.
	// v0.339.0 added rdp_x224_decode (Microsoft
	// RDP initial-handshake dissector per
	// [MS-RDPBCGR] — TPKT + X.224 COTP CR/CC PDUs
	// + RDP_NEG_REQ / NEG_RSP / NEG_FAILURE
	// structures; TCP/3389 default). Universal
	// Windows pentest entry point — every Windows
	// Server + desktop deployment exposes 3389
	// at some layer. Extends Windows-stack pentest
	// surface alongside AD-pentest quintet.
	// Surfaces: username cleartext via RDP Cookie
	// (mstshash=<username> — canonical pre-auth
	// enumeration without sending credentials!);
	// routing token disclosure (msts=<token> RD
	// Connection Broker form); NLA/CredSSP
	// hardening posture (PROTOCOL_RDP=0 standard
	// no-TLS BlueKeep target / PROTOCOL_SSL TLS /
	// PROTOCOL_HYBRID CredSSP NLA modern
	// hardened default / PROTOCOL_RDSTLS /
	// PROTOCOL_HYBRID_EX / PROTOCOL_RDSAAD Entra
	// ID); server hardening enforcement via
	// NEG_FAILURE (SSL_REQUIRED_BY_SERVER /
	// HYBRID_REQUIRED_BY_SERVER = canonical NLA-
	// hardened response); selected-protocol via
	// NEG_RSP; Restricted Admin Mode detection.
	// 4-byte TPKT header + X.224 COTP header +
	// 5-entry PDU-type name table (CR / CC / DT /
	// DR / ER); RDP Cookie cstring walker;
	// RDP_NEG_REQ + NEG_RSP + NEG_FAILURE walkers;
	// 6-entry requestedProtocols name table; 3-
	// entry NEG_REQ flags name table; 3-entry
	// NEG_RSP flags name table; 6-entry
	// failureCode name table. MCS Connect Initial
	// + CredSSP TSRequest (handled by ntlm + krb5)
	// + RDP Security Layer + virtual channels +
	// licensing + FastPath PDUs + multi-segment
	// fragmentation out of scope.
	// v0.340.0 added vnc_rfb_decode (VNC RFB
	// Remote Framebuffer Protocol per RFC 6143 +
	// RealVNC / TightVNC / VeNCrypt / Apple ARD
	// extensions; TCP/5900-5999 default).
	// Universal remote-access pentest target —
	// RealVNC / TightVNC / TigerVNC / UltraVNC /
	// x11vnc / Vino / KRfb / Apple ARD / embedded
	// device VNC (printers / ATMs / industrial
	// HMIs / KVM-over-IP / DVR-NVR) / cloud-managed
	// VNC consoles (AWS Workspaces / Azure Bastion
	// / GCP). Pairs with rdp_x224_decode for
	// complete remote-access pentest surface.
	// Surfaces: ProtocolVersion banner (003.008 /
	// 003.007 / 003.003 — software-class
	// fingerprint); security-type enumeration
	// with vulnerability classification (None=1
	// NO AUTH REQUIRED exposed! / VNC=2 weak 8-
	// byte truncated DES hashcat mode 26200 / TLS
	// / VeNCrypt multi-mechanism / SASL / Apple
	// ARD=30); SecurityResult Failed reason
	// (canonical brute-force feedback); ServerInit
	// desktop-name hostname disclosure; pixel-
	// format + framebuffer-resolution
	// fingerprinting. 13-entry security-type name
	// table; ProtocolVersion banner walker;
	// security-types list walker (3.7+) +
	// single-type walker (3.3); Invalid (0) reason
	// walker; SecurityResult walker; ServerInit
	// 16-byte pixel-format walker. Auto-
	// discrimination between message kinds by
	// leading-byte inspection. Framebuffer
	// encodings + event PDUs + VNC password
	// decryption (deliberately omitted) +
	// VeNCrypt sub-handshake + SASL inner-decode
	// + Apple ARD DH key exchange + TightVNC sub-
	// auth list + HTTP-tunneled VNC TCP/5800-5899
	// out of scope.
	//
	// v0.341.0 added amqp091_decode (RabbitMQ /
	// AMQP 0-9-1 wire protocol; TCP/5672
	// plaintext, TCP/5671 AMQPS), kafka_decode
	// (Apache Kafka wire protocol; TCP/9092
	// plaintext, TCP/9093 SSL, TCP/9094
	// SASL_PLAINTEXT, TCP/9095 SASL_SSL), and
	// memcached_decode (Memcached binary protocol;
	// TCP/11211).
	//
	// v0.342.0 added ipmi_decode (IPMI RMCP/RMCP+
	// wire protocol; UDP/623), rip_decode (RIP
	// v1/v2 routing protocol; UDP/520), and
	// eigrp_decode (EIGRP routing protocol; IP
	// protocol 88).
	//
	// v0.343.0 added isis_decode (IS-IS routing
	// protocol; OSI CLNS L2), ldp_decode (LDP
	// MPLS signalling; TCP/UDP 646), and
	// rtmp_decode (RTMP live streaming; TCP/1935).
	//
	// v0.344.0 added grpc_decode (gRPC Length-
	// Prefixed Message framing; HTTP/2),
	// rsvpte_decode (RSVP-TE MPLS TE signalling;
	// IP protocol 46), and xmpp_decode (XMPP XML
	// messaging; TCP/5222, 5269).
	//
	// v0.345.0 added es_transport_decode (Elasticsearch internal
	// transport protocol; TCP/9300), zmtp_decode (ZMTP wire
	// protocol), and cassandra_decode (Cassandra CQL binary
	// protocol; TCP/9042 plaintext, TCP/9142 TLS).
	//
	// v0.356.0 added knxnetip_decode (KNXnet/IP — KNX building-
	// automation bus over UDP/3671; KNXnet/IP header + HPAI +
	// connection header + cEMI L_Data GroupValue telegram decode).
	//
	// v0.357.0 added mbus_decode (M-Bus / Meter-Bus, EN 13757 —
	// European smart-metering bus + wired sibling of wM-Bus;
	// link-layer frame + checksum + C/A/CI fields + Variable Data
	// Structure header with BCD serial / manufacturer / medium).
	//
	// v0.358.0 added ethercat_decode (EtherCAT, IEC 61158 — real-time
	// industrial-Ethernet motion-control fieldbus; EtherCAT header +
	// datagram chain walk with command / addressing / data / working
	// counter).
	//
	// v0.360.0 added subghz_tpms_decode (TPMS Sub-GHz bit-stream —
	// Manchester line decode + CRC-8 convention disambiguation +
	// 32-bit sensor-ID extraction; gap-analysis §3 rank 6).
	//
	// v0.361.0 added subghz_weather_decode (433 MHz weather-station —
	// LaCrosse TX141TH-Bv2 + Acurite 609TXC fixed-40-bit families with
	// checksum-gated interpretation; gap-analysis §3 rank 5).
	//
	// v0.362.0 added canbus_fd_decode (offline CAN / CAN-FD frame decode
	// over the SocketCAN candump grammar — 11/29-bit ID, CAN-FD
	// FDF/BRS/ESI + DLC↔length table, SAE J1939 PGN decomposition;
	// gap-analysis §3 rank 17).
	//
	// v0.367.0 added tpms_anomaly_detect (defensive blue-team analysis of a
	// sequence of TPMS frames — excess unique sensor IDs vs wheel count +
	// CRC-invalid frame flagging, observation-with-interpretation framing;
	// gap-analysis §3 rank 6). Companion to subghz_tpms_decode.
	//
	// v0.375.0 added dcf77_synth (offline DCF77 minute-telegram generator —
	// BCD + even-parity inverse of dcf77_decode, round-trip-verified against
	// it; gap-analysis honourable mention dcf77_clock_spoof, generation
	// only / no TX).
	//
	// v0.376.0 added rfid_pacs_encode (offline HID Wiegand bit-stream
	// generator — FC+CN+parity inverse of rfid_pacs_decode for H10301/
	// H10306, round-trip-verified; generation only / no write/TX).
	//
	// v0.377.0 added subghz_tpms_synth (offline TPMS frame generator —
	// Manchester + CRC-8 inverse of subghz_tpms_decode, round-trip-verified;
	// generation only / no TX).
	//
	// v0.378.0 added subghz_weather_synth (offline 433 MHz weather-station
	// frame generator — LaCrosse/Acurite field-packing + checksum inverse of
	// subghz_weather_decode, round-trip-verified; generation only / no TX).
	//
	// v0.379.0 added subghz_pocsag_synth (offline POCSAG paging transmission
	// generator — BCH(31,21) + parity + batch framing inverse of
	// subghz_pocsag_decode, BCH-verified vs the idle codeword + round-trip;
	// generation only / no TX).
	//
	// v0.380.0 added ndef_encode (offline NDEF message builder — URI + Text
	// record assembly inverse of ndef_decode, round-trip-verified; generation
	// only / no tag write).
	//
	// v0.381.0 added em4100_encode (offline EM4100 64-bit wire-frame builder —
	// header + row/column parity + stop, companion to em4100_decode; verified
	// by independent parity re-derivation; generation only / no write).
	//
	// v0.382.0 added nfc_emv_encode (offline EMV BER-TLV builder —
	// tag/length/value assembly inverse of nfc_emv_decode, round-trip-
	// verified; generation only / no card I/O).
	//
	// v0.385.0 added ibutton_encode (offline Dallas 1-Wire ROM-ID builder —
	// family + 48-bit serial + Maxim CRC-8, inverse of ibutton_decode;
	// verified by round-trip + the canonical Maxim AN-27 vector; generation
	// only / no key write).
	//
	// v0.386.0 added subghz_rollback_detect (offline defensive analyser over
	// a sequence of captured rolling-code frames — flags non-consecutive
	// duplicate codes (key-free replay/RollBack signature) + counter
	// regressions when decrypted counters are supplied; observation-not-
	// verdict; no RF/TX).
	//
	// v0.387.0 added ble_eddystone_encode (offline Eddystone beacon builder —
	// UID/URL/TLM/EID service-data assembly inverse of ble_eddystone_decode,
	// with URL scheme/expansion abbreviation; round-trip + spec-vector
	// verified; generation only / no BLE TX).
	//
	// v0.388.0 added ble_ibeacon_encode (offline Apple iBeacon builder —
	// UUID + major + minor + measured-power manufacturer-data assembly,
	// inverse of the iBeacon decode in ble_continuity_classify; round-trip +
	// fixed-layout vector verified; generation only / no BLE TX).
	//
	// v0.389.0 added ble_altbeacon_decode + ble_altbeacon_encode (the open
	// AltBeacon standard codec — company ID + 0xBEAC + 20-byte ID + ref RSSI
	// + reserved; the third major beacon format alongside Apple iBeacon and
	// Google Eddystone. Round-trip + canonical spec-example verified;
	// generation only / no BLE TX). +2 tools.
	//
	// v0.390.0 added wifi_pmkid_hc22000 (native hashcat mode-22000 PMKID line
	// builder — WPA*01*pmkid*ap*sta*essid***; removes the hcxpcapngtool
	// shell-out for the clientless-PMKID case. Anchored on hashcat's
	// published example hash; pure host-side, no capture/radio).
	//
	// v0.391.0 added wifi_wps_decode (WPS / Wi-Fi Simple Config data-element
	// dissector — walks the WSC attribute TLVs in a WPS IE: version, setup
	// state, AP-setup-locked, device password ID, config methods, identity.
	// The wash/reaver triage fields; pure offline parser, unknown attrs
	// surfaced as raw hex).
	//
	// v0.392.0 added wifi_rsn_decode (RSN WPA2/WPA3 IE dissector — names the
	// cipher + AKM suites (00-0F-AC), decodes the PMF capability bits, and
	// derives the security posture: WPA2-Personal / WPA3-SAE / transition /
	// Enterprise / OWE. Completes the suite-naming the wifi_80211 decoder
	// deferred; pure offline parser, vendor suites surfaced raw).
	//
	// v0.393.0 added wifi_deauth_detect (defensive 802.11 deauth/disassoc-
	// flood analyser over a sequence of decoded frames — broadcast-deauth /
	// volume-flood / targeted-client signals + reason-code histogram;
	// observation-not-verdict, no RF/TX).
	//
	// v0.394.0 added wifi_rogue_ap_detect (defensive rogue-AP / evil-twin
	// analyser over a set of decoded beacons — security-mismatch (downgrade
	// lure) / bssid-changed-security / ssid-multiple-bssid signals;
	// observation-not-verdict, composes with wifi_rsn_decode, no RF/TX).
	//
	// v0.395.0 added obd2_pid_decode (OBD-II / SAE J1979 Mode-01 PID value
	// decoder — computes RPM / speed / temps / MAF / … from the public
	// per-PID formulas, the value the j1850/canbus decoders left as raw
	// bytes; transport-independent, unknown PIDs surfaced raw).
	//
	// v0.396.0 added obd2_dtc_decode (OBD-II Mode-03/07/0A trouble-code
	// decoder — unpacks 2-byte DTCs into canonical SAE J2012 codes
	// (P/C/B/U + 4 digits); deterministic bit-unpack, padding skipped,
	// no guessed fault descriptions).
	//
	// v0.397.0 added uds_decode (UDS / ISO 14229 diagnostic-message decoder —
	// names the service, classifies request/positive/negative response,
	// decodes the NRC + sub-function + data identifier. The protocol behind
	// modern ECU attacks; pure offline parser, unknown values surfaced raw).
	//
	// v0.398.0 added isotp_decode (ISO-TP / ISO 15765-2 transport decoder +
	// reassembler — decodes SF/FF/CF/FC PCI and reassembles the multi-frame
	// UDS/OBD-II PDU off a CAN capture; the link between canbus_fd_decode and
	// uds_decode/obd2_*. Pure offline transform, sequence gaps noted).
	//
	// v0.399.0 added ble_spam_detect (defensive BLE-spam flood analyser —
	// runs the stateless advert classifier over a batch and flags many
	// distinct rotating MACs emitting one spam signature; surfaces the
	// cross-advert signal defense_classify_advertisement cannot. No RF/TX).
	//
	// v0.400.0 added wifi_wps_pin (WPS PIN checksum validator/completer —
	// validates an 8-digit PIN or completes a 7-digit prefix via the
	// reaver/bully wps_pin_checksum; pairs with wifi_wps_decode. Pure
	// offline math; vendor default-PIN databases deliberately not embedded).
	//
	// v0.403.0 added kwp_decode (KWP2000 / ISO 14230 diagnostic-message
	// decoder — UDS predecessor with a DISTINCT service-ID table (local-
	// identifier + comms-control services UDS lacks) that uds_decode would
	// mislabel; pure offline parser, unknown values surfaced raw).
	//
	// v0.404.0 added nfc_t2t_decode (NFC Forum Type 2 Tag structure decoder —
	// NTAG21x / Ultralight 7-byte UID + BCC validation + static lock bytes +
	// Capability Container; distinct from mifare (Classic) and ndef (the
	// message). Pure offline, BCC-checksum-anchored). v0.405 enhanced it with
	// NTAG21x config/password-protection decode (no new tool).
	//
	// v0.406.0 added lorawan_replay_detect (defensive LoRaWAN replay /
	// frame-counter-reuse analyser over a sequence of decoded frames —
	// key-free FCnt reuse/regression, direction-aware; observation-not-
	// verdict, no RF/TX).
	//
	// v0.407.0 added subghz_debruijn (de Bruijn optimal fixed-code brute
	// sequence generator — OpenSesame technique; all 2^n codes in ~2^n bits.
	// Generation only / no TX; self-verifiable de Bruijn property).
	//
	// v0.408.0 added isotp_encode (ISO-TP segmenter — inverse of
	// isotp_decode; splits a PDU into SF or FF+CFs (padded to 8) for
	// injecting a multi-frame UDS/OBD-II request. Generation only / no TX;
	// round-trip-verified against the reassembler).
	//
	// v0.409.0 added canbus_fd_encode (CAN/CAN-FD candump frame builder —
	// inverse of canbus_fd_decode; classic/remote/CAN-FD with BRS/ESI, the
	// frame-layer complement to isotp_encode. Generation only / no TX;
	// round-trip-verified against the decoder).
	//
	// v0.410.0 added nfc_t2t_encode (NFC Type 2 Tag header builder — inverse
	// of nfc_t2t_decode; UID + computed BCCs + lock + CC for magic-tag UID
	// clone-prep, NFC analogue of ibutton_encode. Generation only / no card;
	// round-trip + BCC-vector verified).
	//
	// v0.411.0 added uds_encode (UDS / ISO 14229 message builder — inverse of
	// uds_decode; SID + sub-function + suppressPosRsp + DID + payload, the
	// application-layer top of the inject chain. Generation only / no TX;
	// round-trip-verified against the decoder).
	//
	// v0.412.0 added kwp_encode (KWP2000 / ISO 14230 message builder —
	// inverse of kwp_decode; SID + param byte + payload, the legacy-vehicle
	// counterpart of uds_encode. Generation only / no TX; round-trip-
	// verified against the decoder).
	// v0.413.0 added ir_raw_decode (raw infrared timing-capture decoder —
	// NEC family: standard / extended / repeat, gated on NEC's address &
	// command bitwise-inverse checksum. Offline read; the IR analogue of
	// subghz_decode, complement to ir_decode_file).
	// v0.414.0 added nfc_emv_track2_decode (EMV tag 57 / ISO 7813 Track 2
	// Equivalent Data decoder — cracks the nibble-packed PAN / expiry /
	// service code / discretionary the BER-TLV walker leaves raw, gated on
	// the PAN's Luhn check digit. Offline read; extends internal/emv).
	// v0.415.0 added nfc_emv_dol_decode (EMV Data Object List decoder —
	// PDOL/CDOL1/CDOL2/DDOL/TDOL; walks the (tag,length) pairs the BER-TLV
	// walker can't parse, summing total_length. Structural reuse of the EMV
	// tag table; offline read; extends internal/emv).
	// v0.416.0 added nfc_emv_afl_decode (EMV Application File Locator decoder
	// — tag 94; expands the 4-byte [SFI, first, last, ODA] entries into the
	// implied READ RECORD command list, gated structurally (4-byte groups,
	// SFI 1-30, ascending ranges). Offline read; extends internal/emv).
	// v0.417.0 added em4100_frame_decode (EM4100 64-bit wire-frame decoder —
	// the parity-validating inverse of em4100_encode: checks the 9-bit
	// header, 10 row parities, 4 column parities, stop bit; recovers the
	// 5-byte ID. Round-trip-verified against the encoder. Offline read).
	// (v0.418/v0.419 added Sony SIRC + Samsung32 to the existing ir_raw_decode;
	//  v0.420 added H10304/H10302 to the existing rfid_pacs_encode — no new
	//  tools, so the count was unchanged for those.)
	// v0.421.0 added vin_decode (VIN / ISO 3779 check-digit validator + region
	// / model-year / WMI breakdown — offline complement to UDS DID F190 /
	// OBD-II Mode 09 PID 02; check digit is the anchor, internal/vin).
	// v0.422.0 added imei_decode (GSM IMEI / IMEISV Luhn-check validator + TAC
	// / serial breakdown — offline complement to gsmtap Identity Response;
	// Luhn is the anchor, TAC-to-device deliberately not guessed, internal/imei).
	// v0.423.0 added mac_classify (IEEE 802 MAC administration-bit classifier —
	// unicast/multicast (I/G), locally/universally administered (U/L →
	// randomized-MAC signal), broadcast; offline analysis complement to the
	// WiFi/BLE scans, layering the known-attack-OUI lookup. internal/macaddr).
	// v0.424.0 added ipv6_eui64_recover (recover the MAC embedded in an IPv6
	// Modified-EUI-64 interface identifier — detect FF:FE, strip it, flip the
	// U/L bit; chains into mac_classify. Offline complement to ndp/dhcpv6
	// decoders. internal/macaddr).
	// v0.425.0 added ble_addr_classify (BLE device-address classifier — random
	// subtype from the top 2 bits: static / resolvable-private (RPA) /
	// non-resolvable / reserved, or public OUI. The BLE counterpart of
	// mac_classify; RPA = privacy/tracking-resistant. internal/ble).
	// v0.426.0 added nfc_emv_cvm_decode (EMV CVM List / tag 8E — X/Y amounts +
	// 2-byte method/condition rules; structural parse, raw bytes always
	// surfaced + best-effort EMV names with unknowns flagged. Completes the
	// EMV field suite alongside track2/dol/afl. internal/emv).
	// v0.427.0 added iso7816_apdu_decode (ISO 7816-4 APDU decoder — response
	// SW1SW2 status word (incl. 61XX/6CXX/63CX families) + command CLA/INS/
	// P1/P2 length-case parsing with INS naming. Offline smart-card analysis
	// complement to nfc_apdu. internal/iso7816).
	// (v0.428/v0.429 extended iso7816_apdu_decode with the DESFire 91XX status
	//  family + CLA-0x90 command naming — no new tools, count unchanged.)
	// v0.430.0 added crc_compute (CRC compute/identify over the reveng
	// catalogue — CRC-8/16/32 models, each verified against its published
	// check value; identify mode fingerprints an unknown frame's CRC.
	// Protocol-RE aid, offline. internal/crc).
	// v0.431.0 added manchester_decode (Manchester line-code RE decoder —
	// both alignments + both conventions (IEEE 802.3 / Thomas), gated on the
	// 01/10-pairs validity rule; the raw-bitstream→data-layer step
	// complementing crc_compute. internal/linecode).
	// (v0.432 added CRC-24 models to crc_compute — no new tool, count unchanged.)
	// v0.433.0 added checksum_compute (non-CRC frame checksums — SUM-8/16,
	// XOR/LRC, Modbus LRC, Fletcher-16/32; compute + identify. Companion to
	// crc_compute for trailers that aren't CRCs. Fletcher verified against
	// published vectors. internal/checksum).
	// (v0.434/v0.435 extended hash_identify with AD-roasting + WPA/Cisco — no
	//  new tools, count unchanged.)
	// v0.436.0 added totp_generate (RFC 6238 TOTP / RFC 4226 HOTP generator —
	// offline OTP derivation from a recovered 2FA seed; SHA1/256/512, 6-8
	// digits; verified against the RFC published test vectors. internal/otp).
	// v0.437.0 added jwt_verify (JWS HMAC signature verifier — the verify
	// counterpart to jwt_decode: HS256/384/512 against a secret or candidate
	// list (weak-secret test), alg:none + asymmetric classified. Verified
	// against the canonical jwt.io token. internal/jwtsig).
	// v0.438.0 added jwt_forge (JWS forging — completes the decode/verify/forge
	// trio: re-sign claims (HS256/384/512) for claim-escalation / alg:none /
	// RS->HS alg-confusion. Offline payload builder, round-trip-verified +
	// reproduces the canonical jwt.io token. internal/jwtsig).
	// v0.439.0 added cisco_type7_decode (Cisco IOS type-7 reversible password
	// decode — fixed-key XOR, the service-password-encryption obfuscation;
	// recovers plaintext directly. Key pinned to published vectors. Complements
	// hash_identify's type 8/9 detection. internal/ciscopw).
	// v0.440.0 added hmac_compute (HMAC-SHA1/256/512 compute + verify — the
	// keyed-MAC tier / webhook-signature analogue of jwt_verify; verify or
	// forge a GitHub/Stripe/API HMAC signature. Verified against RFC 4231
	// vectors. internal/hmacutil).
	// (v0.442/v0.443 added no tools — otpauth:// URI + Steam Guard enhanced the
	// existing totp_generate.)
	// v0.444.0 added wpa_pmk_derive (WPA/WPA2-PSK PMK derivation —
	// PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32) per IEEE 802.11i; the offline
	// Wi-Fi precompute for hashcat 22000/16800. Verified against RFC 6070 PBKDF2
	// + IEEE 802.11i PMK vectors. internal/wpa).
	// v0.445.0 added nt_hash (Windows NT/NTLM hash compute — MD4(UTF-16LE(pw));
	// the compute side of hash_identify/hash_crack. Native MD4 verified against
	// the full RFC 1320 suite + the published NTLM vector. internal/nthash).
	// (v0.446 added no tool — nt_hash now also computes the legacy LM hash via
	// crypto/des, completing the pwdump LM:NT line; gated against three
	// cross-confirming LM vectors.)
	// v0.447.0 added md5crypt (Unix $1$ md5crypt / Apache $apr1$ compute + verify
	// — also Cisco IOS type 5. Native crypto/md5, gated against the OpenSSL
	// `passwd -1`/`-apr1` oracle. internal/unixcrypt).
	// v0.448.0 added sha_crypt (Unix $6$ sha512crypt / $5$ sha256crypt compute +
	// verify — the modern Linux /etc/shadow default. Native crypto/sha512+sha256
	// (Drepper), gated against the OpenSSL `passwd -6`/`-5` oracle. internal/unixcrypt).
	// v0.449.0 added bcrypt (bcrypt $2a/$2b/$2y compute + verify — the dominant
	// web-app hash. Wrap of x/crypto/bcrypt (already a dep; native infeasible —
	// Blowfish S-boxes); gated against the jBCrypt/OpenBSD published vectors).
	// (v0.450 added no tool — hash_crack_dictionary gained the 'mysql' and
	// 'crypt' ($1$/$apr1$/$5$/$6$ via unixcrypt.Verify) algorithms, so it can
	// now crack the modern /etc/shadow + MySQL hashes hash_identify detects.)
	// v0.451.0 added argon2 (Argon2id/Argon2i compute + verify — the OWASP-
	// recommended modern hash. Wrap of x/crypto/argon2 (already a dep; native
	// infeasible — memory-hard BLAKE2b), our own PHC parse/encode, gated against
	// argon2-cffi reference vectors. hash_crack also gained the 'argon2' algo.)
	// (v0.452 added no tool — jwt_verify completed asymmetric coverage: PS*/ES*/
	// EdDSA via jwtsig.VerifyPublicKey, round-trip-verified vs the stdlib signers.)
	// v0.453.0 added magstripe_decode (raw ISO 7813 Track 1/2 ASCII swipe parser
	// — the offline half of magspoof; PAN/name/expiry/service-code, Luhn-anchored.
	// internal/emv.DecodeMagstripe).
	// v0.454.0 added jwk_to_pem (JWK/JWKS -> PKIX PEM for RSA/EC/Ed25519; closes
	// the /.well-known/jwks.json -> jwt_verify workflow. jwt_verify also now
	// accepts a JWK/JWKS directly. Round-trip-verified vs the stdlib. internal/jwtsig).
	// v0.455.0 added nfc_iso15693_decode (ISO 15693 vicinity-card UID + AFI decode
	// — the second major HF NFC standard; 0xE0-prefix-anchored, manufacturer from
	// the shared ISO 7816-6 table. internal/iso15693).
	// v0.456.0 added flask_session (Flask/itsdangerous session cookie decode /
	// verify / forge — the web analogue of the JWT trio, the flask-unsign
	// weak-SECRET_KEY attack. Verified byte-for-byte vs itsdangerous. internal/flasksession).
	// v0.457.0 added pbkdf2_password (Django pbkdf2_sha256$ / Werkzeug pbkdf2:sha256:
	// password verify + compute — Python web-app user DBs. hash_crack also gained
	// 'django'/'werkzeug' modes. Verified vs Django/Werkzeug. internal/webpass).
	// v0.458.0 added phpass_password (WordPress $P$ / phpBB $H$ portable hash verify
	// + compute — iterated MD5. hash_crack also gained the 'phpass' mode. Verified
	// byte-for-byte vs passlib. internal/phpass).
	// (v0.459 added no tool — Werkzeug scrypt (scrypt:N:r:p, the modern Flask
	// default) verify/compute added to internal/webpass; pbkdf2_password and the
	// hash_crack 'werkzeug' mode now cover it. Verified vs Werkzeug + x/crypto/scrypt.)
	// v0.460.0 added nfc_iso14443b_decode (ISO 14443 Type B ATQB decode — the
	// ePassport/eID proximity standard; 0x50-anchored PUPI + protocol-info bit
	// fields. internal/iso14443b).
	// v0.461.0 added wifi_wsc_decode (Wi-Fi Simple Config / WPS credential decode
	// — the tap-to-connect Wi-Fi NFC tag / WPS M7-M8 Credential; SSID + auth/encr
	// + network-key TLVs, attribute IDs per hostap wps_defs.h. internal/wsc; also
	// wired into ndef_decode's application/vnd.wfa.wsc MIME path).
	// v0.462.0 added bluetooth_oob_decode (Bluetooth OOB pairing record — the
	// tap-to-pair NFC handover tag; BR/EDR Easy Pairing length+BD_ADDR framing +
	// LE OOB AD structures, with LE Role / LE device address / Class-of-Device
	// value decode added to the shared internal/ble EIR walker. internal/btoob;
	// also wired into ndef_decode's application/vnd.bluetooth.{ep,le}.oob paths).
	// (v0.463 added no tool — NDEF Connection Handover Hs/Hr/ac/cr/err decode +
	// nested-recursion depth guard, both inside the existing ndef_decode.)
	// v0.463.x: no registry change.
	// v0.464.0 added fdxb_decode (ISO 11784/11785 FDX-B animal/pet-microchip LF
	// transponder data-block decode — national + country code, flags, CRC-16
	// gated; verified vs two real Proxmark3 vectors. internal/fdxb).
	// v0.465.0 added t5577_config_decode (T5577 / ATA5577 config-register block-0
	// decode — modulation / bit rate / max block / AOR / PWD / ST; bit layout +
	// modulation table verified vs Proxmark3 + EM4100 0x00148040 & HID 0x00107060
	// config words. internal/t55xx).
	// v0.466.0 added ntag_config_decode (NTAG213/215/216 config-page decode —
	// AUTH0 / ACCESS (PROT/CFGLCK/NFC_CNT/AUTHLIM) / MIRROR; layout verified
	// byte-for-byte vs the NXP NTAG213/215/216 data sheet §8.5.7. internal/ntag).
	// v0.467.0 added nfc_t2t_tlv_decode (NFC Type 2 Tag data-area TLV walker —
	// NULL/Lock/Memory/NDEF/Proprietary/Terminator blocks; locates + decodes the
	// NDEF Message TLV via internal/ndef. Bridges a raw T2T dump to ndef_decode.
	// internal/t2t).
	// v0.468.0 added epc_decode (GS1 EPC UHF RAIN RFID — SGTIN-96 fully decoded:
	// company prefix / item ref / serial / EPC URIs / GTIN-14; partition table +
	// layout verified vs the GS1 TDS canonical vector. internal/epc).
	// v0.485.0 added ldap_password (LDAP RFC 2307 userPassword compute + verify —
	// {SHA}/{SSHA}/{MD5}/{SMD5} + pw-sha2 {SHA256}…{SSHA512}; H(pw‖salt)‖salt
	// base64, salt recovered from the blob on verify; gated vs the OpenLDAP
	// slappasswd oracle + definitional pw-sha2 vectors. internal/ldappw).
	// v0.486.0 added mysql_password (MySQL/MariaDB mysql_native_password compute +
	// verify — "*"+UPPER(hex(SHA1(SHA1(pw)))), hashcat 300; gated vs the published
	// PASSWORD('password') vector; the compute/verify complement to the existing
	// hash_crack mysql branch. internal/mysqlpw).
	// v0.487.0 added postgres_password (PostgreSQL md5 password compute + verify —
	// "md5"+hex(MD5(password+username)), hashcat 12; username-salted; the
	// DB-credential sibling of mysql_password; gated vs the documented
	// pg_md5_encrypt construction. internal/pgpassword).
	// v0.491.0 added postgres_scram (PostgreSQL SCRAM-SHA-256 verifier compute +
	// verify — SCRAM-SHA-256$iter:salt$StoredKey:ServerKey, hashcat 28600; the
	// PG 10+ default, modern successor to postgres_password's md5; gated vs the
	// RFC 7677 §3 worked example. internal/pgscram).
	// v0.492.0 added cisco_type8 (Cisco IOS type-8 secret compute + verify —
	// PBKDF2-HMAC-SHA256 / 20000 iters / Cisco base64, $8$salt$digest, hashcat
	// 9200; gated vs the canonical hashcat-9200 vector + a second cracked one.
	// internal/ciscopw type8.go).
	// v0.493.0 added msgpack_decode (MessagePack dissector — the binary-
	// serialization sibling of cbor_decode: nil/bool, fixint + uint/int widths,
	// float32/64, str/bin, array/map, ext; gated byte-for-byte vs the reference
	// msgpack library across every format family. internal/msgpack).
	// v0.495.0 added bson_decode (BSON document dissector — full recursive decode
	// of a mongodump .bson document: all element types, nested docs/arrays,
	// ObjectId, dates, binary subtypes, regex, timestamp, decimal128; gated
	// byte-for-byte vs the reference PyMongo bson library. internal/bson).
	// v0.497.0 added paseto_decode (PASETO token decode + Ed25519 verify — the
	// jwt_decode counterpart: vN.purpose.payload[.footer] structure, public
	// cleartext claims, v2/v4 Ed25519 signature verify over the PASETO PAE; gated
	// vs the official PASETO v4 test vectors. internal/paseto).
	// v0.498.0 added saml_decode (SAML 2.0 message decode — the SSO counterpart:
	// base64 ± DEFLATE -> XML + issuer/destination/NameID/conditions/audience +
	// signature-present golden-SAML triage; anchored vs an independent DEFLATE
	// redirect vector + a POST signed Response. internal/saml).
	// v0.499.0 added keytab_decode (MIT Kerberos .keytab v0x0502 parser — the
	// file-format complement to kerberos_decode: principals, KVNO, enctype, raw
	// key bytes (RC4 = NT hash flagged); anchored vs a keytab confirmed by the
	// MIT ktutil oracle. internal/keytab).
	// v0.500.0 added ccache_decode (MIT Kerberos credential cache v0x0504 parser —
	// default principal + per-credential client/server/key/times/flags + the
	// embedded ticket (pass-the-ticket loot; krbtgt TGT flagged); anchored vs a
	// ccache confirmed by the MIT klist -cf oracle. internal/ccache).
	// (v0.501.0 added no tool — kerberos bare-Ticket decode + ccache chain.)
	// v0.502.0 added netntlm_hashcat (NetNTLM crack-line builder — from a captured
	// NTLMSSP AUTHENTICATE + server challenge, emit the hashcat 5600 (NTLMv2) /
	// 5500 (NTLMv1) line; anchored byte-for-byte vs the hashcat 5600 example.
	// internal/netntlm).
	// v0.503.0 added krb_roast_hashcat (Kerberoast / AS-REP-roast crack-line
	// builder — from a captured AS-REP -> $krb5asrep$ (18200) or TGS-REP ->
	// $krb5tgs$ (13100), emit the hashcat line; anchored vs spec-conformant
	// AS-REP/TGS-REP vectors. internal/krbroast).
	// (v0.504.0 added no tool — krb_roast_hashcat AES etype 17/18 support.)
	// v0.505.0 added dcc2 (Domain Cached Credentials v2 / mscash2 compute +
	// verify — MD4(MD4(pw)+user)+PBKDF2-HMAC-SHA1, hashcat 2100; gated vs the
	// canonical hashcat-2100 example tom/hashcat. internal/dcc2).
	// v0.506.0 added ssh_privkey_decode (OpenSSH private-key openssh-key-v1
	// triage — encrypted?/cipher/kdf-rounds/key-type/SHA256-fingerprint/comment;
	// anchored vs ssh-keygen -l for ed25519 + rsa (encrypted and not).
	// internal/sshkey).
	// v0.507.0 added putty_privkey_decode (PuTTY .ppk private-key triage — the
	// Windows counterpart to ssh_privkey_decode: version/encrypted?/encryption/
	// key-type/SHA256-fingerprint/comment/Argon2 KDF params; the .ppk public
	// block is the same SSH-wire blob as an OpenSSH .pub, so the fingerprint is
	// cross-validated vs ssh-keygen -l. internal/puttykey).
	// v0.508.0 added pem_privkey_decode (PEM private-key triage — the openssl-key
	// counterpart to ssh/putty: format/encrypted?/algorithm+size/public-SHA256
	// (unencrypted)/cipher+KDF (PBKDF2 iter, scrypt N,r,p). Native: crypto/x509
	// for the standard DER + a hand-rolled encoding/asn1 walk for the encrypted
	// params; anchored vs openssl pkey -pubout + openssl asn1parse.
	// internal/pemkey).
	// (v0.509-v0.511 added no tool — APRS §9 compressed position + compressed
	// weather extended aprs_packet_decode; amqp091 DoS-panic fix + 93 fuzz
	// harnesses across decoder packages.)
	// v0.512.0 added gps_nmea_decode (GPS/GNSS NMEA 0183 sentence decode —
	// GGA/RMC/GLL/VTG/GSA/GSV: lat/lon/time/fix/speed/course/altitude with XOR
	// checksum validation; the offline complement to marauder_nmea. Anchored vs
	// pynmea2. internal/nmea).
	// (v0.513.0 added no tool — gps_nmea_decode GSV per-satellite + GST + ZDA.)
	// v0.514.0 added subghz_jammer_detect (offline sub-GHz jammer analyser — RSSI
	// floor + occupancy + dwell heuristic over a captured RSSI sequence, the
	// host-side complement to the on-device Jammer Detect FAP; observation-not-
	// verdict like subghz_rollback_detect. internal/subghz AnalyzeJamming).
	// v0.515.0 added maidenhead_locator (bidirectional Maidenhead grid-locator
	// <-> lat/lon converter — the ham/geo companion to aprs/ais/nmea; decode
	// returns center+SW-corner+cell, encode at 1-4 pairs. Anchored vs the
	// maidenhead reference library. internal/maidenhead).
	// v0.516.0 added geohash_decode (bidirectional geohash <-> lat/lon converter
	// — the geo companion to redis/mongodb/bson decoders, where geohashes appear
	// in GEO values / geo fields; decode returns center + half-cell + bbox,
	// encode at 1-12 chars. Anchored vs the pygeohash reference library.
	// internal/geohash).
	// v0.517.0 added uuid_decode (UUID/GUID structure + info-leak decoder —
	// version/variant + the v1/v6 leaked host MAC + creation time, v7 unix-ms
	// timestamp; v3/v4/v5 carry no recoverable data. Anchored vs Python's uuid
	// module. internal/uuidinfo).
	// v0.518.0 added objectid_decode (MongoDB ObjectId decoder — embedded
	// creation timestamp + random + counter; the MongoDB analogue of uuid_decode
	// and the completion of the opaque-hex ObjectId in mongodb/bson decoders.
	// Anchored vs pymongo ObjectId.generation_time. internal/objectid).
	// v0.519.0 added ulid_decode (ULID decoder — 48-bit ms creation timestamp +
	// 80-bit randomness from a 26-char Crockford-base32 ID; completes the
	// identifier-timestamp triad with uuid_decode/objectid_decode. Anchored vs
	// python-ulid + a hand-verified Crockford decode. internal/ulid).
	// v0.520.0 added snowflake_decode (Snowflake-ID decoder — 41-bit ms creation
	// timestamp from a Discord/Twitter-X 64-bit ID; the social-media-OSINT
	// sibling of uuid/objectid/ulid, candidate-per-platform (asserts none).
	// Anchored vs Discord's documented example. internal/snowflake).
	// v0.531.0 added rds_decode (RDS / RBDS FM Radio Data System group decoder
	// — PI + RBDS call sign, group type / TP / PTY, Programme Service name,
	// RadioText with the G0 charset; IEC 62106 / NRSC-4. Verified byte-for-byte
	// against the redsea reference test vectors. internal/rds).
	// v0.534.0 added osdp_packet_decode (OSDP / IEC 60839-11-5 access-control
	// reader-bus packet dissector — frame + control + SCB + command/reply code
	// + NAK error + CRC-16/AUG-CCITT or checksum validation. Verified
	// byte-for-byte against the libosdp phy-layer test vectors. internal/osdp).
	// v0.536.0 added eas_same_decode (EAS / SAME emergency-alert header decoder
	// — originator / event-code / FIPS-location / valid + issue time / callsign,
	// NWS NWSI 10-1712 / FCC 47 CFR 11.31. Verified against the documented NWS
	// worked example. internal/eas).
	// v0.537.0 added enocean_decode (EnOcean ESP3 / ERP1 building-automation
	// radio decoder — framing + dual CRC-8 + RORG + 32-bit sender ID + RSSI.
	// Verified against a CRC-8-valid RADIO_ERP1 reference frame. internal/enocean).
	// v0.538.0 added dsmr_p1_decode (DSMR / P1 smart-meter telegram decoder —
	// identifier + CRC-16/ARC validation + OBIS object decode [energy/power/
	// voltage/current/gas]. DSMR 5.0 / IEC 62056-21; verified byte-for-byte
	// against the dsmr_parser reference telegram (CRC 0x6796). internal/dsmr).
	// v0.539.0 added wmbus_decode (Wireless M-Bus / EN 13757-4 868 MHz radio
	// frame decoder — L/C/manufacturer/meter-ID/device-type + per-block CRC-16
	// + de-chunked application payload. The radio framing internal/mbus
	// explicitly deferred; verified against a CRC-valid Format-A frame and a
	// real meter header block (CRC 0x3363). internal/wmbus).
	// v0.541.0 added lin_frame_decode (LIN / ISO 17987 automotive body-bus
	// frame decoder — PID + parity validation + classic/enhanced checksum.
	// Verified against the standard LIN PID constants. internal/lin).
	// v0.542.0 added meshtastic_decode (Meshtastic LoRa-mesh packet-header
	// decoder — node IDs + packet ID + hop/ack/MQTT flags + channel hash +
	// next-hop/relay; the AES payload is surfaced as ciphertext. Wire layout
	// from the Meshtastic firmware PacketHeader. internal/meshtastic).
	// (v0.543.0 + v0.544.0 extended ais_nmea_decode with AIS Types 19/21/9/27
	// — no new tool, so the count is unchanged.)
	// v0.545.0 added ubx_decode (u-blox UBX binary protocol decoder — frame
	// envelope + Fletcher-16 checksum + NAV-PVT position/velocity/time body;
	// the binary counterpart to gps_nmea_decode. Anchored to pyubx2.
	// internal/ubx).
	// (v0.546.0 extended ubx_decode with NAV-SAT + NAV-STATUS — no new tool.)
	// v0.547.0 added rtcm_decode (RTCM 3.x differential-GNSS message decoder —
	// 0xD3 frame + CRC-24Q + message-type ID + 1005/1006 station-ARP ECEF
	// body; the corrections leg of the GNSS triad. Anchored to pyrtcm.
	// internal/rtcm).
	// (v0.548.0 extended gps_nmea_decode with the marine-instrument sentences
	// HDT/HDG/VHW/DBT/DPT/MTW/MWV/MWD/ROT — no new tool.)
	// v0.549.0 added imsi_decode (IMSI cellular subscriber-identity decoder —
	// MCC→country + MNC/MSIN split; the subscriber companion to imei_decode,
	// the IMSI gap it deferred. MCC table code-generated from python-stdnum's
	// imsi.dat; split verified against stdnum. internal/imsi).
	// v0.550.0 added iccid_decode (ICCID SIM-card-serial decoder — 89 MII +
	// E.164 country code + Luhn check; the SIM-card leg completing the
	// IMEI/IMSI/ICCID cellular identifier triad. Calling-code table
	// code-generated from libphonenumber; Luhn-anchored. internal/iccid).
	// v0.551.0 added mrz_decode (ICAO 9303 Machine Readable Zone decoder —
	// TD1/TD2/TD3 passport/ID/visa fields + 7-3-1 check-digit validation;
	// the BAC-key input for e-passport NFC. Verified against the mrz lib.
	// internal/mrz).
	// v0.552.0 added bcbp_decode (IATA Resolution 792 Bar Coded Boarding Pass
	// decoder — passenger/PNR/itinerary/seat from the boarding-pass barcode;
	// travel-OSINT companion to mrz_decode. Self-describing length markers;
	// conditional section surfaced raw. Verified vs the canonical IATA
	// example. internal/bcbp).
	// v0.553.0 added macsec_decode (IEEE 802.1AE MACsec SecTAG decoder —
	// TCI/AN flags + Short Length + Packet Number + Secure Channel Identifier
	// from the 0x88E5 wired-L2 security header; bodies out the EtherType the
	// vlan/lldp decoders only named. Verified vs scapy. internal/macsec).
	// v0.554.0 added dtp_decode (Cisco Dynamic Trunking Protocol decoder —
	// version + Domain/Status/Type/Neighbour TLVs; the VLAN-hopping
	// attack-surface signal, joining the cdp/lldp/stp switch-L2 set. Status
	// bits surfaced raw (Cisco-proprietary). Verified vs scapy. internal/dtp).
	// v0.555.0 added vtp_decode (Cisco VLAN Trunking Protocol decoder —
	// header + Summary (config revision/updater/MD5) + Subset (VLAN list)
	// bodies; surfaces the config-revision VLAN-database-attack signal.
	// Verified vs scapy. internal/vtp).
	// v0.556.0 added carp_decode (Common Address Redundancy Protocol decoder
	// — version/type + VHID + advskew/advbase + counter + SHA-1 HMAC; the
	// third FHRP decoder (hsrp/vrrp/carp), advskew = the hijack/MITM signal.
	// HMAC surfaced raw. Verified vs scapy. internal/carp).
	// v0.557.0 added erspan_decode (ERSPAN Type II/III header decoder —
	// version/vlan/cos/session-id + (II) index / (III) timestamp, GRE-
	// stripping, mirrored frame surfaced raw; port-mirror/interception
	// recon, pairs with gre_decode. Verified vs scapy. internal/erspan).
	// v0.558.0 added gtpv2_decode (GTPv2-C / GTP control-plane decoder —
	// header (version/flags/type/TEID/seq) + IE TLV walk with TS 29.274
	// type names + IMSI/MSISDN/MEI TBCD decode; the control-plane companion
	// to gtp_decode (which defers GTP-C). Verified vs scapy. internal/gtpv2).
	// v0.559.0 added pfcp_decode (PFCP / 5G N4 (SMF<->UPF) + 4G CUPS control
	// protocol — header (version/flags/type/SEID/seq) + IE TLV walk with
	// TS 29.244 names (code-generated from scapy) + Cause decode; the
	// session-manipulation attack surface. Verified vs scapy. internal/pfcp).
	// v0.560.0 added skinny_decode (Skinny/SCCP Cisco IP-phone signalling —
	// framed walk + 132-entry message-name table (code-generated from scapy)
	// + KeypadButton dialed-digit decode; VoIP call-flow/dialed-number recon.
	// Verified vs scapy. internal/skinny).
	// v0.561.0 added rpl_decode (RPL / RFC 6550 — the IPv6 routing protocol
	// for 6LoWPAN / 802.15.4 IoT mesh, carried in ICMPv6 type 155 — header +
	// message name (DIS/DIO/DAO/DAO-ACK) + DIO rank/version/MOP/DODAGID, the
	// sinkhole / version-rebuild attack fields. Verified vs scapy. internal/rpl).
	// v0.562.0 added vqp_decode (Cisco VQP / VMPS dynamic VLAN assignment,
	// UDP 1589 — 8-byte header + datatype/len/value TLV walk surfacing the
	// queried MAC + assigned VLAN name; third leg of the VLAN-attack family
	// with dtp + vtp (voiphopper / yersinia). Verified vs scapy. internal/vqp).
	// v0.563.0 added igmpv3_decode (IGMPv3 / RFC 3376 IPv4 multicast
	// membership v3 — checksum-verified header + Query (source list, QRV/QQIC
	// float codes, query type) + v3 Report group records (INCLUDE/EXCLUDE
	// source filters); multicast recon, v3 companion to igmp. Verified vs
	// scapy. internal/igmpv3).
	// v0.564.0 added tzsp_decode (TaZmen Sniffer Protocol, UDP 37008 — the
	// MikroTik/Aruba remote wireless-capture encapsulation: 4-byte header +
	// tag walk (RSSI/SNR/rate/channel/FCS) + raw encapsulated frame; wireless
	// sniffer recon. Verified vs scapy. internal/tzsp).
	// v0.565.0 added ripng_decode (RIPng / RFC 2080 IPv6 RIP, UDP 521 — the
	// IPv6 sibling of rip: 4-byte header + 20-byte route table entries with
	// the next-hop (metric 0xFF) + infinity (16) special RTEs; IPv6 routing
	// recon / route-injection surface. Verified vs scapy. internal/ripng).
	// v0.566.0 added gxrp_decode (GARP / GVRP / GMRP, IEEE 802.1D dynamic
	// VLAN + multicast registration — nested message/attribute lists with
	// the JoinIn/Leave/LeaveAll events + VLAN/group-MAC/service values; the
	// GVRP VLAN-hopping primitive, fourth leg of the VLAN-attack family with
	// dtp+vtp+vqp. Verified vs scapy. internal/gxrp).
	// v0.567.0 added maccontrol_decode (IEEE 802.3 MAC Control, EtherType
	// 0x8808 — 802.3x PAUSE (flow-control DoS) + 802.1Qbb PFC (priority-flow
	// storm) + EPON MPCP GATE/REPORT/REGISTER; the L2-DoS leg of the
	// LAN-attack family. Verified vs scapy. internal/maccontrol).
	// (v0.568.0 was an IR feature — RC5/RC5X added to ir_raw_decode, no new
	// tool, registry unchanged.)
	// v0.569.0 added oam_decode (Ethernet OAM / CFM, 802.1ag / Y.1731,
	// EtherType 0x8902 — common header (MD level + all 24 opcode names) + CCM
	// body (RDI / period / seq / MEP ID / MEG ID); the L2 connectivity-fault /
	// service-topology recon leg of the LAN family. Verified vs scapy.
	// internal/oam).
	// v0.570.0 added portmap_decode (ONC RPC portmapper / rpcbind v2, port
	// 111 — RPC header + GETPORT call/reply + DUMP reply service list (the
	// rpcinfo -p enumeration: nfs/mountd/NIS/... program+version+port). The
	// Sun-RPC service-enumeration recon decoder. Verified vs scapy.
	// internal/portmap).
	// v0.571.0 added mount_decode (NFS MOUNT protocol v3, RPC program 100005
	// — MNT/UMNT call path + MOUNT reply (status / file handle / auth
	// flavors); the NFS export / file-handle / weak-auth recon companion to
	// portmap. Verified vs scapy. internal/mount).
	// v0.572.0 added nfs_decode (ONC RPC NFS v3, program 100003 — RPC header
	// + all 22 procedure names + call-side filename / file-handle / offset
	// extraction (LOOKUP/REMOVE/RENAME/READ/WRITE/...); completes the NFS
	// recon chain portmap->mount->nfs. Verified vs scapy. internal/nfs).
	// (v0.573.0 was the shared internal/oncrpc refactor — no new tool.)
	// v0.574.0 added nlm_decode (ONC RPC NFS Lock Manager v4, program 100021
	// / rpc.lockd — TEST/LOCK/CANCEL/UNLOCK lock args (caller / file handle /
	// owner / offset / length / exclusive) + reply nlm4_stats; fourth member
	// of the Sun-RPC suite on internal/oncrpc. Verified vs scapy. internal/nlm).
	// v0.575.0 added socks_decode (SOCKS4/4a/5 proxy, RFC 1928 — greeting /
	// method-select / request+reply with the proxied destination host:port
	// (ipv4/ipv6/domain) + SOCKS4 request/reply; the proxy/pivot/exfil
	// decoder. RFC-verified (scapy cross-check where correct). internal/socks).
	// v0.576.0 added etherip_decode (EtherIP / RFC 3378 L2-over-IP tunnel,
	// IP proto 97 — 2-byte header + inner Ethernet (MACs/EtherType) chaining
	// an inner IPv4/IPv6 to ipdecode; completes the tunnel-decap family
	// gre/geneve/vxlan/mpls/sflow. Verified vs scapy. internal/etherip).
	// v0.577.0 added aoe_decode (ATA over Ethernet, EtherType 0x88A2 — the
	// unauthenticated L2 raw-disk protocol: 10-byte header (shelf/slot/cmd/
	// tag) + ATA command (READ/WRITE/IDENTIFY + 48-bit LBA) / Query-Config;
	// storage attack-surface recon. Structural fields verified vs scapy.
	// internal/aoe).
	// v0.578.0 added hicp_decode (HMS Anybus Host IP Configuration Protocol,
	// UDP 3250 — text Key=value device discovery/reconfig: Module Scan /
	// Response (asset inventory + PSWD=OFF unauth-reconfig flag) / Configure;
	// the profinetdcp-analog OT device-discovery decoder. Verified vs scapy.
	// internal/hicp).
	// v0.579.0 added rtps_decode (RTPS / DDS wire protocol — ROS2 / autonomous
	// / industrial pub-sub: 20-byte header (vendor-id fingerprint + GUID
	// prefix) + submessage-kind walk (DATA/HEARTBEAT/INFO_DST/...); the DDS
	// member of the OT/ICS family. Header verified vs scapy. internal/rtps).
	// v0.580.0 added nsh_decode (Network Service Header / RFC 8300 SFC — base
	// header (MD type / next proto) + service-path SPI/SI + context, chaining
	// the inner IPv4/IPv6/Ethernet to ipdecode; joins the tunnel-decap family.
	// Header verified vs scapy. internal/nsh).
	// v0.581.0 added homeplugav_decode (HomePlug AV / IEEE 1901 powerline
	// management envelope, EtherType 0x88E1 — version + LE MMTYPE + name
	// (77-entry code-gen table) + sub-type/category; powerline (PLC) mgmt
	// recon (key exchange / sniffer / network info). Verified vs scapy.
	// internal/homeplugav).
	// v0.582.0 added homepluggp_decode (HomePlug Green PHY SLAC — the EV ↔ EVSE
	// CCS / ISO 15118 charging-pairing handshake on the Control Pilot: the
	// 0x60xx CCo SLAC MMEs (parm → start-atten → M-sound → atten-char → match →
	// set-key) with the session Run ID, EV/EVSE MACs+IDs and the NID + NMK key
	// material from the match/set-key messages; EV-charging-security recon
	// extending the powerline domain. Body layouts verified vs scapy + ISO
	// 15118-3. internal/homepluggp).
	// v0.583.0 added roce_decode (RoCE / InfiniBand Base Transport Header —
	// RDMA over Converged Ethernet, RoCEv2 over UDP 4791: the fixed 12-byte BTH
	// (opcode → RDMA READ/WRITE/ATOMIC/SEND/ACK/CNP + transport service RC/UC/
	// RD/UD, P_Key isolation domain, destination Queue Pair, FECN/BECN, PSN);
	// datacenter RDMA-fabric recon, a distinct domain. 12-byte layout + 57-entry
	// opcode table verified vs scapy (80-row differential, 0 mismatches).
	// internal/roce).
	// v0.584.0 added icmp_extension_decode (ICMP multipart extension, RFC 4884 +
	// MPLS Label Stack object, RFC 4950 — the extension routers append to Time
	// Exceeded / Unreachable messages: the MPLS labels (label/TC/S/TTL) a
	// dropped packet was traversing, leaking the label-switched path during a
	// traceroute through an MPLS core; RFC 5837 Interface Information surfaced
	// raw. Pairs with icmp_packet_decode + mpls_decode. Header + TLV + MPLS
	// object verified vs scapy + RFC 4950. internal/icmpext).
	// (v0.585.0 was an enhancement to the existing ndp_decode — SeND option
	// decode (RFC 3971 CGA/RSA-Sig/Timestamp/Nonce) + Type-13 Nonce→Timestamp
	// mislabel fix — not a new tool, so the count was unchanged.)
	// v0.586.0 added mld_decode (MLD — Multicast Listener Discovery, RFC 2710
	// MLDv1 + RFC 3810 MLDv2 — the IPv6 multicast-group membership protocol in
	// ICMPv6: Query / Report / Done + the MLDv2 group records (record type +
	// multicast address + source filters); names the groups a host joined
	// (mDNS ff02::fb, LLMNR ff02::1:3) — IPv6 multicast-service recon, the IPv6
	// companion to igmp/igmpv3. Verified vs scapy + RFC 2710/3810 (50-row
	// MLDv2-Report differential, 0 mismatches). internal/mld).
	// v0.587.0 added sampled_values_decode (IEC 61850-9-2 / 9-2LE Sampled Values
	// SV/SMV — the substation process-bus current/voltage sample multicast,
	// EtherType 0x88BA; the sampled-measurement sibling of goose_decode: an
	// ASN.1 BER savPdu (tag 0x60) → seqASDU (0xA2) → ASDUs (0x30) with svID,
	// smpCnt (the SV-injection/replay counter), confRev, smpSynch and the raw
	// sampled-value block. BER walk verified byte-by-byte vs the IEC 61850-9-2
	// ASN.1 / Wireshark sv dissector (no scapy model exists). internal/sv).
	// v0.588.0 added esmc_decode (ESMC — Ethernet Synchronization Messaging
	// Channel / SyncE, ITU-T G.8264; the Slow-Protocol frame EtherType 0x8809
	// subtype 0x0A that advertises the clock Quality Level (SSM): the 10-byte
	// header + QL / Enhanced-QL TLVs, event-vs-information type; the
	// frequency-sync companion to ptpv2_decode. SSM→QL is option-dependent
	// (G.781 Option I/II) so both names are surfaced. Verified vs scapy.contrib
	// .esmc. internal/esmc).
	// v0.589.0 added nfc_felica_decode (FeliCa / NFC-F / NFC Forum Type 3, JIS
	// X 6319-4 — the Sony contactless protocol behind East-Asian transit /
	// payment cards (Suica, Octopus, EZ-Link) + NDEF Type 3; the NFC-F member
	// of the NFC family: LEN + command/response code + IDm (+ manufacturer
	// code) + PMm (+ IC code) + polling System Code + read status/block data +
	// Request-System-Code list. Well-known system codes named, the rest raw.
	// Frame layout verified byte-by-byte vs the Sony FeliCa Card User's Manual /
	// JIS X 6319-4 (no scapy model exists). internal/felica).
	// (v0.590.0 was an enhancement to nfc_iso14443a_identify — full ATS
	// interface-byte decode (TA1 bit rate / TB1 FWI+SFGI / TC1 NAD+CID) to
	// parity with the Type-B decoder — not a new tool, so the count was
	// unchanged.)
	// v0.591.0 added nfc_tcl_decode (ISO 14443-4 T=CL block transmission
	// protocol — the half-duplex block layer carrying APDUs to a Type-4 card:
	// the PCB → I-block (APDU data + chaining) / R-block (ACK/NAK) / S-block
	// (WTX/DESELECT) + CID/NAD + INF; completes the NFC stack identify → ATS →
	// T=CL → APDU. PCB coding verified vs ISO 14443-4 §7.1 + Proxmark/libnfc
	// canonical values. internal/tcl).
	// v0.592.0 added xcp_decode (ASAM XCP Universal Measurement and Calibration
	// Protocol — the ECU calibration/measurement/flash bus: the PID → command
	// (CONNECT / GET_SEED / UNLOCK / UPLOAD / DOWNLOAD / PROGRAM / DAQ) master→
	// slave, or RES/ERR/EV/SERV/DAQ slave→master, with security-relevant
	// commands flagged; joins the uds/kwp/obd2 automotive family. Command /
	// error / event code tables code-genned from scapy.contrib.automotive.xcp.
	// internal/xcp).
	// v0.593.0 added doip_decode (DoIP — Diagnostics over IP, ISO 13400 — the
	// Ethernet/IP transport carrying vehicle diagnostics (UDS) in modern cars:
	// the 8-byte header + payload-type body — vehicle identification (leaks VIN/
	// EID/GID), routing activation (auth gate), alive-check / entity-status /
	// power-mode, and the diagnostic message (UDS payload surfaced raw for
	// uds_decode); joins the automotive family. Header + payload-type + sub-code
	// tables code-genned from scapy.contrib.automotive.doip. internal/doip).
	// v0.594.0 added ccp_decode (CCP — CAN Calibration Protocol, the CAN-native
	// XCP predecessor still in production ECUs: the 8-byte CAN payload — a CRO
	// command (CONNECT / GET_SEED / UNLOCK / UPLOAD / DNLOAD / PROGRAM, master→
	// slave, with CONNECT's LE station address + security flags) or a DTO
	// (CRM + return code / event / DAQ data, slave→master). Direction-dependent
	// like XCP. Command + return-code tables code-genned from
	// scapy.contrib.automotive.ccp. internal/ccp).
	// (v0.595.0 / v0.596.0 / v0.597.0 were chaining enhancements — DoIP→UDS,
	// ISO-TP→UDS, ERSPAN→IP — not new tools, so the count was unchanged.)
	// v0.598.0 added usb_descriptor_decode (USB descriptors — device / config /
	// interface / endpoint / HID / string of USB 2.0/3.x: VID:PID fingerprint,
	// device + per-interface class, endpoints; flags the HID-boot-keyboard
	// (BadUSB / rubber-ducky) and composite-device patterns. Deterministic
	// USB-spec layouts, byte-checkable; the device-fingerprinting companion to
	// the usbhid / badusb tooling. internal/usbdesc).
	// v0.599.0 added usb_hid_report_descriptor_decode (USB HID Report Descriptor,
	// USB HID 1.11 §6.2.2 — the item-based structure declaring what a HID device
	// IS: Main/Global/Local items, Usage Page + Usage (keyboard/mouse/…),
	// collections, report size/count, Input/Output/Feature data flags; the
	// definitive BadUSB tell (a declared Generic-Desktop/Keyboard usage). The
	// deepest layer of USB device identity, completing usb_descriptor + usbhid.
	// Verified vs the canonical boot-keyboard descriptor. internal/hidreport).
	// v0.600.0 added usb_pd_decode (USB Power Delivery — the USB-C CC-line power-
	// negotiation protocol: the 16-bit header (control/data dispatch by data-
	// object count, message type, roles, spec rev) + Source/Sink Capabilities
	// Power Data Objects (Fixed voltage/current+flags, Variable, Battery);
	// emerging hardware-attack surface (malicious chargers). Augmented PDO /
	// Request RDO / VDM surfaced raw. Verified vs the USB-PD spec. internal/usbpd).
	// v0.601.0 added spi_flash_decode (SPI NOR flash transactions — the command
	// set (RDID / READ / FAST_READ / PAGE_PROGRAM / erases / status / dual-quad
	// reads / SFDP / 4-byte mode) + the JEDEC RDID identification (single-byte
	// manufacturer — Winbond/Macronix/Micron/… — + typical 2^code capacity);
	// the chip-dump / firmware-extraction decoder, decoding what
	// buspirate_spi_dump captures. Command set + manufacturer codes verified vs
	// vendor datasheets. internal/spiflash).
	// v0.602.0 added pmbus_decode (PMBus — Power Management Bus over SMBus/I2C:
	// the command set (OPERATION / VOUT_COMMAND / VOUT_MARGIN / fault limits /
	// READ_* telemetry / STATUS_* / MFR_ID), with the voltage-setting writes
	// flagged (the PMFault overvolt vector), LINEAR11 telemetry values decoded
	// and STATUS bit-fields decoded; VOUT (ULINEAR16/VOUT_MODE) surfaced raw.
	// Pairs with i2c_scan. Command set + LINEAR11 verified vs the PMBus spec.
	// internal/pmbus).
	// v0.603.0 added bt_hci_decode (Bluetooth HCI / H4 — the host↔controller
	// transport in btsnoop/hcidump: the packet type + command opcode (OGF/OCF +
	// well-known name) / event code (incl. Command Complete/Status embedded
	// opcode + LE Meta sub-event) / ACL handle; the offline-decode companion to
	// the live bt_hci_info, beneath the BLE decoders. Opcode/event/sub-event
	// tables per the Bluetooth Core spec. internal/hci).
	// v0.604.0 added bt_l2cap_decode (Bluetooth L2CAP — the channel-mux layer
	// inside HCI ACL, bridging bt_hci_decode and the GATT tooling: the basic
	// header (length + CID) + a CID dispatch — signaling channel (codes), ATT
	// (GATT opcode), SMP (pairing code), dynamic. Per-operation params surfaced
	// raw. CID / signaling / ATT / SMP tables per the Bluetooth Core spec.
	// internal/l2cap).
	// v0.605.0 added bt_smp_decode (Bluetooth LE SMP / pairing — the L2CAP
	// CID-0x0006 Security Manager: the Pairing Request/Response IO capability +
	// AuthReq (bonding/MITM/Secure-Connections) + key size + key distribution,
	// with a derived security posture (Just Works vs authenticated, Legacy vs
	// SC), the Pairing Failed reason, the Identity Address, and key material raw;
	// completes the BT-stack chain hci→l2cap→smp. Per the BT Core spec Vol 3
	// Part H. internal/smp).
	// v0.606.0 added bt_att_decode (Bluetooth ATT / GATT — the L2CAP CID-0x0004
	// Attribute Protocol, the application layer of BLE: per-opcode field decode
	// — Error Response, Exchange MTU, Find Information, Read By (Group) Type
	// requests (start/end handle + 16/128-bit UUID), Read / Write (handle +
	// value), Notification/Indication; service-discovery responses + values
	// surfaced raw. Completes hci→l2cap→att, pairs with bluetooth_gatt_uuid_
	// lookup. Per the BT Core spec Vol 3 Part F. internal/att).
	// v0.607.0 added bt_adv_decode (Bluetooth advertising / scan-response — the
	// GAP AD-structure list, same format as BR/EDR EIR: the recon headline a
	// passive BLE scan surfaces first. Per-structure decode — Flags, 16/32/128-
	// bit service-UUID + solicitation lists, Local Name, Tx Power, Appearance,
	// LE Role, URI, Service Data (with Eddystone UID/URL/TLM for UUID 0xFEAA),
	// and Manufacturer Specific Data (company name + Apple iBeacon proximity
	// UUID/major/minor/power). Undocumented value-spaces surfaced raw + noted.
	// Advertising-layer complement to hci→l2cap→att. Per the Bluetooth Assigned
	// Numbers + iBeacon / Eddystone specs. internal/bleadv).
	// v0.608.0 added ioprox_decode (IO Prox / Kantech XSF 125 kHz LF access
	// credential — decodes the 64-bit block: facility code + version + 16-bit
	// card number + 8-bit checksum, with a structural marker/separator gate.
	// Closes the LF reader-cloning gap left by the HID/Indala/AWID PACS
	// coverage; complements em4100_decode / fdxb_decode. Layout + checksum
	// agree byte-for-byte between the Proxmark3 and Flipper Zero references.
	// internal/ioprox).
	// v0.609.0 added jablotron_decode (Jablotron 125 kHz LF access credential —
	// decodes the 64-bit block: 0xFFFF preamble + 40-bit card data + 8-bit
	// checksum (sum XOR 0x3A), with the BCD printed-number render and a
	// not-BCD flag. Continues the LF reader-cloning set (em4100 / fdxb /
	// ioprox / PACS). Layout + checksum + BCD render agree byte-for-byte
	// between the Proxmark3 and Flipper Zero references. internal/jablotron).
	// v0.610.0 added viking_decode (Viking 125 kHz LF access credential —
	// decodes the 64-bit block: 0xF20000 preamble + 32-bit card ID + 8-bit
	// XOR checksum (XOR of all bytes == 0xA8). Continues the LF reader-cloning
	// set (em4100 / fdxb / ioprox / jablotron / PACS). Layout + checksum agree
	// byte-for-byte between the Proxmark3 and Flipper Zero references.
	// internal/viking).
	// v0.611.0 added noralsy_decode (Noralsy 125 kHz LF access credential —
	// decodes the 96-bit block: 0xBB0214FF preamble + 28-bit packed card ID +
	// 8-bit BCD year + two 4-bit nibble-XOR checksums. Card-ID presentation
	// differs between references (Proxmark BCD-decimal vs Flipper hex) so both
	// surfaced. Continues the LF reader-cloning set. Layout + masks + checksums
	// agree byte-for-byte between the Proxmark3 and Flipper Zero references.
	// internal/noralsy).
	// v0.612.0 added presco_decode (Presco 125 kHz LF access credential —
	// decodes the 128-bit block: 0x10D00000 preamble + two zero words + 32-bit
	// full code; site/user codes derived. No checksum — integrity rests on the
	// 96-bit structural gate. Single-reference (Proxmark cmdlfpresco.c
	// encoder+decoder, internally inverse; Flipper mainline lacks Presco).
	// Continues the LF reader-cloning set. internal/presco).
	// v0.614.0 added ir_pronto_decode (Pronto HEX / CCF IR-code decoder — the
	// universal textual IR format used by remote DBs / Logitech Harmony / JP1:
	// converts the code to its carrier frequency + intro/repeat µs timings per
	// the documented 0.241246µs Pronto clock, and chains the intro timings into
	// the raw-IR protocol decoder to name the protocol. Raw formats only; a
	// predefined-code format word is reported, not mis-converted. Anchored on
	// 0x006D->38029Hz + the burst->µs math. internal/ir.DecodePronto).
	// (v0.613.0 added Kaseikyo to the existing ir_raw_decode tool — registry
	// unchanged there, an enhancement not a new tool.)
	// v0.615.0 added ir_pronto_encode (raw IR timings -> Pronto HEX, the inverse
	// of ir_pronto_decode; documented Pronto arithmetic inverted, round-trip-
	// verified with the decoder; the IR companion to em4100_encode / pacs_encode
	// / weather_synth). internal/ir.EncodePronto.
	// v0.616.0 added ioprox_encode (FC/version/card -> 64-bit IO Prox block, the
	// inverse of ioprox_decode; recomputes the checksum, round-trip-verified
	// with the decoder + reproduces the hand-traced vector; closes the ioProx
	// reader-cloning loop alongside em4100_encode / rfid_pacs_encode).
	// internal/ioprox.Encode.
	// v0.617.0 added jablotron_encode (card number -> 64-bit Jablotron block,
	// the inverse of jablotron_decode; BCD-encodes the card + sum-XOR-0x3A
	// checksum + 0xFFFF preamble, round-trip-verified with the decoder +
	// reproduces its vector; extends the LF clone set em4100/pacs/ioprox).
	// internal/jablotron.Encode.
	// v0.618.0 added viking_encode (32-bit card ID -> 64-bit Viking block, the
	// inverse of viking_decode; 0xF20000 preamble + XOR checksum (all bytes XOR
	// == 0xA8), round-trip-verified + reproduces its vector; extends the LF
	// clone set em4100/pacs/ioprox/jablotron). internal/viking.Encode.
	// v0.619.0 added noralsy_encode (card + year -> 96-bit Noralsy block, the
	// inverse of noralsy_decode; BCD-encodes the card non-contiguously + the
	// year + the two nibble checksums + 0xBB0214FF preamble, round-trip-verified
	// + reproduces its vector; completes the LF clone set em4100/pacs/ioprox/
	// jablotron/viking). internal/noralsy.Encode.
	// v0.620.0 added presco_encode (32-bit full code -> 128-bit Presco block,
	// the inverse of presco_decode; fixed 0x10D00000 preamble + two zero words +
	// full code, no checksum, round-trip-verified + reproduces its vector;
	// COMPLETES the LF clone-generation set em4100/pacs/ioprox/jablotron/viking/
	// noralsy/presco). internal/presco.Encode.
	// v0.621.0 added ir_raw_encode (protocol + address + command -> raw IR µs
	// timings, the inverse of ir_raw_decode; NEC / Samsung32 / Sony SIRC /
	// Philips RC5-RC5X, round-trip- and fuzz-verified against the decoder;
	// offline complement to the device-side ir_build, feeds ir_pronto_encode).
	// internal/ir.EncodeRaw.
	// v0.622.0 added Kaseikyo to ir_raw_encode (vendor+address+command -> 48-bit
	// timings, both parities computed; the encoder is now symmetric with the
	// decoder's Kaseikyo support) — registry unchanged, an enhancement not a new
	// tool.
	// v0.623.0 added t5577_config_encode (raw fields -> 32-bit T5577 config word,
	// the inverse of t5577_config_decode; round-trip-verified + reproduces the
	// EM4100/HID reference configs; completes the offline clone-prep chain —
	// the config word that sets a T5577 blank up for the right protocol before
	// writing the cloned data blocks). internal/t55xx.EncodeHex.
	// v0.624.0 added NEC-extended (16-bit address) + NEC-repeat to ir_raw_encode
	// so the encoder now covers the full NEC family the decoder handles —
	// registry unchanged, an enhancement not a new tool.
	// v0.625.0 added metakom_decode (Metakom 4-byte iButton key — per-byte
	// even-parity validity gate per the Flipper firmware; the non-Dallas iButton
	// width that ibutton_decode deferred). internal/metakom.
	// v0.626.0 added cyfral_decode (Cyfral on-wire iButton frame -> 16-bit key;
	// the strong nibble-pattern gate (start/stop 0b0001 + 8 data nibbles each in
	// {1110,1101,1011,0111}) per the Flipper firmware; the second non-Dallas
	// iButton format ibutton_decode deferred — completes the iButton family).
	// internal/cyfral.
	// v0.627.0 added the Gate TX protocol decoder to subghz_classify (24-bit
	// fixed-code OOK/PWM -> code + 20-bit serial + 4-bit button, per the Flipper
	// reference, round-trip-verified) — registry unchanged, a new protocol in
	// the existing classifier, not a new tool. internal/subghz/protocols.
	// v0.628.0 added the SMC5326 (PT2262-family) protocol decoder to
	// subghz_classify (25-bit fixed-code OOK/PWM -> code + 16-bit address per
	// the Flipper reference, round-trip-verified) — registry unchanged.
	// v0.629.0-v0.634.0 extended existing tools (MegaCode/Magellan/Mastercode/
	// GangQi protocols in subghz_classify; BCH(31,21,2) error correction in
	// subghz_pocsag_decode) — registry unchanged.
	// v0.635.0 added ksuid_decode (27-char base62 K-Sortable ID -> 32-bit
	// creation timestamp + 16-byte payload, per segmentio/ksuid, anchored to
	// its documented example; completes the identifier info-leak family
	// uuid/objectid/ulid/snowflake/ksuid). internal/ksuid.
	// v0.636.0 added otpauth_migration_decode (Google Authenticator export
	// payload otpauth-migration://offline?data=… -> the list of 2FA accounts
	// it carries, bulk-recovering every TOTP/HOTP secret; public-schema
	// protobuf parsed with protowire, anchored to the canonical example secret
	// JBSWY3DPEHPK3PXP; pairs with totp_generate). internal/otpmigration.
	// v0.637.0 added bip39_decode (BIP-39 wallet seed phrase -> entropy +
	// SHA-256 checksum validity + PBKDF2-HMAC-SHA512 seed; embedded official
	// 2048-word English list, anchored to the Trezor BIP-39 test vectors).
	// internal/bip39.
	// v0.638.0 added base58check_decode (WIF private key / legacy Bitcoin
	// address / BIP-32 extended key -> version + payload + double-SHA-256
	// checksum + type id; anchored to the canonical WIF + genesis-address
	// vectors; the Base58Check companion to bip39_decode). internal/base58check.
	// v0.639.0 added bech32_decode (Bech32/Bech32m SegWit address / Nostr /
	// Lightning string -> HRP + payload + BCH checksum variant + witness
	// version/program + address type; anchored to the BIP-173/350 vectors; the
	// Bech32 companion to base58check_decode). internal/bech32.
	// v0.640.0 added eth_keystore_decrypt (Ethereum V3 keystore JSON +
	// passphrase -> private key; scrypt/pbkdf2 + AES-128-CTR + Keccak-256 MAC
	// gate, anchored to the canonical Web3 Secret Storage PBKDF2 vector; the
	// ETH companion to bip39_decode / base58check_decode). internal/ethkeystore.
	// v0.641.0 added pgp_packet_decode (OpenPGP RFC 4880 packet stream of a PGP
	// key/message -> per-packet tag/length + key fingerprint/keyID/algo/creation
	// + user IDs + signature fields; native walker cross-checked against
	// x/crypto/openpgp as a test oracle). internal/pgppacket.
	// v0.642.0 extended pgp_packet_decode with signature subpacket parsing
	// (creation time, issuer key ID/fingerprint, key/sig expiry, key flags),
	// cross-checked against x/crypto/openpgp's packet.Signature — registry
	// unchanged, an enhancement not a new tool.
	// v0.643.0 added aws_key_decode (AWS access key ID -> embedded account ID +
	// credential type via base32 + mask + shift, offline; anchored to the
	// published ASIA…→account vectors). internal/awskey.
	// v0.644.0 added azure_sas_decode (Azure Storage SAS query string -> blast
	// radius: SAS type + context-aware permissions + window + scope + IP/proto;
	// anchored to the Microsoft SAS reference worked example). internal/azuresas.
	// v0.645.0 added github_token_decode (GitHub token prefix ID + CRC32-Base62
	// checksum validation for classic ghp_/gho_/ghu_/ghs_/ghr_ tokens, offline;
	// anchored to the canonical ghp_…0mLq17 vector). internal/githubtoken.
	// v0.646.0 added secret_identify (credential triage front end: routes a
	// captured string to the in-tree decoders aws/github/azure/bip39/jwt +
	// structural PEM detection + a documented vendor-prefix table; the
	// credential analogue of hash_identify). internal/secretid.
	// v0.647.0 added discord_token_decode (Discord user/bot token -> owning
	// account user ID + creation time via the in-tree snowflake decoder; the
	// dominant infostealer artifact; also wired into secret_identify).
	// internal/discordtoken.
	// v0.648.0 added roca_detect (CVE-2017-15361 weak-RSA-key detector: the
	// Infineon RSALib fingerprint test over 38 small-prime residues, flagging
	// factorable public keys from Yubikey 4/Neo, Infineon TPMs, Gemalto, and
	// Estonian/Slovak eID; accepts modulus/PEM/cert/ssh-rsa, offline; ported
	// verbatim from crocs-muni/roca detect.py and validated against its ten
	// fingerprint-positive test moduli). internal/roca.
	// v0.649.0 added ssh_pubkey_decode (OpenSSH public-key / authorized_keys /
	// known_hosts triage: SHA256+MD5 fingerprints exactly as ssh-keygen -l,
	// type/size, RSA modulus surfaced for roca_detect chaining, and a hashed
	// known_hosts |1|salt|hash entry tested against a candidate hostname via
	// HMAC-SHA1; native RFC 4253 wire parse, no x/crypto/ssh). internal/sshpub.
	// v0.650.0 added ja3_fingerprint (JA3 TLS-client fingerprint from a captured
	// ClientHello: the IDS/threat-intel string + MD5 digest, GREASE-stripped;
	// native ClientHello wire walk + crypto/md5, pinned to the salesforce pyja3
	// reference on a real openssl hello and a GREASE-bearing one). internal/ja3.
	const expected = 632
	if initialRegistrySize != expected {
		t.Errorf("registry names at init = %d, want %d (wave-by-wave checked in §D of runbook)",
			initialRegistrySize, expected)
	}
}
