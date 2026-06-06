// SPDX-License-Identifier: AGPL-3.0-or-later

// Package homeplugav decodes the management-message envelope of HomePlug AV
// / IEEE 1901 powerline networking (the MAC Management Entry, EtherType
// 0x88E1) — the control plane of powerline (PLC) adapters. Powerline is a
// real, often-overlooked attack surface: the medium is shared across a
// building's wiring, and the management messages drive network membership,
// key exchange and diagnostics. A captured HomePlug AV management frame
// identifies the **management operation** in flight — a **Set Encryption
// Key** (the network membership key exchange), a **Sniffer** enable, a
// **Network Information** query (station / network enumeration), a **Read
// MAC Memory** firmware dump, a device reset — which is the recon headline
// for powerline reconnaissance. It is a distinct domain alongside the
// project's RF / wireless decoders.
//
// # Wrap-vs-native judgement
//
//	Native. The HomePlug AV management envelope is a 1-byte MM version + a
//	2-byte little-endian MMTYPE, then the message body. A byte-field read +
//	an MMTYPE lookup; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The version + MMTYPE were verified field-for-field against scapy's
//	HomePlugAV layer (scapy.contrib.homeplugav), and the 77-entry MMTYPE
//	name table is code-generated from scapy's authoritative map (not
//	hand-transcribed). The message body is surfaced as raw hex: the bodies
//	are many, version-specific (the v1.1 fragmentation header) and largely
//	vendor-specific (Qualcomm/Intellon), so only the envelope (version,
//	MMTYPE name, the request/confirm/indication sub-type from the two LSBs,
//	and the MMTYPE category range) is decoded — the operation type, which
//	is the recon value, with everything after surfaced raw.
package homeplugav

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a HomePlug AV management envelope.
type Result struct {
	Version     int      `json:"version"`
	VersionName string   `json:"version_name"`
	MMType      int      `json:"mmtype"`
	MMTypeHex   string   `json:"mmtype_hex"`
	MMTypeName  string   `json:"mmtype_name"`
	SubType     string   `json:"sub_type"`
	Category    string   `json:"category"`
	BodyHex     string   `json:"body_hex,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

// Decode parses a HomePlug AV management envelope (the EtherType-0x88E1
// payload) from hex (whitespace / ':' / '-' / '_' separators and a '0x'
// prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 3 {
		return nil, fmt.Errorf("homeplugav: %d bytes — too short for the version + MMTYPE header", len(b))
	}
	if versionName(b[0]) == "" {
		return nil, fmt.Errorf("homeplugav: MM version %d is not 0 (1.0) or 1 (1.1)", b[0])
	}
	mm := binary.LittleEndian.Uint16(b[1:3])
	r := &Result{
		Version:     int(b[0]),
		VersionName: versionName(b[0]),
		MMType:      int(mm),
		MMTypeHex:   fmt.Sprintf("0x%04X", mm),
		MMTypeName:  mmTypeName(mm),
		SubType:     subType(mm),
		Category:    category(mm),
	}
	if len(b) > 3 {
		r.BodyHex = strings.ToUpper(hex.EncodeToString(b[3:]))
	}
	r.Notes = append(r.Notes, "HomePlug AV / IEEE 1901 powerline management message — the MMTYPE names the operation (key exchange, sniffer, network info, MAC-memory read, reset); the body is surfaced raw (vendor- and version-specific)")
	if mm == 0xA050 || mm == 0xA051 {
		r.Notes = append(r.Notes, "Set Encryption Key exchange: this carries / negotiates the powerline Network Membership Key (NMK) — the powerline network credential")
	}
	if mm >= 0xA034 && mm <= 0xA036 {
		r.Notes = append(r.Notes, "Sniffer MME: powerline frame sniffing is being configured / reported")
	}
	return r, nil
}

func versionName(v byte) string {
	switch v {
	case 0:
		return "1.0"
	case 1:
		return "1.1"
	}
	return ""
}

// subType is the message sub-type carried in the two LSBs of the MMTYPE.
func subType(mm uint16) string {
	switch mm & 0x3 {
	case 0:
		return "Request"
	case 1:
		return "Confirmation"
	case 2:
		return "Indication"
	case 3:
		return "Response"
	}
	return ""
}

// category is the HomePlug AV / IEEE 1901 MMTYPE category by range.
func category(mm uint16) string {
	switch {
	case mm <= 0x1FFF:
		return "STA-to-STA"
	case mm <= 0x3FFF:
		return "STA-to-CCo"
	case mm <= 0x5FFF:
		return "Proxy"
	case mm <= 0x7FFF:
		return "CCo-to-CCo"
	case mm <= 0x9FFF:
		return "reserved"
	case mm <= 0xBFFF:
		return "Manufacturer-Specific (vendor) MME"
	}
	return "Vendor-Specific MME"
}

// mmTypeName maps the MMTYPE to its name (code-generated from scapy's
// authoritative scapy.contrib.homeplugav HPtype table).
func mmTypeName(mm uint16) string {
	mmtypes := map[uint16]string{
		0xA000: "Get Device/sw version Request",
		0xA001: "Get Device/sw version Confirmation",
		0xA004: "VS_WR_MEM",
		0xA008: "Read MAC Memory Request",
		0xA009: "Read MAC Memory Confirmation",
		0xA00C: "Start MAC Request",
		0xA00D: "Start MAC Confirmation",
		0xA010: "Get NVM Parameters Request",
		0xA011: "Get NVM Parameters Confirmation",
		0xA014: "VS_RSVD_1",
		0xA018: "VS_RSVD_2",
		0xA01C: "Reset Device Request",
		0xA01D: "Reset Device Confirmation",
		0xA020: "Write Module Data Request",
		0xA024: "Read Module Data Request",
		0xA025: "Read Module Data Confirmation",
		0xA028: "Write Module Data to NVM Request",
		0xA029: "Write Module Data to NVM Confirmation",
		0xA02C: "VS_WD_RPT",
		0xA030: "VS_LNK_STATS",
		0xA034: "Sniffer Request",
		0xA035: "Sniffer Confirmation",
		0xA036: "Sniffer Indicates",
		0xA038: "Network Information Request",
		0xA039: "Network Information Confirmation",
		0xA03C: "VS_RSVD_3",
		0xA040: "VS_CP_RPT",
		0xA044: "VS_ARPC",
		0xA048: "Loopback Request",
		0xA049: "Loopback Request Confirmation",
		0xA050: "Set Encryption Key Request",
		0xA051: "Set Encryption Key Request Confirmation",
		0xA054: "VS_MFG_STRING",
		0xA058: "Read Configuration Block Request",
		0xA059: "Read Configuration Block Confirmation",
		0xA05C: "VS_SET_SDRAM",
		0xA060: "VS_HOST_ACTION",
		0xA062: "Embedded Host Action Required Indication",
		0xA068: "VS_OP_ATTRIBUTES",
		0xA06C: "VS_ENET_SETTINGS",
		0xA070: "VS_TONE_MAP_CHAR",
		0xA074: "VS_NW_INFO_STATS",
		0xA078: "VS_SLAVE_MEM",
		0xA07C: "VS_FAC_DEFAULTS",
		0xA07D: "VS_FAC_DEFAULTS_CONFIRM",
		0xA084: "VS_MULTICAST_INFO",
		0xA088: "VS_CLASSIFICATION",
		0xA090: "VS_RX_TONE_MAP_CHAR",
		0xA094: "VS_SET_LED_BEHAVIOR",
		0xA098: "VS_WRITE_AND_EXECUTE_APPLET",
		0xA09C: "VS_MDIO_COMMAND",
		0xA0A0: "VS_SLAVE_REG",
		0xA0A4: "VS_BANDWIDTH_LIMITING",
		0xA0A8: "VS_SNID_OPERATION",
		0xA0AC: "VS_NN_MITIGATE",
		0xA0B0: "VS_MODULE_OPERATION",
		0xA0B4: "VS_DIAG_NETWORK_PROBE",
		0xA0B8: "VS_PL_LINK_STATUS",
		0xA0BC: "VS_GPIO_STATE_CHANGE",
		0xA0C0: "VS_CONN_ADD",
		0xA0C4: "VS_CONN_MOD",
		0xA0C8: "VS_CONN_REL",
		0xA0CC: "VS_CONN_INFO",
		0xA0D0: "VS_MULTIPORT_LNK_STA",
		0xA0DC: "VS_EM_ID_TABLE",
		0xA0E0: "VS_STANDBY",
		0xA0E4: "VS_SLEEPSCHEDULE",
		0xA0E8: "VS_SLEEPSCHEDULE_NOTIFICATION",
		0xA0F0: "VS_MICROCONTROLLER_DIAG",
		0xA0F8: "VS_GET_PROPERTY",
		0xA100: "VS_SET_PROPERTY",
		0xA104: "VS_PHYSWITCH_MDIO",
		0xA10C: "VS_SELFTEST_ONETIME_CONFIG",
		0xA110: "VS_SELFTEST_RESULTS",
		0xA114: "VS_MDU_TRAFFIC_STATS",
		0xA118: "VS_FORWARD_CONFIG",
		0xA200: "VS_HYBRID_INFO",
	}
	if n, ok := mmtypes[mm]; ok {
		return n
	}
	return fmt.Sprintf("0x%04X", mm)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("homeplugav: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("homeplugav: input is not valid hex: %w", err)
	}
	return b, nil
}
