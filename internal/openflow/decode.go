// Package openflow decodes OpenFlow control-channel messages
// per the Open Networking Foundation (ONF) specifications —
// version 1.0 (`of10`), 1.3 (`of13`; the dominant deployed
// version), and 1.5 (`of15`). OpenFlow is the **canonical
// Software-Defined Networking (SDN) control protocol** —
// running over TCP/6653 (or legacy TCP/6633) between an SDN
// controller (ONOS, OpenDaylight, Ryu, Floodlight, Faucet) and
// every OpenFlow-capable switch (Open vSwitch, Pica8 PicOS,
// Cisco Catalyst OpenFlow, Arista OpenFlow, hardware
// merchant-silicon switches built on Broadcom Trident / Tomahawk
// + Mellanox Spectrum).
//
// Operationally, OpenFlow is the wire format for every step of
// SDN-controlled traffic management:
//
//   - **Session bootstrap** — HELLO (version negotiation),
//     FEATURES_REQUEST/REPLY (controller learns the switch's
//     datapath ID + per-table capacities), ECHO_REQUEST/REPLY
//     (keep-alive / latency probe).
//   - **Flow programming** — FLOW_MOD (add/modify/delete rules
//     in the switch flow table), GROUP_MOD (multipath /
//     fast-failover groups), METER_MOD (rate-limiting), TABLE_MOD
//     (per-table miss behaviour).
//   - **Packet plumbing** — PACKET_IN (switch escalates an
//     unmatched packet to the controller for slow-path
//     processing), PACKET_OUT (controller injects a packet
//     back into the switch).
//   - **State sync** — MULTIPART_REQUEST/REPLY (stats: port
//     counters, flow counters, table descriptions, group
//     descriptions, meter descriptions), PORT_STATUS
//     (asynchronous link-up/down notification), FLOW_REMOVED
//     (flow-entry-expired notification).
//   - **HA + role control** — ROLE_REQUEST/REPLY (multi-
//     controller MASTER / SLAVE / EQUAL role negotiation),
//     BARRIER_REQUEST/REPLY (ordering primitive).
//   - **Bundles** (1.4+) — BUNDLE_CONTROL / BUNDLE_ADD_MESSAGE
//     (atomic batched flow programming).
//
// Wrap-vs-native judgement
//
//	Native. The ONF specs are publicly available. OpenFlow has
//	a uniform 8-byte common header (1-byte Version + 1-byte
//	Type + 2-byte Length + 4-byte XID) across all versions —
//	the Type registry is per-version but the header layout
//	itself is invariant. Per-type bodies vary across versions
//	but the bootstrap quartet (HELLO / ERROR / ECHO /
//	FEATURES_REPLY) shares enough common shape to surface as
//	dedicated typed fields. Heavier message types (FLOW_MOD,
//	MULTIPART_REQUEST/REPLY) carry version-specific structured
//	bodies surfaced as `body_hex` for downstream per-type
//	walkers. No crypto at the parse layer (OpenFlow over TLS
//	is a transport concern; handle the TLS strip first).
//
// What this package covers
//
//   - **Common header** (8 bytes, big-endian; identical across
//     all OpenFlow versions): byte 0 Version (0x01 = OF 1.0,
//     0x04 = OF 1.3, 0x06 = OF 1.5) + byte 1 Type + bytes 2-3
//     Length (uint16 BE; total bytes INCLUDING this 8-byte
//     header) + bytes 4-7 XID (uint32 BE; per-controller
//     transaction identifier, opaque to the switch).
//
//   - **3-entry Version name table**: 0x01 `OF_1.0` / 0x04
//     `OF_1.3` / 0x06 `OF_1.5`.
//
//   - **30+ entry Type name table** (per OF 1.3 ofp_type, which
//     is the most common deployed version): 0 `HELLO` / 1
//     `ERROR` / 2 `ECHO_REQUEST` / 3 `ECHO_REPLY` / 4
//     `EXPERIMENTER` / 5 `FEATURES_REQUEST` / 6 `FEATURES_REPLY`
//     / 7 `GET_CONFIG_REQUEST` / 8 `GET_CONFIG_REPLY` / 9
//     `SET_CONFIG` / 10 `PACKET_IN` / 11 `FLOW_REMOVED` / 12
//     `PORT_STATUS` / 13 `PACKET_OUT` / 14 `FLOW_MOD` / 15
//     `GROUP_MOD` / 16 `PORT_MOD` / 17 `TABLE_MOD` / 18
//     `MULTIPART_REQUEST` / 19 `MULTIPART_REPLY` / 20
//     `BARRIER_REQUEST` / 21 `BARRIER_REPLY` / 22
//     `QUEUE_GET_CONFIG_REQUEST` / 23 `QUEUE_GET_CONFIG_REPLY`
//     / 24 `ROLE_REQUEST` / 25 `ROLE_REPLY` / 26
//     `ASYNC_GET_REQUEST` / 27 `ASYNC_GET_REPLY` / 28
//     `ASYNC_SET` / 29 `METER_MOD` / 30 `ROLE_STATUS` / 31
//     `TABLE_STATUS` / 32 `REQUESTFORWARD` / 33
//     `BUNDLE_CONTROL` / 34 `BUNDLE_ADD_MESSAGE`.
//
//   - **HELLO body** (OF 1.3 §A.1): zero or more 4-byte HELLO
//     element TLVs. The standard element is `OFPHET_VERSIONBITMAP`
//     (type=1) carrying a uint32 bitmap of supported versions
//     (bit N = OF version N supported). The decoder surfaces
//     the version bitmap as `hello_versions_supported`.
//
//   - **ERROR body** (OF 1.3 §A.4, 4 bytes + optional data):
//     2-byte Type + 2-byte Code + optional `data` (usually
//     contains at least the first 64 bytes of the offending
//     message). 14-entry error-type name table.
//
//   - **FEATURES_REPLY body** (OF 1.3 §A.3.2, 32 bytes): 8-byte
//     `datapath_id` (the switch's unique identifier, typically
//     low 6 bytes = MAC, high 2 bytes = implementor-defined) +
//     4-byte `n_buffers` (max packets-in-flight the switch can
//     buffer) + 1-byte `n_tables` (number of flow tables) +
//     1-byte `auxiliary_id` (0 = main channel, non-zero =
//     auxiliary connection per RFC 6633 §6.3.7) + 2-byte pad +
//     4-byte `capabilities` bitmap + 4-byte `reserved`. The
//     decoder unpacks the documented `capabilities` flags
//     (FLOW_STATS / TABLE_STATS / PORT_STATS / GROUP_STATS /
//     IP_REASM / QUEUE_STATS / PORT_BLOCKED).
//
//   - **ECHO body** — opaque payload (controllers + switches
//     may use it for latency measurement or proprietary keep-
//     alive data); surfaced as `payload_hex`.
//
//   - All other message types — body surfaced as `body_hex`
//     for downstream per-type walkers.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed OpenFlow bytes after the TCP-
//     segment header strip (default TCP port 6653 modern, 6633
//     legacy; OpenFlow-over-TLS wraps the same bytes in TLS
//     records — handle the TLS strip first).
//   - **Per-type structured body decoders** beyond the
//     bootstrap quartet — FLOW_MOD instruction lists, GROUP_MOD
//     buckets, MULTIPART_REQUEST sub-types (flow stats / port
//     stats / table desc / group desc / meter desc) + their
//     replies, PORT_STATUS port descriptions, METER_MOD bands
//     — surfaced as `body_hex` for per-message-type follow-on
//     decoders.
//   - **OXM (OpenFlow Extensible Match) TLV walker** — match
//     conditions inside FLOW_MOD / PACKET_IN are encoded as
//     OXM TLVs (class + field + length + value); decoding the
//     ~40 OXM field types is out of scope.
//   - **Action / Instruction decoder** — OF 1.3 instructions
//     (GOTO_TABLE / WRITE_METADATA / WRITE_ACTIONS /
//     APPLY_ACTIONS / CLEAR_ACTIONS / METER / EXPERIMENTER)
//     and the 18-entry action type registry are out of scope.
//   - **Per-version delta** — OF 1.0 + 1.4 + 1.5 differ from
//     1.3 in match / instruction / port-stats shapes; this
//     decoder surfaces the version byte but does not branch
//     per-version body decoders.
//   - **TLS transport** — out of scope; feed bytes after TLS
//     decryption.
package openflow

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an OpenFlow message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Common header
	Version     int    `json:"version"`
	VersionName string `json:"version_name"`
	Type        int    `json:"type"`
	TypeName    string `json:"type_name"`
	Length      int    `json:"length"`
	XID         uint32 `json:"xid"`

	// Per-type fields (only the relevant subset populated).
	HelloVersionsSupported []int  `json:"hello_versions_supported,omitempty"`
	ErrorType              int    `json:"error_type,omitempty"`
	ErrorTypeName          string `json:"error_type_name,omitempty"`
	ErrorCode              int    `json:"error_code,omitempty"`
	ErrorDataHex           string `json:"error_data_hex,omitempty"`

	DatapathIDHex      string   `json:"datapath_id_hex,omitempty"`
	NBuffers           uint32   `json:"n_buffers,omitempty"`
	NTables            int      `json:"n_tables,omitempty"`
	AuxiliaryID        int      `json:"auxiliary_id,omitempty"`
	CapabilitiesHex    string   `json:"capabilities_hex,omitempty"`
	CapabilitiesActive []string `json:"capabilities_active,omitempty"`

	PayloadHex string `json:"payload_hex,omitempty"`
	BodyHex    string `json:"body_hex,omitempty"`
}

// Decode parses an OpenFlow message from a hex string starting
// at the Version byte. Separators (':' '-' '_' whitespace)
// tolerated; '0x' prefix tolerated.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("OpenFlow message truncated (%d bytes; need ≥8 for header)",
			len(b))
	}

	r := &Result{
		TotalBytes: len(b),
		Version:    int(b[0]),
		Type:       int(b[1]),
		Length:     int(binary.BigEndian.Uint16(b[2:4])),
		XID:        binary.BigEndian.Uint32(b[4:8]),
	}
	r.VersionName = versionName(r.Version)
	r.TypeName = typeName(r.Type)

	body := b[8:]
	switch r.Type {
	case 0: // HELLO
		decodeHello(r, body)
	case 1: // ERROR
		decodeError(r, body)
	case 2, 3: // ECHO_REQUEST / ECHO_REPLY
		if len(body) > 0 {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(body))
		}
	case 6: // FEATURES_REPLY
		decodeFeaturesReply(r, body)
	default:
		if len(body) > 0 {
			r.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
	}
	return r, nil
}

func decodeHello(r *Result, body []byte) {
	// HELLO body is zero or more 4-byte element TLVs:
	// 2-byte Type + 2-byte Length + Length-4 bytes of value.
	off := 0
	for off+4 <= len(body) {
		etype := binary.BigEndian.Uint16(body[off : off+2])
		elen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		if elen < 4 || off+elen > len(body) {
			break
		}
		if etype == 1 && elen >= 8 {
			// OFPHET_VERSIONBITMAP — uint32 bitmap.
			bm := binary.BigEndian.Uint32(body[off+4 : off+8])
			for i := 0; i < 32; i++ {
				if bm&(1<<i) != 0 {
					r.HelloVersionsSupported = append(r.HelloVersionsSupported, i)
				}
			}
		}
		// Pad to next 8-byte boundary.
		next := off + elen
		if next%8 != 0 {
			next += 8 - (next % 8)
		}
		off = next
	}
}

func decodeError(r *Result, body []byte) {
	if len(body) < 4 {
		return
	}
	r.ErrorType = int(binary.BigEndian.Uint16(body[0:2]))
	r.ErrorCode = int(binary.BigEndian.Uint16(body[2:4]))
	r.ErrorTypeName = errorTypeName(r.ErrorType)
	if len(body) > 4 {
		r.ErrorDataHex = strings.ToUpper(hex.EncodeToString(body[4:]))
	}
}

func decodeFeaturesReply(r *Result, body []byte) {
	if len(body) < 24 {
		return
	}
	r.DatapathIDHex = strings.ToUpper(hex.EncodeToString(body[0:8]))
	r.NBuffers = binary.BigEndian.Uint32(body[8:12])
	r.NTables = int(body[12])
	r.AuxiliaryID = int(body[13])
	// body[14:16] pad
	caps := binary.BigEndian.Uint32(body[16:20])
	r.CapabilitiesHex = fmt.Sprintf("0x%08X", caps)
	r.CapabilitiesActive = decodeCapabilities(caps)
}

// decodeCapabilities walks the OF 1.3 ofp_capabilities bitmap.
func decodeCapabilities(c uint32) []string {
	var names []string
	if c&0x01 != 0 {
		names = append(names, "FLOW_STATS")
	}
	if c&0x02 != 0 {
		names = append(names, "TABLE_STATS")
	}
	if c&0x04 != 0 {
		names = append(names, "PORT_STATS")
	}
	if c&0x08 != 0 {
		names = append(names, "GROUP_STATS")
	}
	if c&0x20 != 0 {
		names = append(names, "IP_REASM")
	}
	if c&0x40 != 0 {
		names = append(names, "QUEUE_STATS")
	}
	if c&0x100 != 0 {
		names = append(names, "PORT_BLOCKED")
	}
	return names
}

func versionName(v int) string {
	switch v {
	case 0x01:
		return "OF_1.0"
	case 0x02:
		return "OF_1.1"
	case 0x03:
		return "OF_1.2"
	case 0x04:
		return "OF_1.3"
	case 0x05:
		return "OF_1.4"
	case 0x06:
		return "OF_1.5"
	}
	return fmt.Sprintf("uncatalogued OF version 0x%02X", v)
}

func typeName(t int) string {
	switch t {
	case 0:
		return "HELLO"
	case 1:
		return "ERROR"
	case 2:
		return "ECHO_REQUEST"
	case 3:
		return "ECHO_REPLY"
	case 4:
		return "EXPERIMENTER"
	case 5:
		return "FEATURES_REQUEST"
	case 6:
		return "FEATURES_REPLY"
	case 7:
		return "GET_CONFIG_REQUEST"
	case 8:
		return "GET_CONFIG_REPLY"
	case 9:
		return "SET_CONFIG"
	case 10:
		return "PACKET_IN"
	case 11:
		return "FLOW_REMOVED"
	case 12:
		return "PORT_STATUS"
	case 13:
		return "PACKET_OUT"
	case 14:
		return "FLOW_MOD"
	case 15:
		return "GROUP_MOD"
	case 16:
		return "PORT_MOD"
	case 17:
		return "TABLE_MOD"
	case 18:
		return "MULTIPART_REQUEST"
	case 19:
		return "MULTIPART_REPLY"
	case 20:
		return "BARRIER_REQUEST"
	case 21:
		return "BARRIER_REPLY"
	case 22:
		return "QUEUE_GET_CONFIG_REQUEST"
	case 23:
		return "QUEUE_GET_CONFIG_REPLY"
	case 24:
		return "ROLE_REQUEST"
	case 25:
		return "ROLE_REPLY"
	case 26:
		return "ASYNC_GET_REQUEST"
	case 27:
		return "ASYNC_GET_REPLY"
	case 28:
		return "ASYNC_SET"
	case 29:
		return "METER_MOD"
	case 30:
		return "ROLE_STATUS"
	case 31:
		return "TABLE_STATUS"
	case 32:
		return "REQUESTFORWARD"
	case 33:
		return "BUNDLE_CONTROL"
	case 34:
		return "BUNDLE_ADD_MESSAGE"
	}
	return fmt.Sprintf("uncatalogued type %d", t)
}

// errorTypeName decodes the 14-entry OF 1.3 ofp_error_type
// registry.
func errorTypeName(t int) string {
	switch t {
	case 0:
		return "HELLO_FAILED"
	case 1:
		return "BAD_REQUEST"
	case 2:
		return "BAD_ACTION"
	case 3:
		return "BAD_INSTRUCTION"
	case 4:
		return "BAD_MATCH"
	case 5:
		return "FLOW_MOD_FAILED"
	case 6:
		return "GROUP_MOD_FAILED"
	case 7:
		return "PORT_MOD_FAILED"
	case 8:
		return "TABLE_MOD_FAILED"
	case 9:
		return "QUEUE_OP_FAILED"
	case 10:
		return "SWITCH_CONFIG_FAILED"
	case 11:
		return "ROLE_REQUEST_FAILED"
	case 12:
		return "METER_MOD_FAILED"
	case 13:
		return "TABLE_FEATURES_FAILED"
	case 0xFFFF:
		return "EXPERIMENTER"
	}
	return fmt.Sprintf("uncatalogued error type %d", t)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
