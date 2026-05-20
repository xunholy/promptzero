// openflow.go — host-side OpenFlow control-channel decoder
// Spec. Wraps the internal/openflow walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/openflow"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(openflowDecodeSpec)
}

var openflowDecodeSpec = Spec{
	Name: "openflow_decode",
	Description: "Decode an OpenFlow control-channel message per the Open Networking " +
		"Foundation (ONF) specifications — versions 1.0 / 1.3 (the dominant " +
		"deployed version) / 1.5. OpenFlow is the canonical Software-Defined " +
		"Networking (SDN) control protocol running over TCP/6653 (modern) or " +
		"TCP/6633 (legacy) between an SDN controller (ONOS, OpenDaylight, Ryu, " +
		"Floodlight, Faucet) and every OpenFlow-capable switch (Open vSwitch, " +
		"Pica8 PicOS, Cisco Catalyst OpenFlow, Arista OpenFlow, hardware " +
		"merchant-silicon switches built on Broadcom Trident / Tomahawk + " +
		"Mellanox Spectrum). Operationally the wire format for every step of " +
		"SDN-controlled traffic management: session bootstrap (HELLO version " +
		"negotiation / FEATURES_REQUEST/REPLY / ECHO_REQUEST/REPLY keep-alive); " +
		"flow programming (FLOW_MOD add/modify/delete rules / GROUP_MOD multipath " +
		"/ METER_MOD rate-limiting / TABLE_MOD); packet plumbing (PACKET_IN slow-" +
		"path escalation / PACKET_OUT controller-side injection); state sync " +
		"(MULTIPART_REQUEST/REPLY for stats / PORT_STATUS asynchronous link-up/" +
		"down / FLOW_REMOVED expiry notification); HA + role control " +
		"(ROLE_REQUEST/REPLY MASTER/SLAVE/EQUAL negotiation / BARRIER_REQUEST/" +
		"REPLY ordering); bundles (BUNDLE_CONTROL / BUNDLE_ADD_MESSAGE atomic " +
		"batched programming). Decodes:\n\n" +
		"- **Common header** (8 bytes, big-endian; identical across all " +
		"OpenFlow versions): Version (0x01 = OF 1.0, 0x04 = OF 1.3, 0x06 = OF " +
		"1.5) + Type + Length (uint16 BE; total bytes INCLUDING this 8-byte " +
		"header) + XID (uint32 BE; per-controller transaction identifier).\n" +
		"- **6-entry Version name table**: 0x01 OF_1.0 / 0x02 OF_1.1 / 0x03 " +
		"OF_1.2 / 0x04 OF_1.3 / 0x05 OF_1.4 / 0x06 OF_1.5.\n" +
		"- **35-entry Type name table** (per OF 1.3 ofp_type): HELLO / ERROR / " +
		"ECHO_REQUEST/REPLY / EXPERIMENTER / FEATURES_REQUEST/REPLY / " +
		"GET_CONFIG_REQUEST/REPLY / SET_CONFIG / PACKET_IN / FLOW_REMOVED / " +
		"PORT_STATUS / PACKET_OUT / FLOW_MOD / GROUP_MOD / PORT_MOD / TABLE_MOD " +
		"/ MULTIPART_REQUEST/REPLY / BARRIER_REQUEST/REPLY / " +
		"QUEUE_GET_CONFIG_REQUEST/REPLY / ROLE_REQUEST/REPLY / " +
		"ASYNC_GET_REQUEST/REPLY / ASYNC_SET / METER_MOD / ROLE_STATUS / " +
		"TABLE_STATUS / REQUESTFORWARD / BUNDLE_CONTROL / BUNDLE_ADD_MESSAGE.\n" +
		"- **HELLO body** (OF 1.3 §A.1): walks zero or more 4-byte HELLO " +
		"element TLVs; OFPHET_VERSIONBITMAP (type=1) is decoded into the " +
		"hello_versions_supported list (bit N = OF version N supported).\n" +
		"- **ERROR body** (OF 1.3 §A.4): 2-byte Type + 2-byte Code + optional " +
		"data (usually the first 64 bytes of the offending message). 14-entry " +
		"error-type name table (HELLO_FAILED / BAD_REQUEST / BAD_ACTION / " +
		"BAD_INSTRUCTION / BAD_MATCH / FLOW_MOD_FAILED / GROUP_MOD_FAILED / " +
		"PORT_MOD_FAILED / TABLE_MOD_FAILED / QUEUE_OP_FAILED / " +
		"SWITCH_CONFIG_FAILED / ROLE_REQUEST_FAILED / METER_MOD_FAILED / " +
		"TABLE_FEATURES_FAILED + EXPERIMENTER).\n" +
		"- **FEATURES_REPLY body** (OF 1.3 §A.3.2): 8-byte datapath_id (the " +
		"switch's unique identifier — typically low 6 bytes = MAC, high 2 = " +
		"implementor-defined) + n_buffers (max in-flight packets the switch " +
		"can buffer) + n_tables (number of flow tables) + auxiliary_id (0 = " +
		"main channel, non-zero = auxiliary connection per RFC 6633 §6.3.7) + " +
		"capabilities bitmap with 7-entry decoded set (FLOW_STATS / " +
		"TABLE_STATS / PORT_STATS / GROUP_STATS / IP_REASM / QUEUE_STATS / " +
		"PORT_BLOCKED).\n" +
		"- **ECHO body** — opaque payload (controllers + switches may use it " +
		"for latency measurement or proprietary keep-alive data); surfaced as " +
		"payload_hex.\n" +
		"- All other message types — body surfaced as body_hex for downstream " +
		"per-type walkers.\n\n" +
		"Pure offline parser — operators paste OpenFlow bytes (starting at " +
		"the Version byte) from a `tcpdump -X port 6653` line or a Wireshark " +
		"OpenFlow dissector view and get the documented header + per-type body " +
		"breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the TCP-" +
		"segment header strip; default TCP port 6653 modern / 6633 legacy; " +
		"OpenFlow-over-TLS wraps the same bytes in TLS records — handle the " +
		"TLS strip first); per-type structured body decoders beyond the " +
		"bootstrap quartet (FLOW_MOD instruction lists / GROUP_MOD buckets / " +
		"MULTIPART_REQUEST sub-types for flow stats / port stats / table desc " +
		"/ group desc / meter desc + their replies / PORT_STATUS port " +
		"descriptions / METER_MOD bands — surfaced as body_hex for per-message-" +
		"type follow-on decoders); OXM (OpenFlow Extensible Match) TLV walker " +
		"(match conditions inside FLOW_MOD / PACKET_IN are encoded as OXM TLVs " +
		"— ~40 OXM field types — out of scope); action / instruction decoder " +
		"(OF 1.3 instructions GOTO_TABLE / WRITE_METADATA / WRITE_ACTIONS / " +
		"APPLY_ACTIONS / CLEAR_ACTIONS / METER / EXPERIMENTER and the 18-entry " +
		"action type registry are out of scope); per-version delta (OF 1.0 + " +
		"1.4 + 1.5 differ from 1.3 in match / instruction / port-stats shapes " +
		"— surfaces version byte but does not branch per-version body " +
		"decoders); TLS transport.\n\n" +
		"Source: docs/catalog/gap-analysis.md (SDN control-plane dissector — " +
		"common in DEF CON Wireless / Network Village CTFs + datacenter SDN " +
		"research + OpenFlow-controller fuzzing engagements; complements the " +
		"L2/L3 protocol family already covered). Wrap-vs-native: native — the " +
		"ONF specs are publicly available; OpenFlow has a uniform 8-byte " +
		"common header across all versions; per-type body shapes for the " +
		"bootstrap quartet (HELLO / ERROR / ECHO / FEATURES_REPLY) are well-" +
		"documented; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"OpenFlow message bytes starting at the Version byte (after the TCP-segment header strip; default TCP port 6653 modern / 6633 legacy; OpenFlow-over-TLS wraps the same bytes in TLS records — handle TLS strip first). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   openflowDecodeHandler,
}

func openflowDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("openflow_decode: 'hex' is required")
	}
	res, err := openflow.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("openflow_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
