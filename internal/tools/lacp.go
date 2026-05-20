// lacp.go — host-side LACP PDU decoder Spec.
// Wraps the internal/lacp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/lacp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(lacpDecodeSpec)
}

var lacpDecodeSpec = Spec{
	Name: "lacp_decode",
	Description: "Decode a Link Aggregation Control Protocol (LACP) PDU per IEEE " +
		"802.1AX-2020 (formerly 802.3ad). LACP is the universal link-aggregation " +
		"control plane: every multi-NIC server with a bonded interface and every " +
		"datacenter / enterprise switch with a LAG (Link Aggregation Group) speaks " +
		"it to coordinate which physical links join an aggregate. Closes a key L2 " +
		"visibility gap alongside the existing `lldp_decode` + `cdp_decode` + " +
		"`stp_bpdu_decode` L2 control-plane coverage. Decodes:\n\n" +
		"- **Subtype byte** — the leading byte after the Slow Protocols EtherType " +
		"(0x8809). Value 0x01 = LACP, 0x02 = Marker (rare; surfaced as a Note). A " +
		"non-1/2 subtype is rejected.\n" +
		"- **1-byte Version Number** — typically 1; v2 reserved by IEEE 802.1AX-" +
		"2014 but not yet widely deployed (surfaced verbatim).\n" +
		"- **TLV walker** — repeated (Type uint8, Length uint8, Value) records. " +
		"**4-entry TLV type table**: 0 Terminator (Length 0; signals end of TLV " +
		"chain), 1 Actor Information (Length 20), 2 Partner Information (Length " +
		"20), 3 Collector Information (Length 16).\n" +
		"- **Actor / Partner Information** (Type 1/2, body 18 bytes after the 2-" +
		"byte TLV header):\n" +
		"  - bytes 0-1: System Priority (uint16 BE — lower wins the Aggregator " +
		"Master role).\n" +
		"  - bytes 2-7: System ID (6-byte MAC — the system's canonical MAC).\n" +
		"  - bytes 8-9: Key (uint16 BE — operationally the LAG identifier; ports " +
		"with the same Key on the same System ID can be bundled together).\n" +
		"  - bytes 10-11: Port Priority (uint16 BE — tie-breaker for which member " +
		"port is the Aggregator).\n" +
		"  - bytes 12-13: Port ID (uint16 BE — per-port identifier unique within " +
		"a System).\n" +
		"  - byte 14: **State** — 8-bit bitfield with **8 named flags** (LSB " +
		"first per 802.1AX §6.4.2.3): LACP_Activity (1 Active / 0 Passive), " +
		"LACP_Timeout (1 Short=1s / 0 Long=30s), Aggregation (1 Aggregatable / 0 " +
		"Individual), Synchronization (1 In Sync), Collecting (RX path active), " +
		"Distributing (TX path active), Defaulted (using admin defaults rather " +
		"than received LACPDU info), Expired (current_while timer expired — " +
		"partner info stale).\n" +
		"  - bytes 15-17: Reserved.\n" +
		"- **Collector Information** (Type 3, body 14 bytes): Max Delay (uint16 " +
		"BE; in 10 µs units; max time the Frame Distributor holds a frame before " +
		"delivery) + Reserved (12 bytes).\n" +
		"- **Terminator** (Type 0, Length 0; end of TLV chain).\n\n" +
		"Pure offline parser — operators paste LACPDU bytes (multicast to the " +
		"Slow Protocols Multicast Address 01:80:C2:00:00:02) from a `tcpdump -X " +
		"ether proto 0x8809` line or a Wireshark Follow-Frame view and get the " +
		"documented Actor / Partner / Collector breakdown.\n\n" +
		"Out of scope (deferred): Ethernet framing (feed LACPDU bytes starting " +
		"at the Slow Protocols subtype byte — after destination MAC + source MAC " +
		"+ 0x8809 EtherType strip; destination is 01:80:C2:00:00:02); 802.3 " +
		"Marker Protocol (Subtype 0x02 — used during port-removal flushing; same " +
		"Slow Protocols envelope but different body; surfaced as a Note rather " +
		"than parsed); LACP state-machine simulation (State bitfield is decoded " +
		"with named flags; reasoning about Selection / Mux state machine " +
		"transitions is higher-level).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational L2 control-plane " +
		"protocol — universal in datacenter + enterprise networks with bonded " +
		"interfaces / port-channels / EtherChannels / LAGs). Wrap-vs-native: " +
		"native — IEEE 802.1AX-2020 wire format is fully public; LACP uses a " +
		"tight TLV-based PDU with well-defined body sizes for each TLV type; no " +
		"crypto, no compression.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"LACPDU bytes starting at the Slow Protocols subtype byte (i.e. after Ethernet header + 0x8809 EtherType strip). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   lacpDecodeHandler,
}

func lacpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("lacp_decode: 'hex' is required")
	}
	res, err := lacp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("lacp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
