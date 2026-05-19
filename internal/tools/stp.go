// stp.go — host-side STP/RSTP/MSTP BPDU decoder Spec.
// Wraps the internal/stp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/stp"
)

func init() { //nolint:gochecknoinits
	Register(stpBPDUDecodeSpec)
}

var stpBPDUDecodeSpec = Spec{
	Name: "stp_bpdu_decode",
	Description: "Decode a Spanning Tree Protocol BPDU (Bridge Protocol Data Unit) per " +
		"IEEE 802.1D-2004 (STP / RSTP) and IEEE 802.1Q-2014 §13 (MSTP). STP is the " +
		"foundational L2 loop-prevention protocol every managed switch runs by default " +
		"— every datacenter, every enterprise floor switch, every Cisco VSS / Juniper " +
		"Virtual Chassis / Arista MLAG deployment uses it. Pairs with `lldp_decode`, " +
		"`cdp_decode`, `vlan_decode`, `arp_decode` for complete L2 topology + " +
		"discovery visibility. Decodes:\n\n" +
		"- **4-byte common header**:\n" +
		"  - Protocol ID (2 bytes BE) — must be 0x0000.\n" +
		"  - **Version** (1 byte) — 0 = STP (IEEE 802.1D), 2 = RSTP (IEEE 802.1D-" +
		"2004), 3 = MSTP (IEEE 802.1Q-2014 §13).\n" +
		"  - **BPDU Type** (1 byte) — 0x00 Configuration BPDU, 0x80 Topology Change " +
		"Notification (TCN), 0x02 RSTP/MSTP BPDU (carries the extended flags).\n" +
		"- **Configuration BPDU body** (31 bytes):\n" +
		"  - **Flags** (1 byte) with **8-bit name table**: TC (bit 0, Topology " +
		"Change) / Proposal (bit 1) / Port Role (bits 2-3) / Learning (bit 4) / " +
		"Forwarding (bit 5) / Agreement (bit 6) / TC Ack (bit 7). **Port Role**: " +
		"0 Unknown/Master, 1 Alternate-or-Backup, 2 Root, 3 Designated.\n" +
		"  - **Root Bridge ID** (8 bytes) — 4-bit Priority (multiple of 4096) + 12-" +
		"bit System ID Extension (typically VLAN ID for PVST+) + 6-byte MAC.\n" +
		"  - **Root Path Cost** (4 bytes BE).\n" +
		"  - **Bridge ID** (8 bytes) — same split as Root Bridge ID.\n" +
		"  - **Port ID** (2 bytes BE) — 4-bit Port Priority + 12-bit Port Number.\n" +
		"  - **Message Age / Max Age / Hello Time / Forward Delay** (2 bytes BE " +
		"each, in IEEE 1/256-second units; surfaced as milliseconds for " +
		"readability).\n" +
		"- **TCN BPDU body** — empty; the 4-byte common header is the entire frame. " +
		"Trailing bytes surface a non-conformance Note.\n" +
		"- **MSTP trailer** (Version=3) — the Version 1 Length byte + Version 3 " +
		"Length + MSTI Configuration block is surfaced as raw hex (deep MSTI " +
		"dissection is a future Spec).\n\n" +
		"Pure offline parser — operators paste BPDU bytes (after the LLC header " +
		"strip — DSAP/SSAP 0x42, Control 0x03, sent to the STP-bridge multicast MAC " +
		"01:80:C2:00:00:00) from a `tcpdump -X ether dst host 01:80:c2:00:00:00` " +
		"line, a Wireshark Follow-Frame view, or any STP-emitting switch and get " +
		"the documented bridge / root / cost / port / timer breakdown.\n\n" +
		"Out of scope (deferred): LLC header (DSAP/SSAP/Control — feed BPDU bytes " +
		"starting at the Protocol ID field); PVST+ / per-VLAN STP SNAP-encapsulation " +
		"wrapper (the System ID Extension VLAN embedding is decoded but the SNAP " +
		"strip is the operator's responsibility); convergence-time simulation (timers " +
		"surfaced, reasoning is higher-level); MSTP MSTI configuration block deep " +
		"dissection beyond the raw-hex surface.\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational L2 loop-prevention " +
		"protocol — universal in modern Ethernet). Wrap-vs-native: native — IEEE " +
		"802.1D is fully public; wire format is a tight bit-packed binary header; " +
		"no crypto, no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"STP BPDU bytes (after the LLC header strip; starts at the Protocol ID field). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   stpBPDUDecodeHandler,
}

func stpBPDUDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("stp_bpdu_decode: 'hex' is required")
	}
	res, err := stp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("stp_bpdu_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
