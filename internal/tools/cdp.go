// cdp.go — host-side Cisco Discovery Protocol decoder Spec.
// Wraps the internal/cdp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/cdp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(cdpDecodeSpec)
}

var cdpDecodeSpec = Spec{
	Name: "cdp_decode",
	Description: "Decode a Cisco Discovery Protocol (CDP) packet. CDP is the Cisco-" +
		"proprietary equivalent of LLDP and remains the dominant link-layer discovery " +
		"protocol on Cisco-heavy enterprise networks (every Catalyst switch / IOS " +
		"router / NX-OS device / Meraki AP / Cisco IP phone emits CDP frames by " +
		"default, often alongside LLDP). Natural sibling to `lldp_decode`. Decodes:\n\n" +
		"- **4-byte header** — Version (1 byte; usually 2) + TTL (1 byte seconds, " +
		"default 180) + Checksum (2 bytes BE; surfaced as hex, verification is out " +
		"of scope at this layer).\n" +
		"- **TLV walker** — each TLV is Type (2 bytes BE) + Length (2 bytes BE, " +
		"includes the 4 header bytes) + Value (Length-4 bytes). Walker iterates " +
		"frame-by-frame until the buffer is consumed.\n" +
		"- **~17 documented TLV types** with per-type body decoding:\n" +
		"  - **0x0001 Device ID** — UTF-8 string (the canonical 'hostname' equivalent).\n" +
		"  - **0x0002 Addresses** — list of protocol-typed addresses (see below).\n" +
		"  - **0x0003 Port ID** — UTF-8 string (e.g. 'GigabitEthernet0/1').\n" +
		"  - **0x0004 Capabilities** — uint32 BE bitfield with **10 documented bits**: " +
		"Router / Transparent Bridge / Source Route Bridge / Switch (Layer 2) / Host " +
		"/ IGMP-capable / Repeater / VoIP Phone / Remotely Managed Device / CVTA " +
		"(Cast VLAN Trunking Aware).\n" +
		"  - **0x0005 Software Version** — UTF-8 string (typically multi-line IOS " +
		"version banner).\n" +
		"  - **0x0006 Platform** — UTF-8 string (e.g. 'cisco WS-C2960').\n" +
		"  - **0x0007 IP Network Prefix** / **0x0008 Protocol Hello** / **0x0009 " +
		"VTP Management Domain** — surfaced with raw body hex.\n" +
		"  - **0x000A Native VLAN** — uint16 BE.\n" +
		"  - **0x000B Duplex** — 1 byte (0 half-duplex / 1 full-duplex).\n" +
		"  - **0x000E VoIP VLAN Reply** / **0x000F VoIP VLAN Query** — surfaced with " +
		"raw body hex.\n" +
		"  - **0x0010 Power Consumption** — uint16 BE milliwatts (PoE).\n" +
		"  - **0x0011 MTU** — uint32 BE bytes.\n" +
		"  - **0x0012 Trust Bitmap** / **0x0013 Untrusted Port CoS** — 1 byte each.\n" +
		"  - **0x0014 System Name** — UTF-8 string (newer than Device ID; canonical " +
		"hostname).\n" +
		"  - **0x0015 System Object ID** — ASN.1 OID bytes (surfaced as hex).\n" +
		"  - **0x0016 Management Address** — list, same shape as Addresses TLV.\n" +
		"- **Addresses TLV body** (used by both 0x0002 and 0x0016):\n" +
		"  - Number of addresses (uint32 BE).\n" +
		"  - For each entry: Protocol Type (1 byte, typically 1=NLPID) + Protocol " +
		"Length (1 byte) + Protocol bytes (e.g. 0xCC for IPv4 NLPID) + Address Length " +
		"(uint16 BE) + Address bytes (4 for IPv4, 16 for IPv6 via 802.2 SNAP).\n\n" +
		"Pure offline parser — operators paste CDP payload bytes (after the SNAP/LLC " +
		"header strip, EtherType 0x2000 with OUI 00-00-0C and PID 0x2000) from a " +
		"`tcpdump -i ethX -X ether proto 0x2000` line, a Wireshark Follow-Frame " +
		"view, an `cdpr` / `cdptools` capture, or any CDP-emitting tool and inspect " +
		"every documented field.\n\n" +
		"Out of scope (deferred): SNAP/LLC framing (feed the CDP bytes after the " +
		"802.2 LLC SNAP header — DSAP/SSAP 0xAA / Control 0x03 / OUI 00-00-0C / PID " +
		"0x2000); checksum verification (the value is surfaced as hex for visual " +
		"sanity-check); CDP version 1 (deprecated; v2 is a superset); LLDP (handled " +
		"by `lldp_decode` — CDP and LLDP often coexist on the same wire).\n\n" +
		"Source: docs/catalog/gap-analysis.md (sibling to LLDP — Cisco-proprietary " +
		"L2 discovery protocol). Wrap-vs-native: native — wire format reverse-" +
		"engineered for decades, agreed-upon by every Wireshark dissector and " +
		"cdpr/cdptools utility; no crypto, no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"CDP payload bytes (after the SNAP/LLC header) as hex. Starts at the CDP version byte. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   cdpDecodeHandler,
}

func cdpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("cdp_decode: 'hex' is required")
	}
	res, err := cdp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("cdp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
