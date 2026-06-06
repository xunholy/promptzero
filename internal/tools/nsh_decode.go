// nsh_decode.go — host-side NSH (Network Service Header, RFC 8300, SFC)
// decoder Spec, delegating to internal/nsh.
//
// Wrap-vs-native: native — a 4-byte base header + 4-byte service-path
// header + context, chaining the inner packet to internal/ipdecode;
// byte/bitfield reads, stdlib only. Joins the tunnel-decap family
// (gre/geneve/vxlan/mpls/sflow/etherip). Surfaces the SFC service path +
// the steered inner flow. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/nsh"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(nshDecodeSpec)
}

var nshDecodeSpec = Spec{
	Name: "nsh_decode",
	Description: "Decode the **Network Service Header** (NSH, RFC 8300) — the **Service Function Chaining (SFC)** " +
		"encapsulation that steers a packet through an ordered chain of service functions (firewalls, DPI, " +
		"NAT, load-balancers) in SDN / NFV / cloud fabrics. Joins the project's tunnel-decap decoder family " +
		"(`gre`, `geneve`, `vxlan`, `mpls`, `sflow`, `etherip`): a captured NSH packet reveals the **service " +
		"path** (SPI) and current **service index** (SI) a packet is being steered along — the SFC routing " +
		"topology — and carries the original packet inside, so decoding it decaps the steered inner flow.\n\n" +
		"Decodes the 4-byte base header (version, OAM flag, TTL, length, **MD type**, **next protocol**) and " +
		"the 4-byte service-path header (**SPI** + **SI**); surfaces the context headers as raw hex; and " +
		"chains the inner packet via the project's IP decoder when next protocol is IPv4 / IPv6 (an Ethernet " +
		"inner has its L2 header surfaced and its IP payload chained; other next protocols are left raw).\n\n" +
		"No confidently-wrong output: the base + service-path header was verified against scapy's NSH layer; " +
		"the context headers (MD type 1 = fixed 16 bytes; MD type 2 = varied TLVs) are surfaced raw rather " +
		"than field-decoded, and an inner IP payload that fails to parse degrades to an inner_decode_error + " +
		"raw hex. No network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (SFC / NSH service-chain decap recon). Wrap-vs-native: native " +
		"— a byte/bitfield read + the existing inner-IP decode path, stdlib only, no new go.mod dep. Base + " +
		"service-path header verified field-for-field against scapy's NSH layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The NSH packet as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nshDecodeHandler,
}

func nshDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("nsh_decode: 'hex' is required")
	}
	res, err := nsh.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("nsh_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
