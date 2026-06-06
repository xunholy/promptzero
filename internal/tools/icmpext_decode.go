// icmpext_decode.go — host-side ICMP multipart extension (RFC 4884) +
// MPLS Label Stack object (RFC 4950) decoder Spec, delegating to
// internal/icmpext.
//
// Wrap-vs-native: native — a 4-byte extension header + TLV objects, the MPLS
// object being a stack of 32-bit label entries; a byte walk + a bit-field
// read, stdlib only. The ICMP-extension decoder — surfaces the MPLS labels a
// dropped packet was carrying (the label-switched path) from a Time-Exceeded
// / Unreachable message's extension. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/icmpext"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(icmpExtDecodeSpec)
}

var icmpExtDecodeSpec = Spec{
	Name: "icmp_extension_decode",
	Description: "Decode the **ICMP multipart message extension** (RFC 4884) and its **MPLS Label Stack** object " +
		"(RFC 4950). When a router sends an ICMP **Time Exceeded** (TTL expired) or **Destination Unreachable** " +
		"message, RFC 4884 lets it append an extension structure describing the context — and RFC 4950 defines " +
		"the MPLS Label Stack object carrying the label stack the dropped packet was traversing. This is a real " +
		"**network-reconnaissance** lever: a traceroute through an MPLS core elicits Time-Exceeded messages " +
		"whose extensions **leak the MPLS labels** (and their TTLs) at each hop, exposing the label-switched " +
		"path and the provider's MPLS topology that the tunnel would otherwise hide. RFC 5837 adds Interface " +
		"Information / Identification objects (egress interface index / IP / name / MTU) that similarly " +
		"enumerate a router's interfaces. Pairs with `icmp_packet_decode` and `mpls_decode`.\n\n" +
		"Decodes the 4-byte extension header (version + checksum) and walks the TLV objects; the **MPLS Label " +
		"Stack** object is fully decoded into its 32-bit entries (**label**, traffic class, bottom-of-stack, " +
		"TTL).\n\n" +
		"No confidently-wrong output: the extension header, the object TLV framing and the MPLS object were " +
		"verified field-for-field against scapy's ICMP-extensions layer + RFC 4950. The Interface Information " +
		"/ Identification objects (RFC 5837) carry intricate conditional fields (a bit-flagged c-type selecting " +
		"an optional ifIndex / IP sub-object / length-framed ifName / MTU), so their payload is surfaced as raw " +
		"hex with the class name rather than risk a wrong field decode; the Extended Information and any " +
		"unknown class are likewise surfaced raw, and a malformed object length stops the walk and surfaces the " +
		"remainder raw. No network, no device, transmits nothing, so it is Low risk. The input is the extension " +
		"structure (the bytes after the ICMP original-datagram field). ':' / '-' / '_' / whitespace separators " +
		"and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (ICMP MPLS-extension / traceroute topology recon). Wrap-vs-native: " +
		"native — a byte walk + a bit-field read, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The ICMP extension structure (the RFC 4884 extension header + objects, i.e. the bytes after the ICMP message's original-datagram field) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   icmpExtDecodeHandler,
}

func icmpExtDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("icmp_extension_decode: 'hex' is required")
	}
	res, err := icmpext.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("icmp_extension_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
