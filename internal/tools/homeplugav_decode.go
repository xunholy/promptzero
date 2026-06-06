// homeplugav_decode.go — host-side HomePlug AV / IEEE 1901 powerline
// management-message decoder Spec, delegating to internal/homeplugav.
//
// Wrap-vs-native: native — a 1-byte version + 2-byte little-endian MMTYPE
// + body; a byte read + an MMTYPE lookup, stdlib only. The powerline (PLC)
// management decoder — a distinct domain. Surfaces the management
// operation (key exchange / sniffer / network info / MAC-memory read)
// from a captured powerline frame. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/homeplugav"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(homePlugAVDecodeSpec)
}

var homePlugAVDecodeSpec = Spec{
	Name: "homeplugav_decode",
	Description: "Decode the management-message envelope of **HomePlug AV / IEEE 1901 powerline** networking (the " +
		"MAC Management Entry, EtherType 0x88E1) — the control plane of powerline (PLC) adapters. Powerline " +
		"is a real, often-overlooked **attack surface**: the medium is shared across a building's wiring, and " +
		"the management messages drive network membership, key exchange and diagnostics. A captured HomePlug " +
		"AV management frame identifies the **management operation** in flight — a **Set Encryption Key** (the " +
		"powerline Network Membership Key exchange), a **Sniffer** enable, a **Network Information** query " +
		"(station / network enumeration), a **Read MAC Memory** firmware dump, a device reset — which is the " +
		"recon headline for powerline reconnaissance. A distinct domain alongside the project's RF / wireless " +
		"decoders.\n\n" +
		"Decodes the envelope: the MM **version** (1.0 / 1.1), the **MMTYPE** (little-endian) + its **name** " +
		"(from the 77-entry table), the request/confirmation/indication/response **sub-type** (the two LSBs) " +
		"and the MMTYPE **category** (STA-STA / STA-CCo / vendor / …). The Set-Encryption-Key and Sniffer " +
		"messages are flagged.\n\n" +
		"No confidently-wrong output: only the envelope is decoded — the message **bodies** are many, " +
		"version-specific (the v1.1 fragmentation header) and largely vendor-specific (Qualcomm/Intellon), so " +
		"they are surfaced as raw hex; the MMTYPE name table is code-generated from scapy's authoritative " +
		"map. No network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (powerline / HomePlug AV management recon). Wrap-vs-native: " +
		"native — a byte read + an MMTYPE lookup, stdlib only, no new go.mod dep. Version + MMTYPE verified " +
		"field-for-field against scapy's HomePlugAV layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The HomePlug AV management envelope (the EtherType-0x88E1 payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   homePlugAVDecodeHandler,
}

func homePlugAVDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("homeplugav_decode: 'hex' is required")
	}
	res, err := homeplugav.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("homeplugav_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
