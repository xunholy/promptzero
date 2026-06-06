// aoe_decode.go — host-side ATA over Ethernet (AoE) decoder Spec,
// delegating to internal/aoe.
//
// Wrap-vs-native: native — a fixed 10-byte header + a command body;
// byte-field reads + a command switch, stdlib only. AoE is unauthenticated
// L2 raw-disk access — surfaces the target disk (shelf.slot), the ATA
// command (READ/WRITE/IDENTIFY) + LBA, or the Query-Config string. A real
// storage attack-surface recon decoder. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/aoe"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(aoeDecodeSpec)
}

var aoeDecodeSpec = Spec{
	Name: "aoe_decode",
	Description: "Decode **ATA over Ethernet** (AoE, EtherType 0x88A2) — the CORAID protocol that exposes raw ATA " +
		"disk commands directly over an Ethernet segment. AoE has **no authentication and no IP layer**: any " +
		"host on the same L2 segment can issue ATA **READ / WRITE** to an exposed AoE target — a major " +
		"unauthenticated **data-theft / data-destruction** surface. A captured AoE frame is storage-" +
		"reconnaissance: it reveals the target disk (**shelf.slot**), the **ATA command** (READ / WRITE / " +
		"IDENTIFY / DMA / FLUSH), the 48-bit **LBA** + sector count being transferred, or — via **Query " +
		"Config Information** — the target's **config string** + firmware version.\n\n" +
		"Decodes the 10-byte header (version, Response / Error flags, error code, shelf, slot, command, tag) " +
		"and the command body: Issue ATA Command (aflags, sector count, ATA command + name, 48-bit LBA) and " +
		"Query Config Information (buffer count, firmware, AoE version, config command, config string); MAC " +
		"Mask List / Reserve-Release are named with their body surfaced raw.\n\n" +
		"No confidently-wrong output: the structural fields were verified against scapy's AoE layer; the " +
		"Response / Error flags follow the AoE spec / Wireshark (bit 3 / bit 2 — scapy maps them wrong, so " +
		"the spec is followed and the raw flag nibble is also surfaced), and the under-specified ATA aflags " +
		"byte is surfaced raw rather than mis-labelled (read-vs-write intent is already clear from the ATA " +
		"command). No network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (unauthenticated L2 storage / AoE attack-surface recon). " +
		"Wrap-vs-native: native — a byte-field read + a command switch, stdlib only, no new go.mod dep. " +
		"Structural fields verified field-for-field against scapy's AoE layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The AoE frame (the EtherType-0x88A2 payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   aoeDecodeHandler,
}

func aoeDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("aoe_decode: 'hex' is required")
	}
	res, err := aoe.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("aoe_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
