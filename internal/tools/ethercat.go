// ethercat.go — host-side EtherCAT frame dissector Spec, delegating
// to the internal/ethercat package for the datagram walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ethercat"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ethercatDecodeSpec)
}

var ethercatDecodeSpec = Spec{
	Name: "ethercat_decode",
	Description: "Decode an EtherCAT (Ethernet for Control Automation Technology, IEC " +
		"61158 / ETG.1000) frame — the real-time industrial Ethernet fieldbus dominating " +
		"factory automation, motion control, and robotics (Beckhoff TwinCAT masters and " +
		"the EtherCAT-slave drives, servo controllers, and I/O terminals built on the " +
		"ET1100/ET1200 ESC ASICs). EtherCAT runs directly on Ethernet (EtherType 0x88A4) " +
		"or tunnelled in UDP/34980, with no authentication or encryption on the wire — a " +
		"capture reveals the full process image and addressing, exactly what an OT " +
		"pentester inspects. Decodes:\n\n" +
		"- **EtherCAT header**: 11-bit Length and 4-bit Type (1 = command/DLPDU, 4 = " +
		"network variables, 5 = mailbox) with a name table, plus length-vs-buffer " +
		"validation (trailing Ethernet padding is trimmed; an over-declared length is " +
		"noted and the walk clamped).\n" +
		"- **Datagram chain walk**: each datagram's Command (16-entry table — NOP, APRD/" +
		"APWR/APRW auto-increment, FPRD/FPWR/FPRW configured-address, BRD/BWR/BRW " +
		"broadcast, LRD/LWR/LRW logical, ARMW/FRMW multiple-write), datagram index, " +
		"addressing decode (position+offset ADP/ADO for the physical-addressing commands, " +
		"32-bit logical address for the logical commands), 11-bit data length with the " +
		"Circulating and More-follows (M) flags, IRQ, the data block (surfaced as hex), " +
		"and the Working Counter incremented by each slave that processed the datagram.\n" +
		"- **Chaining**: the More-follows (M) bit drives the multi-datagram walk, " +
		"validated against the remaining buffer so a truncated chain stops cleanly.\n\n" +
		"Pure offline parser — operators paste the EtherCAT payload from a Wireshark " +
		"capture (the bytes after EtherType 0x88A4) or a UDP/34980 dump and inspect every " +
		"datagram. Companion to knxnetip_decode, bacnet_ip_decode, modbus_decode, and " +
		"mbus_decode for the full OT / industrial decode space.\n\n" +
		"Out of scope (deferred): the Ethernet/UDP framing (feed the EtherCAT payload), " +
		"the Mailbox (Type 5) sub-protocols (CoE / EoE / FoE / SoE — the data block is " +
		"surfaced as hex), and process-data interpretation (mapping the data block to " +
		"objects needs the slave's ESI / object dictionary).\n\n" +
		"Source: docs/catalog/gap-analysis.md (OT / industrial-Ethernet decode space — " +
		"EtherCAT is the dominant motion-control fieldbus, companion to the PROFINET / " +
		"Modbus / OPC UA decoders). Wrap-vs-native: native — IEC 61158 is public and the " +
		"datagram chain is a fixed-format byte stream.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded EtherCAT payload (bytes after EtherType 0x88A4, or the UDP/34980 payload): 2-byte EtherCAT header (11-bit length + 4-bit type) followed by the datagram chain (each: command + index + address + length/flags + IRQ + data + working counter). ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ethercatDecodeHandler,
}

func ethercatDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ethercat_decode: 'hex' is required")
	}
	res, err := ethercat.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ethercat_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
