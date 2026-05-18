// j1850.go — host-side SAE J1850 frame dissector Spec,
// delegating to the internal/j1850 package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/j1850"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(automotiveJ1850DecodeSpec)
}

var automotiveJ1850DecodeSpec = Spec{
	Name: "automotive_j1850_decode",
	Description: "Decode a SAE J1850 VPW (GM) or PWM (Ford) frame — the legacy OBD-II " +
		"protocol used by classic-car (pre-2008) GM and Ford vehicles before they migrated " +
		"to CAN bus. Per SAE J1850 + SAE J2178 + SAE J1979 (OBD-II). Decodes:\n\n" +
		"- **3-byte header**: priority (3 bits) + header type (1 bit) + ID (4 bits) + target " +
		"ECU address (8 bits) + source ECU address (8 bits).\n" +
		"- **Standard ECU address lookup**: Engine Control Module (0x10), Transmission " +
		"Control Module (0x18), Body Control Module (0x28), ABS (0x40), Airbag (0x48), " +
		"HVAC (0x60), Instrument Cluster (0x70), Radio (0x80), Diagnostic Tool (0xF1), " +
		"Broadcast (0xFE).\n" +
		"- **OBD-II detection**: when data[0] matches a known Mode (Service ID 0x01-0x0A), " +
		"surfaces the structured OBD-II view with mode name + request/response flag (high " +
		"bit of mode = 0x40 indicates response) + PID name lookup for Mode 1 (Engine Load / " +
		"Coolant Temp / RPM / Vehicle Speed / MAF / Throttle / Fuel Tank / Control Module " +
		"Voltage / Engine Oil Temp / etc. — ~30 documented PIDs from SAE J1979).\n" +
		"- **CRC-8 validation**: per SAE J1850 §5.4 (polynomial 0x1D, init 0xFF, final " +
		"XOR 0xFF). Surfaces both the captured CRC byte and the computed expected value for " +
		"debugging mismatches.\n\n" +
		"Pure offline parser — operators paste a captured J1850 frame from a Macchina M2 / " +
		"OBDLink LX / classic-car OBD-II adapter and inspect every field without re-" +
		"connecting to the vehicle. Pairs with the existing canbus_* tools (those cover CAN " +
		"bus from 2008+); this Spec extends automotive coverage backwards to the legacy " +
		"J1850 buses still found on classic-car restoration / older fleet analysis workflows.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (automotive decode space — honourable mentions " +
		"m2_lin_capture / m2_j1850_decode). Wrap-vs-native: native — SAE J1850 + J2178 + " +
		"J1979 are all fully public specs, the walker is ~300 lines of bit-twiddling + " +
		"lookup tables.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded J1850 frame (3-byte header + 0-7 data bytes + 1-byte CRC; 4-11 bytes total). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   automotiveJ1850DecodeHandler,
}

func automotiveJ1850DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("automotive_j1850_decode: 'hex' is required")
	}
	res, err := j1850.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("automotive_j1850_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
