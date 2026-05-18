// jtag.go — host-side JTAG IDCODE / SWD DPIDR chip identifier
// Spec, delegating to the internal/jtag package for the lookup
// + bitfield walker proper.
//
// Wrap-vs-native judgement: IEEE 1149.1 IDCODE is a fully
// public spec, the JEDEC JEP106 vendor registry is also public.
// Wrapping a FAP for this would require an SD-card install + a
// firmware-fork dependency for a pure lookup. Native delivers
// offline analysis — operators scan a JTAG chain with their
// Bus Pirate / openocd / adapter-of-choice, read the IDCODE,
// and identify the chip without touching the board again.
//
// Pairs with the existing Bus Pirate / hw_recon workflows.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/jtag"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(jtagIDCodeDecodeSpec)
}

var jtagIDCodeDecodeSpec = Spec{
	Name: "jtag_idcode_decode",
	Description: "Decode a 32-bit JTAG IDCODE (IEEE 1149.1) or SWD DPIDR / TARGETID value into " +
		"manufacturer + part-number + version. Bit layout:\n\n" +
		"- **bit 0**: must be 1 per IEEE 1149.1 (we flag malformed inputs).\n" +
		"- **bits 11..1** (Manufacturer ID): IDCODE-encoded JEDEC manufacturer code " +
		"(continuation-byte-count << 7 | byte). Looks up the vendor name from our ~120-entry " +
		"JEP106 table.\n" +
		"- **bits 27..12** (Part Number): vendor-specific 16-bit chip identifier. Looks up the " +
		"chip name from a per-vendor part-number table covering common ARM Cortex-M / STM32 / " +
		"AVR / SAM / nRF52 / MSP430 / Tiva-C / PSoC / Espressif / Lattice iCE40-ECP5 / Xilinx " +
		"Spartan-Artix / Altera Cyclone families.\n" +
		"- **bits 31..28** (Version): 4-bit revision number.\n\n" +
		"Pure offline parser — operators paste an IDCODE from openocd / `bp` / urjtag / " +
		"buspirate output and identify the chip. Accepts '0x' prefix and ':' / '-' / '_' / " +
		"whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (hardware-recon decode space). Wrap-vs-native: " +
		"native — IEEE 1149.1 + JEDEC JEP106 are fully public, the walker is a 32-bit bit-shift " +
		"+ two lookup tables.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"32-bit IDCODE hex (8 chars; e.g. '4BA00477' for ARM Cortex-M JTAG-DP). Accepts '0x' prefix and ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   jtagIDCodeDecodeHandler,
}

func jtagIDCodeDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("jtag_idcode_decode: 'hex' is required")
	}
	res, err := jtag.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("jtag_idcode_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
