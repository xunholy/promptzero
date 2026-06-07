// spiflash_decode.go — host-side SPI NOR flash transaction decoder Spec,
// delegating to internal/spiflash.
//
// Wrap-vs-native: native — a 1-byte command opcode + optional 24-bit address /
// 3-byte JEDEC ID; a byte read + an opcode lookup + a manufacturer table,
// stdlib only. The chip-dump / firmware-extraction decoder — identifies the
// SPI flash command and, for RDID, the JEDEC manufacturer + capacity (which
// chip). Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/spiflash"
)

func init() { //nolint:gochecknoinits
	Register(spiFlashDecodeSpec)
}

var spiFlashDecodeSpec = Spec{
	Name: "spi_flash_decode",
	Description: "Decode a **SPI NOR flash** transaction — the command set and JEDEC identification of the serial " +
		"flash chips that hold firmware on embedded devices, routers, IoT gear and the Flipper's own targets. " +
		"Reading the chip's contents (a **firmware dump**) is a core hardware-hacking activity, and the first " +
		"steps are always the same: issue **RDID** (0x9F) to identify the chip, then **READ** (0x03) / " +
		"FAST_READ (0x0B) to dump it (or WREN + PAGE_PROGRAM / ERASE to write). A captured SPI transaction " +
		"(from a logic analyzer or a Bus Pirate dump — cf. the project's `buspirate_spi_dump`) is decoded " +
		"here: the **command name**, the **24-bit address** of a read / program / erase, and — for RDID — the " +
		"**JEDEC manufacturer** (Winbond / Macronix / Micron / GigaDevice / ISSI / Spansion / SST / …) and the " +
		"typical **capacity**, which identifies the chip and its size. The chip-dump member of the project's " +
		"hardware-bus tooling (`internal/jtag`, `internal/buspirate`).\n\n" +
		"No confidently-wrong output: the decoded command opcodes are the universal / JEDEC-standard SPI NOR " +
		"set (RDID, READ, FAST_READ, PAGE_PROGRAM, the erases, the status-register and write-enable commands, " +
		"the dual/quad reads, SFDP, reset, 4-byte-address mode) shared across the major vendors and verified " +
		"against their datasheets; an opcode outside the set is reported as **unknown / vendor-specific** " +
		"rather than guessed. The RDID manufacturer byte is named from the well-known single-byte SPI " +
		"manufacturer codes (unknown otherwise); the capacity is the common **2^code** encoding labelled " +
		"'typical' (a few vendors deviate), with the raw memory-type and capacity bytes surfaced alongside. No " +
		"network, no device, transmits nothing, so it is Low risk. The input is the SPI transaction (the MOSI " +
		"command stream, with any captured readback). ':' / '-' / '_' / whitespace separators and a '0x' " +
		"prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (chip-dump / firmware-extraction recon; decodes what " +
		"buspirate_spi_dump captures). Wrap-vs-native: native — a byte read + an opcode lookup + a " +
		"manufacturer table, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The SPI NOR flash transaction (the MOSI command stream, e.g. '9F EF 40 18' for RDID, with any captured readback) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   spiFlashDecodeHandler,
}

func spiFlashDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("spi_flash_decode: 'hex' is required")
	}
	res, err := spiflash.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("spi_flash_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
