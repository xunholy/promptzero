// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spiflash decodes SPI NOR flash transactions — the command set and
// the JEDEC RDID identification of the serial flash chips that hold firmware
// on embedded devices, routers, IoT gear and the Flipper's own targets.
// Reading the chip's contents (a firmware dump) is a core hardware-hacking
// activity, and the first steps are always the same: issue RDID (0x9F) to
// identify the chip, then READ (0x03) / FAST_READ (0x0B) to dump it (or
// WREN + PAGE_PROGRAM / ERASE to write). A captured SPI transaction (from a
// logic analyzer or a Bus Pirate dump, cf. the project's buspirate_spi_dump)
// is decoded here: the command name, the 24-bit address of a read / program /
// erase, and — for RDID — the **JEDEC manufacturer** (Winbond / Macronix /
// Micron / GigaDevice / …) and the typical capacity, which identifies the chip
// and its size. The chip-dump member of the project's hardware-bus tooling
// (internal/jtag, internal/buspirate).
//
// # Wrap-vs-native judgement
//
//	Native. A SPI NOR transaction is a 1-byte command opcode optionally
//	followed by a 24-bit address (read / program / erase) or a 3-byte JEDEC
//	ID (RDID). A byte read + an opcode lookup + a manufacturer table; stdlib
//	only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The decoded command opcodes are the universal / JEDEC-standard SPI NOR set
//	(RDID, READ, FAST_READ, PAGE_PROGRAM, the erases, the status-register and
//	write-enable commands, the dual/quad reads, SFDP, reset, 4-byte-address
//	mode) shared across Winbond / Macronix / Micron / GigaDevice / ISSI /
//	Spansion / SST and verified against their datasheets; an opcode outside
//	the set is reported as unknown / vendor-specific rather than guessed. The
//	RDID manufacturer byte is named from the well-known single-byte SPI
//	manufacturer codes; the capacity is computed as the common 2^code encoding
//	and labelled "typical" (a few vendors deviate), with the raw memory-type
//	and capacity bytes surfaced alongside.
package spiflash

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a SPI NOR flash transaction.
type Result struct {
	Command     int    `json:"command"`
	CommandHex  string `json:"command_hex"`
	CommandName string `json:"command_name"`

	Address string `json:"address,omitempty"` // 24-bit address for read/program/erase

	// RDID (0x9F)
	ManufacturerID   string `json:"manufacturer_id,omitempty"`
	ManufacturerName string `json:"manufacturer_name,omitempty"`
	MemoryTypeHex    string `json:"memory_type_hex,omitempty"`
	CapacityCodeHex  string `json:"capacity_code_hex,omitempty"`
	TypicalCapacity  string `json:"typical_capacity,omitempty"`

	PayloadHex string   `json:"payload_hex,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// Decode parses a SPI NOR flash transaction (the MOSI command stream, with any
// captured readback) from hex (whitespace / ':' / '-' / '_' separators and a
// '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("spiflash: empty input")
	}
	cmd := b[0]
	r := &Result{
		Command:     int(cmd),
		CommandHex:  fmt.Sprintf("0x%02X", cmd),
		CommandName: commandName(cmd),
	}
	rest := b[1:]

	switch cmd {
	case 0x9F: // RDID — JEDEC ID: manufacturer, memory type, capacity
		if len(rest) >= 3 {
			r.ManufacturerID = fmt.Sprintf("0x%02X", rest[0])
			r.ManufacturerName = manufacturerName(rest[0])
			r.MemoryTypeHex = fmt.Sprintf("0x%02X", rest[1])
			r.CapacityCodeHex = fmt.Sprintf("0x%02X", rest[2])
			r.TypicalCapacity = capacityFromCode(rest[2])
			if len(rest) > 3 {
				r.PayloadHex = hexUpper(rest[3:])
			}
		} else {
			r.Notes = append(r.Notes, "RDID (0x9F): the 3-byte JEDEC ID is returned on MISO — include the readback bytes to decode the manufacturer + capacity")
			if len(rest) > 0 {
				r.PayloadHex = hexUpper(rest)
			}
		}
	case 0x03, 0x0B, 0x02, 0x20, 0x52, 0xD8, 0x32, 0x3B, 0x6B, 0xBB, 0xEB, 0x5A: // 3-byte address commands
		if len(rest) >= 3 {
			r.Address = fmt.Sprintf("0x%02X%02X%02X", rest[0], rest[1], rest[2])
			if len(rest) > 3 {
				r.PayloadHex = hexUpper(rest[3:])
			}
		} else if len(rest) > 0 {
			r.PayloadHex = hexUpper(rest)
		}
	default:
		if len(rest) > 0 {
			r.PayloadHex = hexUpper(rest)
		}
	}

	r.Notes = append(r.Notes, "SPI NOR flash — RDID (0x9F) identifies the chip, READ (0x03) / FAST_READ (0x0B) dump it, WREN + PAGE_PROGRAM / ERASE write it; the recon headline for a firmware dump")
	return r, nil
}

func commandName(c byte) string {
	names := map[byte]string{
		0x06: "WREN (Write Enable)",
		0x04: "WRDI (Write Disable)",
		0x9F: "RDID (Read JEDEC ID)",
		0x90: "REMS (Read Manufacturer/Device ID)",
		0xAB: "RDP / Release Power-Down + Device ID",
		0xB9: "DP (Deep Power-Down)",
		0x05: "RDSR (Read Status Register 1)",
		0x35: "RDSR2 (Read Status Register 2)",
		0x15: "RDSR3 (Read Status Register 3)",
		0x01: "WRSR (Write Status Register)",
		0x03: "READ (Read Data)",
		0x0B: "FAST_READ",
		0x3B: "Dual Output Fast Read",
		0x6B: "Quad Output Fast Read",
		0xBB: "Dual I/O Fast Read",
		0xEB: "Quad I/O Fast Read",
		0x02: "PP (Page Program)",
		0x32: "Quad Page Program",
		0x20: "SE (Sector Erase, 4 KB)",
		0x52: "BE32K (Block Erase, 32 KB)",
		0xD8: "BE64K (Block Erase, 64 KB)",
		0xC7: "CE (Chip Erase)",
		0x60: "CE (Chip Erase)",
		0x5A: "RDSFDP (Read SFDP)",
		0x66: "Enable Reset",
		0x99: "Reset",
		0xB7: "EN4B (Enter 4-Byte Address Mode)",
		0xE9: "EX4B (Exit 4-Byte Address Mode)",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("unknown / vendor-specific command 0x%02X", c)
}

// manufacturerName maps the single-byte SPI NOR JEDEC manufacturer code (as
// returned by RDID) to the vendor; only the well-known codes are named.
func manufacturerName(c byte) string {
	names := map[byte]string{
		0xEF: "Winbond",
		0xC2: "Macronix (MXIC)",
		0x20: "Micron / Numonyx / ST",
		0xC8: "GigaDevice",
		0x9D: "ISSI",
		0x01: "Spansion / Cypress / Infineon",
		0xBF: "SST / Microchip",
		0x1F: "Atmel / Adesto / Renesas",
		0x1C: "EON",
		0x8C: "ESMT",
		0x0B: "XTX",
		0x68: "Boya",
		0xA1: "Fudan",
		0x5E: "Zbit",
		0xEB: "Zetta",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return "unknown manufacturer"
}

// capacityFromCode renders the typical 2^code capacity from the RDID capacity
// byte. A few vendors deviate, so it is labelled "typical".
func capacityFromCode(code byte) string {
	if code < 0x10 || code > 0x2A {
		return ""
	}
	bytes := uint64(1) << code
	var human string
	switch {
	case bytes >= 1<<20:
		human = fmt.Sprintf("%d MB", bytes>>20)
	case bytes >= 1<<10:
		human = fmt.Sprintf("%d KB", bytes>>10)
	default:
		human = fmt.Sprintf("%d B", bytes)
	}
	return fmt.Sprintf("typical %s (2^%d bytes)", human, code)
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("spiflash: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("spiflash: input is not valid hex: %w", err)
	}
	return b, nil
}
