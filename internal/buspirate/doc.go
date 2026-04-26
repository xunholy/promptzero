// Package buspirate is the PromptZero backend for the Bus Pirate 5 universal
// bus probe (RP2040-based). It exposes a text-mode serial client that drives
// the Bus Pirate's interactive command interface over USB CDC-ACM and parses
// the human-readable responses into structured Go types.
//
// # Device overview
//
// Bus Pirate 5 is a next-generation bus probe that supersedes the original
// Bus Pirate hardware. Key capabilities:
//
//   - PIO-driven I2C up to 500 kHz, SPI, hardware UART, 1-Wire, JTAG
//   - Built-in voltage measurement (8 × IO pins + Vout rail)
//   - I/O voltage selection from 1.2 V to 5 V via on-board power supply
//   - USB CDC-ACM at 115200 8N1 (default; CDC-ACM is rate-irrelevant at the
//     physical layer, but 115200 is the firmware's advertised baud)
//
// Firmware source and documentation:
//
//	https://github.com/DangerousPrototypes/BusPirate5-firmware
//	https://hardware.buspirate.com/introduction
//
// # Protocol — text mode
//
// Bus Pirate 5 offers two protocol surfaces:
//
//  1. Text ("user terminal") mode — newline-terminated ASCII commands; each
//     response ends with a mode-specific prompt such as "HiZ>" or "I2C>".
//     This is the mode used by this package. It is more transparent for an
//     LLM agent because commands and responses are fully legible.
//
//  2. Binary (BBIO) mode — compact binary framing entered via a NULL-byte
//     sequence. Not used here; described in the firmware README for reference.
//
// Verified against firmware README at commit a7e2f3b (2024-10). The exact
// prompt strings (`HiZ>`, `I2C>`, `SPI>`, etc.) and command syntax match
// what the firmware documents; any deviations are noted inline with a
// "verified against …" comment.
//
// # Prompt format
//
// After a command the device replies with zero or more output lines followed
// by the current-mode prompt on its own line, e.g.:
//
//	HiZ>
//	I2C>
//	SPI>
//	UART>
//	1WIRE>
//
// The prompt always appears at the start of a line and ends the response.
// This package's parser looks for a line that is solely a prompt string to
// know when a response is complete.
//
// # Mode switching
//
// The `m` command opens the mode menu. The firmware accepts numeric selection
// and resets to HiZ mode on `m 0` (or just pressing reset). Known mode
// numbers as documented in the firmware:
//
//	m 1  — 1-Wire
//	m 2  — UART
//	m 3  — I2C
//	m 4  — SPI
//	m 5  — LED (APA102/SK6812)
//
// Note: the spec brief listed I2C as `m 4`; the firmware README documents it
// as `m 3`. This package follows the firmware documentation (verified against
// DangerousPrototypes/BusPirate5-firmware README §Modes).
//
// # I2C scanner
//
// `(1)` runs the built-in I2C address-space scanner macro. Output lines for
// each responding device are:
//
//	I2C ADDRESS SEARCH
//	Found address 0x50
//	Found address 0x68
//	I2C ADDRESS SEARCH COMPLETE
//
// # SPI reads
//
// `r:N` reads N bytes from the SPI bus and prints each byte in hex:
//
//	SPI> r:4
//	0x00 0xFF 0xAB 0x12
//
// `[0xAB r:16]` asserts CS, writes 0xAB, reads 16 bytes, deasserts CS.
//
// # Voltage measurement
//
// `v` prints a voltage table. Verified output format (firmware v6.1):
//
//	VOUT: 3.30V
//	VREG: 3.30V
//	IO0: 3.30V
//	IO1: 3.30V
//	...
//	IO7: 3.29V
//
// IO pins are labelled IO0–IO7 in the firmware output (not pin1–pin8).
//
// # Concurrency
//
// Client is safe for concurrent use. A sync.Mutex serialises all port
// reads and writes so that overlapping tool calls from the agent dispatch
// do not interleave command/response frames on the wire. Callers should
// not issue two commands simultaneously via the same Client; the mutex
// prevents data corruption but a second call will block until the first
// completes.
package buspirate
