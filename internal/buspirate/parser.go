package buspirate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParseI2CScan parses the output of the `(1)` I2C scanner macro and returns
// the list of 7-bit device addresses that responded.
//
// The firmware emits lines like:
//
//	I2C ADDRESS SEARCH
//	Found address 0x50
//	Found address 0x68
//	I2C ADDRESS SEARCH COMPLETE
//
// Verified against Bus Pirate 5 firmware output (DangerousPrototypes/
// BusPirate5-firmware). Lines that do not match the "Found address 0xNN"
// pattern are silently ignored so partial output (e.g. scan interrupted by
// timeout) still yields whatever addresses were discovered before the cut.
func ParseI2CScan(raw string) []byte {
	var addrs []byte
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if m := i2cFoundRE.FindStringSubmatch(line); m != nil {
			if v, err := strconv.ParseUint(strings.TrimPrefix(m[1], "0x"), 16, 8); err == nil {
				addrs = append(addrs, byte(v))
			}
		}
	}
	return addrs
}

// i2cFoundRE matches "Found address 0xNN" lines from the `(1)` scanner macro.
// The address is captured as group 1 (with the "0x" prefix retained so the
// caller can choose how to format it).
//
// Verified against Bus Pirate 5 firmware I2C scan output.
var i2cFoundRE = regexp.MustCompile(`(?i)found\s+address\s+(0x[0-9a-fA-F]+)`)

// ParseHexBytes parses a space- or newline-separated list of hex byte values
// as emitted by `r:N` SPI reads and the UART bridge response. Both `0xNN`
// and bare `NN` formats are accepted.
//
// Example inputs:
//
//	"0x00 0xFF 0xAB 0x12"
//	"0x00\n0xFF\n0xAB"
//	"00 FF AB 12"
//
// Tokens that cannot be parsed as a hex byte are skipped so partial or
// annotated output (e.g. the firmware may prefix the line with "READ:")
// still yields the bytes that are present.
func ParseHexBytes(raw string) []byte {
	var out []byte
	for _, tok := range hexSplitRE.Split(raw, -1) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		// Strip 0x prefix for ParseUint.
		hex := strings.TrimPrefix(tok, "0x")
		hex = strings.TrimPrefix(hex, "0X")
		if len(hex) == 0 || len(hex) > 2 {
			continue
		}
		if v, err := strconv.ParseUint(hex, 16, 8); err == nil {
			out = append(out, byte(v))
		}
	}
	return out
}

// hexSplitRE splits on any mix of whitespace, commas, and colons so that
// output like "0x00, 0xFF; 0xAB" tokenises cleanly.
var hexSplitRE = regexp.MustCompile(`[\s,;]+`)

// ParseVoltages parses the output of the `v` voltage command and returns a
// map of IO pin index (0–7) to volts.
//
// The firmware emits lines in the format:
//
//	VOUT: 3.30V
//	VREG: 3.30V
//	IO0: 3.30V
//	IO1: 3.30V
//	...
//	IO7: 3.29V
//
// Verified against Bus Pirate 5 firmware v6.1 output. Only IO0–IO7 lines
// are mapped to integer keys; VOUT and VREG are ignored by this function
// (use ParseVoltageTable for the full table including rails).
//
// Returns an error only when no IO pins could be parsed — a non-fatal
// partial result is still returned alongside the error.
func ParseVoltages(raw string) (map[int]float64, error) {
	m := make(map[int]float64)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		pm := ioPinRE.FindStringSubmatch(line)
		if pm == nil {
			continue
		}
		pinIdx, err := strconv.Atoi(pm[1])
		if err != nil {
			continue
		}
		v, err := strconv.ParseFloat(pm[2], 64)
		if err != nil {
			continue
		}
		m[pinIdx] = v
	}
	if len(m) == 0 {
		return m, fmt.Errorf("buspirate: no IO pin voltages found in output: %q", raw)
	}
	return m, nil
}

// ioPinRE matches lines like "IO3: 3.30V" and captures the pin index and
// voltage value.
var ioPinRE = regexp.MustCompile(`(?i)^IO(\d+)\s*:\s*([\d.]+)\s*V`)

// ParseSingleVoltage extracts a single voltage reading from the output of
// `a N` (analog pin read). The firmware prints a line like:
//
//	IO1 VOLTAGE: 1.65V
//
// or simply:
//
//	1.65V
//
// Returns an error when no voltage value can be parsed.
func ParseSingleVoltage(raw string) (float64, error) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if m := singleVoltRE.FindStringSubmatch(line); m != nil {
			if v, err := strconv.ParseFloat(m[1], 64); err == nil {
				return v, nil
			}
		}
	}
	return 0, fmt.Errorf("buspirate: no voltage value found in output: %q", raw)
}

// singleVoltRE captures a decimal number followed by 'V' (case-insensitive).
var singleVoltRE = regexp.MustCompile(`([\d.]+)\s*[Vv]\b`)

// ParseVoltageTable returns a string→float64 map covering all labelled
// voltage lines in the `v` output, including VOUT, VREG, and all IO pins.
// Useful for detailed reporting; the buspirate_voltages tool uses
// ParseVoltages (IO pins only) for its structured result.
func ParseVoltageTable(raw string) map[string]float64 {
	m := make(map[string]float64)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if pm := voltTableRE.FindStringSubmatch(line); pm != nil {
			label := strings.ToUpper(strings.TrimRight(pm[1], ": \t"))
			if v, err := strconv.ParseFloat(pm[2], 64); err == nil {
				m[label] = v
			}
		}
	}
	return m
}

// voltTableRE matches "LABEL: N.NNV" lines from the full voltage table.
var voltTableRE = regexp.MustCompile(`^([A-Za-z0-9]+)\s*:\s*([\d.]+)\s*[Vv]`)
