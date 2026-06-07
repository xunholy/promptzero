// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pmbus decodes PMBus — the Power Management Bus, an SMBus/I2C command
// set (PMBus spec) that PSUs, voltage regulators (VRMs), battery chargers and
// hot-swap controllers expose to set and read their power rails. PMBus is a
// real and current hardware-attack surface: the 2023 "PMFault" research showed
// that writing the PSU's VOUT_COMMAND / OPERATION over PMBus can overvolt a
// server's CPU rail to induce faults — so a captured PMBus transaction (from
// an I2C/SMBus sniffer, cf. the project's i2c_scan) is real recon. A PMBus
// message identifies the **command** in flight — a voltage-setting OPERATION /
// VOUT_COMMAND / VOUT_MARGIN (the attack-relevant writes, flagged), a READ_VIN
// / READ_VOUT / READ_IOUT / READ_TEMPERATURE telemetry read, a STATUS query, a
// manufacturer-ID query — and, for the LINEAR11 telemetry reads, the decoded
// physical value. It joins the project's hardware-bus tooling (internal/jtag,
// internal/buspirate, internal/spiflash).
//
// # Wrap-vs-native judgement
//
//	Native. A PMBus transaction is a 1-byte command code optionally followed
//	by little-endian data; telemetry values use the LINEAR11 (5-bit signed
//	exponent + 11-bit signed mantissa) float encoding and STATUS words are
//	bit-fields. A byte read + an opcode table + a couple of bit/float decodes;
//	stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The decoded command codes are the PMBus-specification standard set
//	(OPERATION, VOUT_COMMAND, the VOUT margins/limits, the READ_* telemetry,
//	the STATUS_* registers, PMBUS_REVISION, MFR_ID, …); a code outside the set
//	is reported as unknown / manufacturer-specific rather than guessed. The
//	LINEAR11 decode (deterministic two's-complement exponent × mantissa) is
//	applied only to the commands defined as LINEAR11 (the current / power /
//	temperature / input-voltage reads); VOUT-format values (ULINEAR16, scaled
//	by the device's VOUT_MODE exponent which is not on the wire) are surfaced
//	raw with a note, and STATUS bit-fields are decoded from the spec. Other
//	command data is surfaced as raw hex.
package pmbus

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a PMBus transaction.
type Result struct {
	Command     int    `json:"command"`
	CommandHex  string `json:"command_hex"`
	CommandName string `json:"command_name"`

	Value             string   `json:"value,omitempty"`
	StatusFlags       []string `json:"status_flags,omitempty"`
	SecurityRelevance string   `json:"security_relevance,omitempty"`

	DataHex string   `json:"data_hex,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Decode parses a PMBus transaction (command code + little-endian data) from
// hex (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("pmbus: empty input")
	}
	cmd := b[0]
	r := &Result{
		Command:     int(cmd),
		CommandHex:  fmt.Sprintf("0x%02X", cmd),
		CommandName: commandName(cmd),
	}
	data := b[1:]
	if len(data) > 0 {
		r.DataHex = hexUpper(data)
	}
	r.SecurityRelevance = security(cmd)

	switch {
	case isLinear11(cmd) && len(data) >= 2:
		v := binary.LittleEndian.Uint16(data[0:2])
		r.Value = fmt.Sprintf("%.4g %s", linear11(v), unit(cmd))
	case cmd == 0x78 && len(data) >= 1: // STATUS_BYTE
		r.StatusFlags = statusByte(data[0])
	case cmd == 0x79 && len(data) >= 2: // STATUS_WORD (low = STATUS_BYTE, high = extra)
		r.StatusFlags = append(statusByte(data[0]), statusWordHigh(data[1])...)
	case (cmd == 0x21 || cmd == 0x22 || cmd == 0x8B) && len(data) >= 2: // VOUT_COMMAND/TRIM/READ_VOUT
		r.Notes = append(r.Notes, "VOUT value is ULINEAR16 scaled by the device's VOUT_MODE exponent (not on the wire) — surfaced raw")
	}

	r.Notes = append(r.Notes, "PMBus — VOUT_COMMAND / OPERATION / VOUT_MARGIN writes set the power rail (the PMFault overvolt vector); READ_* are telemetry; STATUS_* report faults")
	return r, nil
}

func isLinear11(c byte) bool {
	switch c {
	case 0x35, 0x36, 0x88, 0x89, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x96, 0x97:
		// VIN_ON, VIN_OFF, READ_VIN, READ_IIN, READ_IOUT, READ_TEMPERATURE_1..3,
		// READ_FAN_SPEED_1, READ_POUT, READ_PIN.
		return true
	}
	return false
}

func unit(c byte) string {
	switch c {
	case 0x35, 0x36, 0x88:
		return "V"
	case 0x89, 0x8C:
		return "A"
	case 0x8D, 0x8E, 0x8F:
		return "°C"
	case 0x90:
		return "RPM"
	case 0x96, 0x97:
		return "W"
	}
	return ""
}

// linear11 decodes the PMBus LINEAR11 format: bits[15:11] = 5-bit two's-
// complement exponent, bits[10:0] = 11-bit two's-complement mantissa.
func linear11(v uint16) float64 {
	exp := int16(v) >> 11 // arithmetic shift sign-extends the 5-bit exponent
	mant := int16(v<<5) >> 5
	return float64(mant) * pow2(int(exp))
}

func pow2(e int) float64 {
	r := 1.0
	if e >= 0 {
		for i := 0; i < e; i++ {
			r *= 2
		}
	} else {
		for i := 0; i < -e; i++ {
			r /= 2
		}
	}
	return r
}

func statusByte(s byte) []string {
	bits := []struct {
		mask byte
		name string
	}{
		{0x80, "BUSY"}, {0x40, "OFF"}, {0x20, "VOUT_OV_FAULT"}, {0x10, "IOUT_OC_FAULT"},
		{0x08, "VIN_UV_FAULT"}, {0x04, "TEMPERATURE"}, {0x02, "CML (comms/memory/logic)"},
		{0x01, "NONE_OF_THE_ABOVE"},
	}
	var out []string
	for _, b := range bits {
		if s&b.mask != 0 {
			out = append(out, b.name)
		}
	}
	return out
}

func statusWordHigh(s byte) []string {
	bits := []struct {
		mask byte
		name string
	}{
		{0x80, "VOUT"}, {0x40, "IOUT/POUT"}, {0x20, "INPUT"}, {0x10, "MFR_SPECIFIC"},
		{0x08, "POWER_GOOD#"}, {0x04, "FANS"}, {0x02, "OTHER"}, {0x01, "UNKNOWN"},
	}
	var out []string
	for _, b := range bits {
		if s&b.mask != 0 {
			out = append(out, b.name)
		}
	}
	return out
}

func security(c byte) string {
	switch c {
	case 0x01:
		return "OPERATION — turns the rail on/off and selects margin mode"
	case 0x21, 0x22:
		return "sets the output voltage (VOUT_COMMAND / VOUT_TRIM) — the PMFault overvolt vector"
	case 0x25, 0x26:
		return "sets a VOUT margin (high/low) — can drive the rail out of spec"
	case 0x40, 0x44, 0x46, 0x4F:
		return "sets a fault limit (OV/UV/OC/OT) — raising it disables protection"
	case 0x10:
		return "WRITE_PROTECT — controls whether further writes are allowed"
	}
	return ""
}

func commandName(c byte) string {
	names := map[byte]string{
		0x00: "PAGE", 0x01: "OPERATION", 0x02: "ON_OFF_CONFIG", 0x03: "CLEAR_FAULTS",
		0x10: "WRITE_PROTECT", 0x15: "STORE_DEFAULT_ALL", 0x19: "CAPABILITY",
		0x20: "VOUT_MODE", 0x21: "VOUT_COMMAND", 0x22: "VOUT_TRIM", 0x24: "VOUT_MAX",
		0x25: "VOUT_MARGIN_HIGH", 0x26: "VOUT_MARGIN_LOW", 0x27: "VOUT_TRANSITION_RATE",
		0x35: "VIN_ON", 0x36: "VIN_OFF", 0x40: "VOUT_OV_FAULT_LIMIT", 0x42: "VOUT_OV_WARN_LIMIT",
		0x44: "VOUT_UV_FAULT_LIMIT", 0x46: "IOUT_OC_FAULT_LIMIT", 0x4F: "OT_FAULT_LIMIT",
		0x51: "OT_WARN_LIMIT", 0x55: "VIN_OV_FAULT_LIMIT", 0x58: "VIN_UV_FAULT_LIMIT",
		0x68: "POUT_OP_FAULT_LIMIT", 0x78: "STATUS_BYTE", 0x79: "STATUS_WORD",
		0x7A: "STATUS_VOUT", 0x7B: "STATUS_IOUT", 0x7C: "STATUS_INPUT",
		0x7D: "STATUS_TEMPERATURE", 0x7E: "STATUS_CML", 0x80: "STATUS_MFR_SPECIFIC",
		0x81: "STATUS_FANS_1_2", 0x88: "READ_VIN", 0x89: "READ_IIN", 0x8B: "READ_VOUT",
		0x8C: "READ_IOUT", 0x8D: "READ_TEMPERATURE_1", 0x8E: "READ_TEMPERATURE_2",
		0x8F: "READ_TEMPERATURE_3", 0x90: "READ_FAN_SPEED_1", 0x96: "READ_POUT",
		0x97: "READ_PIN", 0x98: "PMBUS_REVISION", 0x99: "MFR_ID", 0x9A: "MFR_MODEL",
		0x9B: "MFR_REVISION", 0x9C: "MFR_LOCATION", 0x9D: "MFR_DATE", 0x9E: "MFR_SERIAL",
		0xAD: "IC_DEVICE_ID", 0xAE: "IC_DEVICE_REV",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("unknown / manufacturer-specific command 0x%02X", c)
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("pmbus: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("pmbus: input is not valid hex: %w", err)
	}
	return b, nil
}
