// SPDX-License-Identifier: AGPL-3.0-or-later

// Package obd2 decodes OBD-II / SAE J1979 Mode-01 ("show current data")
// responses into engineering values — turning the raw measurement bytes of
// a diagnostic response into RPM, speed, coolant temperature, MAF, etc. via
// the standard per-PID formulas.
//
// # Wrap-vs-native judgement
//
// Native. The J1979 Mode-01 PID set and its conversion formulas are public,
// exact, and transport-independent (the same A/B-byte formulas apply whether
// the response arrived over CAN/ISO 15765, J1850 VPW/PWM, or ISO 9141) —
// documented in SAE J1979 and reproduced identically by python-OBD,
// ELM327-based tools, and the widely-cited OBD-II PID tables. Decoding is a
// static table of (name, unit, byte-count, formula) entries; no hardware, no
// vendor SDK, no probing. The existing internal/j1850 decoder names the PID
// but stops at the raw payload bytes ("Engine RPM" + payload_hex) — this
// computes the value those bytes encode, and works for any transport since
// the caller supplies the already-extracted Mode-01 payload.
//
// # No confidently-wrong output
//
// Only PIDs whose formula is in the table are given a value; an unknown PID,
// or a known PID with too few data bytes, is surfaced with its raw hex (and
// name when known) plus a note — never a guessed number. Manufacturer-
// specific PIDs and the bitmask/string PIDs (e.g. 0x00/0x20 "PIDs supported",
// 0x03 fuel status, VIN) are intentionally left to the raw bytes.
package obd2

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Mode01Response is the service byte of a Mode-01 ("current data") response
// — the request mode 0x01 plus 0x40.
const Mode01Response = 0x41

// Reading is the decoded view of one Mode-01 PID.
type Reading struct {
	PID     int      `json:"pid"`
	PIDHex  string   `json:"pid_hex"`
	Name    string   `json:"name"`
	RawHex  string   `json:"raw_hex"`
	Value   *float64 `json:"value,omitempty"`
	Unit    string   `json:"unit,omitempty"`
	Formula string   `json:"formula,omitempty"`
	Note    string   `json:"note,omitempty"`
}

type pidInfo struct {
	name    string
	unit    string
	bytes   int
	formula string
	fn      func(d []byte) float64
}

// a/b/c/d name the first four data bytes the J1979 formulas reference.
func a(d []byte) float64 { return float64(d[0]) }
func b(d []byte) float64 { return float64(d[1]) }

// s16 reads the first two data bytes as a signed two's-complement 16-bit value,
// for the PIDs whose J1979 range is signed (e.g. evap-system vapor pressure).
func s16(d []byte) float64 { return float64(int16(uint16(d[0])<<8 | uint16(d[1]))) }

var pidTable = map[int]pidInfo{
	0x04: {"Calculated engine load", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x05: {"Engine coolant temperature", "°C", 1, "A-40", func(d []byte) float64 { return a(d) - 40 }},
	0x06: {"Short term fuel trim (bank 1)", "%", 1, "(A-128)*100/128", func(d []byte) float64 { return (a(d) - 128) * 100 / 128 }},
	0x07: {"Long term fuel trim (bank 1)", "%", 1, "(A-128)*100/128", func(d []byte) float64 { return (a(d) - 128) * 100 / 128 }},
	0x08: {"Short term fuel trim (bank 2)", "%", 1, "(A-128)*100/128", func(d []byte) float64 { return (a(d) - 128) * 100 / 128 }},
	0x09: {"Long term fuel trim (bank 2)", "%", 1, "(A-128)*100/128", func(d []byte) float64 { return (a(d) - 128) * 100 / 128 }},
	0x0A: {"Fuel pressure", "kPa", 1, "A*3", func(d []byte) float64 { return a(d) * 3 }},
	0x0B: {"Intake manifold absolute pressure", "kPa", 1, "A", func(d []byte) float64 { return a(d) }},
	0x0C: {"Engine RPM", "rpm", 2, "((A*256)+B)/4", func(d []byte) float64 { return (a(d)*256 + b(d)) / 4 }},
	0x0D: {"Vehicle speed", "km/h", 1, "A", func(d []byte) float64 { return a(d) }},
	0x0E: {"Timing advance", "° before TDC", 1, "(A/2)-64", func(d []byte) float64 { return a(d)/2 - 64 }},
	0x0F: {"Intake air temperature", "°C", 1, "A-40", func(d []byte) float64 { return a(d) - 40 }},
	0x10: {"MAF air flow rate", "g/s", 2, "((A*256)+B)/100", func(d []byte) float64 { return (a(d)*256 + b(d)) / 100 }},
	0x11: {"Throttle position", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x1F: {"Run time since engine start", "s", 2, "(A*256)+B", func(d []byte) float64 { return a(d)*256 + b(d) }},
	0x21: {"Distance with MIL on", "km", 2, "(A*256)+B", func(d []byte) float64 { return a(d)*256 + b(d) }},
	0x22: {"Fuel rail pressure (rel. manifold vacuum)", "kPa", 2, "((A*256)+B)*0.079", func(d []byte) float64 { return (a(d)*256 + b(d)) * 0.079 }},
	0x23: {"Fuel rail gauge pressure", "kPa", 2, "((A*256)+B)*10", func(d []byte) float64 { return (a(d)*256 + b(d)) * 10 }},
	0x2C: {"Commanded EGR", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x2F: {"Fuel tank level input", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x31: {"Distance since codes cleared", "km", 2, "(A*256)+B", func(d []byte) float64 { return a(d)*256 + b(d) }},
	0x32: {"Evap system vapor pressure", "Pa", 2, "signed(A*256+B)/4", func(d []byte) float64 { return s16(d) / 4 }},
	0x33: {"Absolute barometric pressure", "kPa", 1, "A", func(d []byte) float64 { return a(d) }},
	0x3C: {"Catalyst temperature (bank 1, sensor 1)", "°C", 2, "((A*256)+B)/10-40", func(d []byte) float64 { return (a(d)*256+b(d))/10 - 40 }},
	0x3D: {"Catalyst temperature (bank 2, sensor 1)", "°C", 2, "((A*256)+B)/10-40", func(d []byte) float64 { return (a(d)*256+b(d))/10 - 40 }},
	0x3E: {"Catalyst temperature (bank 1, sensor 2)", "°C", 2, "((A*256)+B)/10-40", func(d []byte) float64 { return (a(d)*256+b(d))/10 - 40 }},
	0x3F: {"Catalyst temperature (bank 2, sensor 2)", "°C", 2, "((A*256)+B)/10-40", func(d []byte) float64 { return (a(d)*256+b(d))/10 - 40 }},
	0x42: {"Control module voltage", "V", 2, "((A*256)+B)/1000", func(d []byte) float64 { return (a(d)*256 + b(d)) / 1000 }},
	0x43: {"Absolute load value", "%", 2, "((A*256)+B)*100/255", func(d []byte) float64 { return (a(d)*256 + b(d)) * 100 / 255 }},
	0x44: {"Commanded equivalence ratio (lambda)", "", 2, "((A*256)+B)/32768", func(d []byte) float64 { return (a(d)*256 + b(d)) / 32768 }},
	0x45: {"Relative throttle position", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x46: {"Ambient air temperature", "°C", 1, "A-40", func(d []byte) float64 { return a(d) - 40 }},
	0x47: {"Absolute throttle position B", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x49: {"Accelerator pedal position D", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x4A: {"Accelerator pedal position E", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x4C: {"Commanded throttle actuator", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x4D: {"Time run with MIL on", "min", 2, "(A*256)+B", func(d []byte) float64 { return a(d)*256 + b(d) }},
	0x4E: {"Time since trouble codes cleared", "min", 2, "(A*256)+B", func(d []byte) float64 { return a(d)*256 + b(d) }},
	0x52: {"Ethanol fuel", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x59: {"Fuel rail absolute pressure", "kPa", 2, "((A*256)+B)*10", func(d []byte) float64 { return (a(d)*256 + b(d)) * 10 }},
	0x5A: {"Relative accelerator pedal position", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x5B: {"Hybrid/EV battery pack remaining life", "%", 1, "A*100/255", func(d []byte) float64 { return a(d) * 100 / 255 }},
	0x5C: {"Engine oil temperature", "°C", 1, "A-40", func(d []byte) float64 { return a(d) - 40 }},
	0x5D: {"Fuel injection timing", "°", 2, "((A*256)+B)/128-210", func(d []byte) float64 { return (a(d)*256+b(d))/128 - 210 }},
	0x5E: {"Engine fuel rate", "L/h", 2, "((A*256)+B)/20", func(d []byte) float64 { return (a(d)*256 + b(d)) / 20 }},
}

// DecodePID decodes one Mode-01 PID from its measurement bytes, computing
// the engineering value via the J1979 formula when the PID and byte count
// are known.
func DecodePID(pid int, data []byte) *Reading {
	r := &Reading{
		PID:    pid,
		PIDHex: fmt.Sprintf("0x%02X", pid),
		RawHex: strings.ToUpper(hex.EncodeToString(data)),
	}
	info, ok := pidTable[pid]
	if !ok {
		r.Name = "Unknown / unsupported PID"
		r.Note = "no formula in the Mode-01 table; raw bytes surfaced (manufacturer-specific, bitmask, or string PID)"
		return r
	}
	r.Name = info.name
	r.Unit = info.unit
	r.Formula = info.formula
	if len(data) < info.bytes {
		r.Note = fmt.Sprintf("need %d data byte(s) for %s; got %d", info.bytes, info.name, len(data))
		return r
	}
	v := info.fn(data[:info.bytes])
	r.Value = &v
	return r
}

// DecodeResponse parses a Mode-01 response payload — the service byte
// (0x41) + PID + measurement bytes — and decodes the PID. A request byte
// (0x01) is also accepted (named, no value, since a request carries no
// measurement). Separators and a 0x prefix are tolerated.
func DecodeResponse(hexStr string) (*Reading, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(hexStr))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("obd2: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("obd2: invalid hex: %w", err)
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("obd2: need at least a service byte + PID; got %d byte(s)", len(b))
	}
	mode := b[0]
	if mode != Mode01Response && mode != 0x01 {
		return nil, fmt.Errorf("obd2: service byte 0x%02X is not Mode-01 (request 0x01 / response 0x41); only Mode-01 current-data is decoded", mode)
	}
	pid := int(b[1])
	data := b[2:]
	if mode == 0x01 {
		// A request carries no measurement; just name the PID.
		r := DecodePID(pid, nil)
		r.RawHex = ""
		r.Value = nil
		r.Note = "Mode-01 request (no measurement bytes)"
		return r, nil
	}
	return DecodePID(pid, data), nil
}
