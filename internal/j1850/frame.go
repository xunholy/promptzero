// Package j1850 decodes SAE J1850 VPW (Variable Pulse Width)
// and PWM (Pulse Width Modulation) frames — the legacy OBD-II
// protocol used by GM and Ford vehicles before they migrated
// to CAN bus around 2008. Pure offline parser; no transport,
// no hardware.
//
// Wrap-vs-native judgement: SAE J1850 + SAE J2178 + ISO/SAE
// 15765 are all fully public specs. The walker is bit-level
// decoding over a 3-byte header + 0-7 data bytes + 1-byte CRC.
// Wrapping a FAP for this would require an SD-card install +
// a firmware-fork dependency for a pure parser. Native delivers
// offline analysis — operators paste a captured J1850 frame
// from a Macchina M2 / OBDLink LX / classic-car OBD-II
// adapter and inspect every field without re-connecting to
// the vehicle.
//
// Pairs with the existing canbus_* tools — those handle CAN
// bus (post-2008 vehicles); this Spec covers the legacy
// J1850 buses still found on classic-car restoration / older
// fleet analysis workflows.
//
// What this package covers:
//   - SAE J1850 header decode: 3-byte header with priority (3
//     bits) + header type (1 bit) + ID (4 bits) + target ECU
//     (8 bits) + source ECU (8 bits)
//   - Standard ECU address lookup (Engine Control Module /
//     Transmission Control Module / Body Control Module / ABS
//     / Climate Control / Diagnostic Tool / etc.)
//   - Data payload extraction (0-7 bytes for single-frame
//     format; HFM multi-frame format flagged but not
//     reassembled)
//   - Service ID (SID) + Parameter ID (PID) recognition for
//     OBD-II Mode 1-9 with documented PID name lookup for the
//     most common diagnostic queries (engine load / coolant
//     temp / RPM / vehicle speed / throttle / fuel level / etc.)
//   - CRC-8 validation per SAE J1850 §5.4 (polynomial 0x1D
//     with init 0xFF and final XOR 0xFF)
//
// What this package does NOT cover (deliberately out of scope):
//   - Bit-stream demodulation (operators bring pre-deframed
//     bytes from their OBD-II adapter)
//   - Multi-frame HFM message reassembly (flagged but not
//     processed — the SAE J2178 multi-frame format wraps a
//     single decoded payload across multiple physical frames)
//   - GMLAN extension (a GM-specific J1850 superset; same
//     header but extended PID space)
//   - Other diagnostic protocols (KWP2000, UDS, ISO-TP)
package j1850

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Frame is the top-level decoded J1850 message.
type Frame struct {
	// PriorityField is bits 7..5 of byte 0 (3 bits).
	Priority int `json:"priority"`
	// HeaderType is bit 4 of byte 0 — 0 = 3-byte consolidated
	// header (standard), 1 = 1-byte header (rare).
	HeaderType int `json:"header_type"`
	// ID is bits 3..0 of byte 0 (4 bits) — function/message ID
	// shared with the per-OEM service catalog.
	ID int `json:"id"`
	// TargetHex is byte 1 — the destination ECU address.
	TargetHex     string `json:"target_address_hex"`
	TargetAddress int    `json:"target_address"`
	TargetName    string `json:"target_name,omitempty"`
	// SourceHex is byte 2 — the source ECU address.
	SourceHex     string `json:"source_address_hex"`
	SourceAddress int    `json:"source_address"`
	SourceName    string `json:"source_name,omitempty"`
	// DataHex is the payload (bytes 3 to end-1, where end-1
	// is the CRC byte).
	DataHex string `json:"data_hex,omitempty"`
	// CRC is the last-byte checksum.
	CRC         int  `json:"crc"`
	CRCExpected int  `json:"crc_expected"`
	CRCValid    bool `json:"crc_valid"`
	// OBDII is populated when the payload looks like an OBD-II
	// service request or response (i.e. data[0] is a known SID).
	OBDII *OBDIIDecoded `json:"obdii,omitempty"`
}

// OBDIIDecoded is the structured view of an OBD-II request /
// response.
type OBDIIDecoded struct {
	// Mode is the OBD-II Service ID (Mode). For requests, the
	// raw value (0x01..0x0A). For responses, the request mode
	// + 0x40 (so 0x41 = Mode 1 response, 0x43 = Mode 3
	// response).
	Mode     int    `json:"mode"`
	ModeName string `json:"mode_name"`
	// IsResponse reports whether the high bit of Mode is set
	// (Mode + 0x40 = response).
	IsResponse bool `json:"is_response"`
	// PID is the Parameter ID (data[1]) for Mode 1/2/9 requests/
	// responses. nil for modes that don't use a PID.
	PID     *int   `json:"pid,omitempty"`
	PIDName string `json:"pid_name,omitempty"`
	// PayloadHex is the data after Mode + optional PID
	// (i.e. the actual measurement bytes for a response).
	PayloadHex string `json:"payload_hex,omitempty"`
}

// Decode parses a hex-encoded J1850 frame (3-byte header +
// data + 1-byte CRC). Tolerates ':' / '-' / '_' / whitespace
// separators.
func Decode(hexBlob string) (Frame, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Frame{}, fmt.Errorf("j1850: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Frame{}, fmt.Errorf("j1850: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant of Decode.
func DecodeBytes(b []byte) (Frame, error) {
	// Minimum: 3-byte header + 1-byte CRC = 4 bytes.
	if len(b) < 4 {
		return Frame{}, fmt.Errorf("j1850: frame %d bytes < 4-byte minimum (header + CRC)", len(b))
	}
	// Maximum: 3 header + 7 data + 1 CRC = 11 bytes
	if len(b) > 11 {
		return Frame{}, fmt.Errorf("j1850: frame %d bytes > 11-byte single-frame maximum (HFM multi-frame not supported)", len(b))
	}
	hdr := b[0]
	target := b[1]
	source := b[2]
	dataLen := len(b) - 4 // 3-byte header + data + 1-byte CRC
	data := b[3 : 3+dataLen]
	crc := b[len(b)-1]

	out := Frame{
		Priority:      int(hdr>>5) & 0x07,
		HeaderType:    int(hdr>>4) & 0x01,
		ID:            int(hdr & 0x0F),
		TargetHex:     fmt.Sprintf("%02X", target),
		TargetAddress: int(target),
		TargetName:    ecuName(target),
		SourceHex:     fmt.Sprintf("%02X", source),
		SourceAddress: int(source),
		SourceName:    ecuName(source),
		CRC:           int(crc),
	}
	if dataLen > 0 {
		out.DataHex = hexString(data)
	}
	// CRC validation
	out.CRCExpected = int(computeCRC(b[:len(b)-1]))
	out.CRCValid = byte(out.CRCExpected) == crc
	// OBD-II detection: data[0] is the mode byte
	if len(data) > 0 {
		out.OBDII = decodeOBDII(data)
	}
	return out, nil
}

// decodeOBDII inspects the data payload and surfaces the OBD-II
// view when data[0] matches a documented mode. Returns nil
// when the payload doesn't look like OBD-II.
func decodeOBDII(data []byte) *OBDIIDecoded {
	mode := int(data[0])
	rawMode := mode & 0x3F
	isResponse := mode >= 0x40
	if rawMode < 0x01 || rawMode > 0x0A {
		return nil
	}
	out := &OBDIIDecoded{
		Mode:       mode,
		ModeName:   obdiiModeName(rawMode, isResponse),
		IsResponse: isResponse,
	}
	// Modes 1, 2, 9 carry a PID byte at data[1]
	if (rawMode == 0x01 || rawMode == 0x02 || rawMode == 0x09) && len(data) > 1 {
		pid := int(data[1])
		out.PID = &pid
		if rawMode == 0x01 {
			out.PIDName = mode1PIDName(byte(pid))
		}
		if len(data) > 2 {
			out.PayloadHex = hexString(data[2:])
		}
	} else if len(data) > 1 {
		out.PayloadHex = hexString(data[1:])
	}
	return out
}

// computeCRC computes the SAE J1850 CRC-8 over the message
// bytes (header + data) — polynomial 0x1D, init 0xFF, final
// XOR 0xFF. Per SAE J1850 §5.4.
func computeCRC(b []byte) byte {
	crc := byte(0xFF)
	for _, c := range b {
		crc ^= c
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x1D
			} else {
				crc <<= 1
			}
		}
	}
	return crc ^ 0xFF
}

// ecuName maps standard J1850 ECU addresses to canonical
// names. Source: SAE J2178-1 + GM/Ford service manuals.
func ecuName(addr byte) string {
	switch addr {
	case 0x10:
		return "Engine Control Module (ECM)"
	case 0x18:
		return "Transmission Control Module (TCM)"
	case 0x28:
		return "Body Control Module (BCM)"
	case 0x40:
		return "Anti-lock Brake Module (ABS)"
	case 0x48:
		return "Air Bag Module (SRS)"
	case 0x60:
		return "HVAC / Climate Control"
	case 0x68:
		return "Driver Door Module"
	case 0x70:
		return "Instrument Cluster"
	case 0x80:
		return "Radio / Entertainment"
	case 0xA0:
		return "Steering Wheel / Cruise Control"
	case 0xF0:
		return "Diagnostic Trouble Code (DTC) functional address"
	case 0xF1:
		return "Diagnostic Tool / Scan Tool"
	case 0xFE:
		return "Broadcast (all modules)"
	}
	return ""
}

// obdiiModeName maps OBD-II Mode (Service ID) to its canonical
// name per SAE J1979.
func obdiiModeName(mode int, isResponse bool) string {
	var name string
	switch mode {
	case 0x01:
		name = "Show current data"
	case 0x02:
		name = "Show freeze frame data"
	case 0x03:
		name = "Show stored Diagnostic Trouble Codes"
	case 0x04:
		name = "Clear DTCs and stored values"
	case 0x05:
		name = "Test results, oxygen sensor monitoring"
	case 0x06:
		name = "Test results, other component / system monitoring"
	case 0x07:
		name = "Show pending DTCs (detected during current/last drive cycle)"
	case 0x08:
		name = "Control operation of on-board component/system"
	case 0x09:
		name = "Request vehicle information"
	case 0x0A:
		name = "Permanent DTCs (cleared DTCs)"
	default:
		return ""
	}
	if isResponse {
		return name + " (response)"
	}
	return name + " (request)"
}

// mode1PIDName maps OBD-II Mode 1 PIDs to their canonical
// names per SAE J1979. Covers the most-commonly-used diagnostic
// PIDs operators encounter on real vehicles.
func mode1PIDName(pid byte) string {
	switch pid {
	case 0x00:
		return "PIDs supported [0x01-0x20]"
	case 0x01:
		return "Monitor status since DTCs cleared"
	case 0x02:
		return "Freeze DTC"
	case 0x03:
		return "Fuel system status"
	case 0x04:
		return "Calculated engine load"
	case 0x05:
		return "Engine coolant temperature"
	case 0x06:
		return "Short-term fuel trim bank 1"
	case 0x07:
		return "Long-term fuel trim bank 1"
	case 0x08:
		return "Short-term fuel trim bank 2"
	case 0x09:
		return "Long-term fuel trim bank 2"
	case 0x0A:
		return "Fuel pressure"
	case 0x0B:
		return "Intake manifold absolute pressure"
	case 0x0C:
		return "Engine RPM"
	case 0x0D:
		return "Vehicle speed"
	case 0x0E:
		return "Timing advance"
	case 0x0F:
		return "Intake air temperature"
	case 0x10:
		return "MAF air flow rate"
	case 0x11:
		return "Throttle position"
	case 0x12:
		return "Commanded secondary air status"
	case 0x13:
		return "Oxygen sensors present (in 2 banks)"
	case 0x1C:
		return "OBD standards compliance"
	case 0x1F:
		return "Run time since engine start"
	case 0x20:
		return "PIDs supported [0x21-0x40]"
	case 0x21:
		return "Distance traveled with MIL on"
	case 0x22:
		return "Fuel rail pressure (relative to manifold vacuum)"
	case 0x23:
		return "Fuel rail gauge pressure"
	case 0x2C:
		return "Commanded EGR"
	case 0x2D:
		return "EGR error"
	case 0x2E:
		return "Commanded evaporative purge"
	case 0x2F:
		return "Fuel tank level input"
	case 0x30:
		return "Warm-ups since codes cleared"
	case 0x31:
		return "Distance traveled since codes cleared"
	case 0x33:
		return "Absolute barometric pressure"
	case 0x40:
		return "PIDs supported [0x41-0x60]"
	case 0x42:
		return "Control module voltage"
	case 0x43:
		return "Absolute engine load"
	case 0x44:
		return "Commanded equivalence ratio (lambda)"
	case 0x45:
		return "Relative throttle position"
	case 0x46:
		return "Ambient air temperature"
	case 0x47:
		return "Absolute throttle position B"
	case 0x4C:
		return "Commanded throttle actuator"
	case 0x4D:
		return "Time run with MIL on"
	case 0x4E:
		return "Time since trouble codes cleared"
	case 0x51:
		return "Fuel type"
	case 0x52:
		return "Ethanol fuel %"
	case 0x5B:
		return "Hybrid battery pack remaining life"
	case 0x5C:
		return "Engine oil temperature"
	}
	return ""
}

// hexString renders bytes as uppercase no-separator hex.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// stripSeparators mirrors the convention across our pure-decoder
// packages.
func stripSeparators(s string) string {
	repl := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		":", "",
		"-", "",
		"_", "",
	)
	return repl.Replace(strings.TrimSpace(s))
}
