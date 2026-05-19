// SPDX-License-Identifier: AGPL-3.0-or-later

// Package modbus decodes Modbus RTU and Modbus TCP frames per
// the Modbus Application Protocol Specification v1.1b3 and the
// Modbus Messaging Implementation Guide v1.0b. Both serial
// (RTU) and Ethernet (TCP) variants share the same Protocol
// Data Unit (PDU) — only the envelope differs.
//
// # Wrap-vs-native judgement
//
// Native. Modbus is a fully published industrial control
// protocol with two well-defined envelopes:
//
//   - RTU: [Address:1][Function:1][Data:0..252][CRC-16:2]
//   - TCP: [TransactionID:2][ProtocolID:2][Length:2]
//     [UnitID:1][Function:1][Data:0..252]
//
// Function codes 1..127 dispatch to documented request /
// response layouts; exception responses set the high bit of
// the function code and carry a single exception-code byte.
// CRC-16/Modbus (polynomial 0xA001, init 0xFFFF) is a textbook
// reflected bit-walker. Pasting a hex blob from Wireshark /
// Modbus Doctor / a PLC traffic capture is enough — no vendor
// SDK, no handshake.
//
// # What this package covers
//
//   - Envelope auto-detection: TCP MBAP header is recognised
//     by ProtocolID == 0x0000 + Length covering the PDU
//     remainder; everything else falls through to RTU.
//   - RTU CRC-16/Modbus validation (poly 0xA001, init 0xFFFF,
//     reflected, no final XOR) — surfaces both the captured
//     CRC and the computed expected value for forensic
//     diffing.
//   - Function code dispatch for the well-known operations:
//     0x01 Read Coils, 0x02 Read Discrete Inputs, 0x03 Read
//     Holding Registers, 0x04 Read Input Registers (all four
//     decoded for both request and response shapes),
//     0x05 Write Single Coil, 0x06 Write Single Register,
//     0x07 Read Exception Status, 0x08 Diagnostic,
//     0x0B Get Comm Event Counter, 0x0C Get Comm Event Log,
//     0x0F Write Multiple Coils, 0x10 Write Multiple
//     Registers, 0x11 Report Server ID, 0x14 Read File
//     Record, 0x15 Write File Record, 0x16 Mask Write
//     Register, 0x17 Read/Write Multiple Registers,
//     0x18 Read FIFO Queue, 0x2B Encapsulated Interface
//     (MEI).
//   - Exception responses: function code >= 0x80 → original
//     function = code & 0x7F, exception code 0x01-0x0B named
//     (Illegal Function, Illegal Data Address, Illegal Data
//     Value, Server Device Failure, Acknowledge, Server
//     Device Busy, Negative Acknowledge, Memory Parity
//     Error, Gateway Path Unavailable, Gateway Target Device
//     Failed to Respond).
//   - Request / response disambiguation via payload shape —
//     when the function code's request and response have
//     different byte layouts (e.g. read functions: request is
//     4 bytes [start:2][qty:2]; response starts with a
//     byte_count then N data bytes), the body is parsed into
//     whichever shape fits.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Modbus ASCII envelope (function code + data hex-encoded
//     with LRC; framed by ':' and CRLF). Niche compared to
//     RTU + TCP and easy to add later as a third parser.
//   - Sub-function-code MEI / diagnostic / encapsulated-
//     interface deeper decode (0x08, 0x2B): the parent
//     function is named but the sub-function payload is
//     surfaced as raw hex.
//   - Modbus over UDP, Modbus+ (the proprietary token-bus
//     dialect), and JBUS dialects — handled by users who
//     extract the standard PDU.
//   - Multi-frame reassembly — Modbus is single-frame; if a
//     PDU is split across captured packets the caller must
//     reassemble before passing in.
package modbus

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Frame is the decoded view of a Modbus RTU or TCP frame.
type Frame struct {
	HexInput      string `json:"hex_input"`
	Format        string `json:"format"`
	TransactionID *int   `json:"transaction_id,omitempty"`
	ProtocolID    *int   `json:"protocol_id,omitempty"`
	LengthField   *int   `json:"length_field,omitempty"`
	UnitID        int    `json:"unit_id"`
	FunctionCode  int    `json:"function_code"`
	FunctionHex   string `json:"function_hex"`
	FunctionName  string `json:"function_name"`
	IsException   bool   `json:"is_exception"`
	ExceptionCode *int   `json:"exception_code,omitempty"`
	ExceptionName string `json:"exception_name,omitempty"`
	DataHex       string `json:"data_hex,omitempty"`
	CRC           string `json:"crc,omitempty"`
	CRCExpected   string `json:"crc_expected,omitempty"`
	CRCValid      bool   `json:"crc_valid,omitempty"`
	Request       *Body  `json:"request,omitempty"`
	Response      *Body  `json:"response,omitempty"`
}

// Body is the per-function structured view. Only the fields
// relevant to the parsed function code are populated.
type Body struct {
	StartAddress    *int   `json:"start_address,omitempty"`
	Quantity        *int   `json:"quantity,omitempty"`
	OutputAddress   *int   `json:"output_address,omitempty"`
	OutputValue     *int   `json:"output_value,omitempty"`
	RegisterAddress *int   `json:"register_address,omitempty"`
	RegisterValue   *int   `json:"register_value,omitempty"`
	AndMask         *int   `json:"and_mask,omitempty"`
	OrMask          *int   `json:"or_mask,omitempty"`
	ByteCount       *int   `json:"byte_count,omitempty"`
	CoilStatuses    []bool `json:"coil_statuses,omitempty"`
	RegisterValues  []int  `json:"register_values,omitempty"`
	SubFunction     *int   `json:"sub_function,omitempty"`
	PayloadHex      string `json:"payload_hex,omitempty"`
}

// Decode parses a hex-encoded Modbus frame. The envelope
// (RTU vs TCP) is auto-detected: a 7-byte MBAP header
// (ProtocolID == 0x0000 + Length field matching the remainder)
// is parsed as TCP; everything else is treated as RTU.
//
// Accepts ':', '-', '_', whitespace as separators and a
// leading '0x' prefix.
func Decode(hexBlob string) (*Frame, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes dispatches on the byte buffer.
func DecodeBytes(b []byte) (*Frame, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("modbus: frame too short (%d bytes) — RTU minimum is 4 (addr+func+CRC), TCP minimum is 8", len(b))
	}
	f := &Frame{HexInput: strings.ToUpper(hex.EncodeToString(b))}
	if looksLikeTCP(b) {
		return decodeTCP(b, f)
	}
	return decodeRTU(b, f)
}

// looksLikeTCP returns true when bytes 0..6 form a valid MBAP
// header: bytes 2-3 (ProtocolID) are 0x00 0x00 and bytes 4-5
// (Length) cover the unit + function + data bytes that follow.
func looksLikeTCP(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	if b[2] != 0x00 || b[3] != 0x00 {
		return false
	}
	declared := int(b[4])<<8 | int(b[5])
	// Length covers UnitID + Function + Data (every byte from
	// offset 6 onwards).
	return declared == len(b)-6
}

func decodeTCP(b []byte, f *Frame) (*Frame, error) {
	tid := int(b[0])<<8 | int(b[1])
	pid := int(b[2])<<8 | int(b[3])
	lf := int(b[4])<<8 | int(b[5])
	f.Format = "TCP"
	f.TransactionID = &tid
	f.ProtocolID = &pid
	f.LengthField = &lf
	f.UnitID = int(b[6])
	f.FunctionCode = int(b[7])
	f.FunctionHex = fmt.Sprintf("0x%02X", f.FunctionCode)
	data := b[8:]
	classifyFunction(f, data)
	return f, nil
}

func decodeRTU(b []byte, f *Frame) (*Frame, error) {
	f.Format = "RTU"
	f.UnitID = int(b[0])
	f.FunctionCode = int(b[1])
	f.FunctionHex = fmt.Sprintf("0x%02X", f.FunctionCode)
	// CRC is the last 2 bytes (little-endian).
	if len(b) < 4 {
		return nil, fmt.Errorf("modbus: RTU frame must be at least 4 bytes")
	}
	captured := uint16(b[len(b)-2]) | uint16(b[len(b)-1])<<8
	expected := crc16(b[:len(b)-2])
	// Display CRC in wire-byte order (low byte first) — this
	// matches how Modbus tools and packet captures present the
	// trailing 2 bytes, so an operator pasting a hex dump sees
	// the same hex in this field.
	f.CRC = fmt.Sprintf("%02X%02X", b[len(b)-2], b[len(b)-1])
	f.CRCExpected = fmt.Sprintf("%02X%02X", byte(expected), byte(expected>>8))
	f.CRCValid = captured == expected
	data := b[2 : len(b)-2]
	classifyFunction(f, data)
	return f, nil
}

// classifyFunction names the function and attempts a structured
// body decode based on the documented per-function layout. For
// codes where the request and response have distinct shapes,
// we attempt both and surface whichever matches the payload
// length.
func classifyFunction(f *Frame, data []byte) {
	f.IsException = f.FunctionCode&0x80 != 0
	originalFC := f.FunctionCode & 0x7F
	if f.IsException {
		f.FunctionName = "Exception Response (" + functionCodeName(originalFC) + ")"
		if len(data) >= 1 {
			ec := int(data[0])
			f.ExceptionCode = &ec
			f.ExceptionName = exceptionCodeName(ec)
		}
		f.DataHex = strings.ToUpper(hex.EncodeToString(data))
		return
	}
	f.FunctionName = functionCodeName(f.FunctionCode)
	f.DataHex = strings.ToUpper(hex.EncodeToString(data))

	switch f.FunctionCode {
	case 0x01, 0x02, 0x03, 0x04:
		// Read coils / discrete / holding / input registers
		if len(data) == 4 {
			// Request: [start:2][qty:2]
			start := int(data[0])<<8 | int(data[1])
			qty := int(data[2])<<8 | int(data[3])
			f.Request = &Body{StartAddress: &start, Quantity: &qty}
		}
		if len(data) >= 1 && int(data[0]) == len(data)-1 {
			// Response: [byte_count:1][data:N]
			bc := int(data[0])
			body := &Body{ByteCount: &bc, PayloadHex: strings.ToUpper(hex.EncodeToString(data[1:]))}
			switch f.FunctionCode {
			case 0x01, 0x02:
				body.CoilStatuses = unpackCoilBits(data[1:], bc*8)
			case 0x03, 0x04:
				body.RegisterValues = unpackRegisters(data[1:])
			}
			f.Response = body
		}
	case 0x05:
		// Write Single Coil — same shape for request and
		// response. Output value 0xFF00 = ON, 0x0000 = OFF.
		if len(data) == 4 {
			addr := int(data[0])<<8 | int(data[1])
			val := int(data[2])<<8 | int(data[3])
			body := &Body{OutputAddress: &addr, OutputValue: &val}
			f.Request = body
			f.Response = body
		}
	case 0x06:
		// Write Single Register — same shape for request and
		// response.
		if len(data) == 4 {
			addr := int(data[0])<<8 | int(data[1])
			val := int(data[2])<<8 | int(data[3])
			body := &Body{RegisterAddress: &addr, RegisterValue: &val}
			f.Request = body
			f.Response = body
		}
	case 0x0F:
		// Write Multiple Coils
		// Request: [start:2][qty:2][bc:1][values:N]
		// Response: [start:2][qty:2]
		if len(data) >= 5 && int(data[4]) == len(data)-5 {
			start := int(data[0])<<8 | int(data[1])
			qty := int(data[2])<<8 | int(data[3])
			bc := int(data[4])
			f.Request = &Body{
				StartAddress: &start,
				Quantity:     &qty,
				ByteCount:    &bc,
				CoilStatuses: unpackCoilBits(data[5:], qty),
			}
		} else if len(data) == 4 {
			start := int(data[0])<<8 | int(data[1])
			qty := int(data[2])<<8 | int(data[3])
			f.Response = &Body{StartAddress: &start, Quantity: &qty}
		}
	case 0x10:
		// Write Multiple Registers
		// Request: [start:2][qty:2][bc:1][values:2*qty]
		// Response: [start:2][qty:2]
		if len(data) >= 5 && int(data[4]) == len(data)-5 {
			start := int(data[0])<<8 | int(data[1])
			qty := int(data[2])<<8 | int(data[3])
			bc := int(data[4])
			f.Request = &Body{
				StartAddress:   &start,
				Quantity:       &qty,
				ByteCount:      &bc,
				RegisterValues: unpackRegisters(data[5:]),
			}
		} else if len(data) == 4 {
			start := int(data[0])<<8 | int(data[1])
			qty := int(data[2])<<8 | int(data[3])
			f.Response = &Body{StartAddress: &start, Quantity: &qty}
		}
	case 0x16:
		// Mask Write Register
		// Request and Response: [addr:2][AND mask:2][OR mask:2]
		if len(data) == 6 {
			addr := int(data[0])<<8 | int(data[1])
			and := int(data[2])<<8 | int(data[3])
			or := int(data[4])<<8 | int(data[5])
			body := &Body{RegisterAddress: &addr, AndMask: &and, OrMask: &or}
			f.Request = body
			f.Response = body
		}
	case 0x08:
		// Diagnostic — surface sub-function and raw data
		if len(data) >= 2 {
			sub := int(data[0])<<8 | int(data[1])
			f.Request = &Body{
				SubFunction: &sub,
				PayloadHex:  strings.ToUpper(hex.EncodeToString(data[2:])),
			}
		}
	case 0x2B:
		// Encapsulated Interface Transport (MEI) — sub-function
		// 0x0E is Read Device Identification, the most common.
		if len(data) >= 1 {
			sub := int(data[0])
			f.Request = &Body{
				SubFunction: &sub,
				PayloadHex:  strings.ToUpper(hex.EncodeToString(data[1:])),
			}
		}
	}
}

// unpackCoilBits walks a byte buffer (LSB-first per byte) and
// returns the first `qty` coil states as bools.
func unpackCoilBits(data []byte, qty int) []bool {
	out := make([]bool, 0, qty)
	for i := 0; i < qty; i++ {
		byteIdx := i / 8
		if byteIdx >= len(data) {
			break
		}
		bitIdx := i % 8
		out = append(out, (data[byteIdx]>>bitIdx)&0x01 == 1)
	}
	return out
}

// unpackRegisters walks a byte buffer and returns each 16-bit
// big-endian word as an int (Modbus uses big-endian register
// ordering on the wire).
func unpackRegisters(data []byte) []int {
	out := make([]int, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		out = append(out, int(data[i])<<8|int(data[i+1]))
	}
	return out
}

// crc16 implements the Modbus CRC-16: polynomial 0xA001
// (the bit-reversal of 0x8005, x^16 + x^15 + x^2 + 1), init
// 0xFFFF, reflected, no final XOR. The result is appended to
// the RTU frame in little-endian byte order.
func crc16(data []byte) uint16 {
	const poly = uint16(0xA001)
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&0x01 != 0 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

func functionCodeName(fc int) string {
	switch fc {
	case 0x01:
		return "Read Coils"
	case 0x02:
		return "Read Discrete Inputs"
	case 0x03:
		return "Read Holding Registers"
	case 0x04:
		return "Read Input Registers"
	case 0x05:
		return "Write Single Coil"
	case 0x06:
		return "Write Single Register"
	case 0x07:
		return "Read Exception Status"
	case 0x08:
		return "Diagnostic"
	case 0x0B:
		return "Get Comm Event Counter"
	case 0x0C:
		return "Get Comm Event Log"
	case 0x0F:
		return "Write Multiple Coils"
	case 0x10:
		return "Write Multiple Registers"
	case 0x11:
		return "Report Server ID"
	case 0x14:
		return "Read File Record"
	case 0x15:
		return "Write File Record"
	case 0x16:
		return "Mask Write Register"
	case 0x17:
		return "Read/Write Multiple Registers"
	case 0x18:
		return "Read FIFO Queue"
	case 0x2B:
		return "Encapsulated Interface Transport (MEI)"
	}
	return fmt.Sprintf("Reserved / vendor-specific (0x%02X)", fc)
}

func exceptionCodeName(ec int) string {
	switch ec {
	case 0x01:
		return "Illegal Function"
	case 0x02:
		return "Illegal Data Address"
	case 0x03:
		return "Illegal Data Value"
	case 0x04:
		return "Server Device Failure"
	case 0x05:
		return "Acknowledge"
	case 0x06:
		return "Server Device Busy"
	case 0x07:
		return "Negative Acknowledge"
	case 0x08:
		return "Memory Parity Error"
	case 0x0A:
		return "Gateway Path Unavailable"
	case 0x0B:
		return "Gateway Target Device Failed to Respond"
	}
	return fmt.Sprintf("Reserved (exception 0x%02X)", ec)
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("modbus: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("modbus: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
