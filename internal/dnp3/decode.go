// Package dnp3 decodes DNP3 (Distributed Network Protocol 3)
// frames per IEEE 1815-2012. DNP3 is the dominant utility-SCADA
// protocol in North American power-grid, water, and oil-and-gas
// telemetry — the field-bus protocol an attacker tapping into a
// substation, pumping station, or pipeline RTU is most likely to
// see on the wire.
//
// Operationally, DNP3 carries:
//
//   - **Master ↔ outstation polls** ("read class 1 events" /
//     "operate breaker") across leased lines, IP/TCP (port 20000)
//     or IP/UDP between SCADA control centres and field RTUs.
//   - **Unsolicited responses** from outstations reporting state
//     changes (breaker open, transformer over-temperature) without
//     waiting for a poll — a defining DNP3 capability.
//   - **Time synchronisation + freeze-at-time** for substation
//     event sequencing (used alongside PTP in IEC 61850
//     deployments where DNP3 still owns the SCADA application
//     layer).
//   - **File transfer** for outstation firmware updates and
//     configuration drops (function codes 0x19–0x1E).
//   - **Secure Authentication** (IEEE 1815-2012 §7, function codes
//     0x20 / 0x21 / 0x83) — HMAC-SHA256 based message
//     authentication retrofitted onto the protocol.
//
// Wrap-vs-native judgement
//
//	Native. IEEE 1815-2012 is fully public; DNP3 has a tight
//	10-byte data-link header followed by a transport byte, a 2-
//	or 4-byte application header, and a series of objects whose
//	per-group/variation prefixing rules are documented but
//	deferred (object decoding is dataset-specific). No crypto at
//	the parse layer — Secure Authentication payloads are
//	surfaced as hex.
//
// What this package covers
//
//   - **Data-link layer header** (IEEE 1815-2012 §10.3, 10 bytes;
//     little-endian where multi-byte):
//
//   - bytes 0-1: Start = 0x05 0x64 (sync).
//
//   - byte 2: Length (count of bytes that follow the Length
//     field excluding CRCs — so Control + Dest + Src + user
//     data; range 5-255).
//
//   - byte 3: **Control field** — bit 7 DIR (1 = master-to-
//     outstation direction), bit 6 PRM (1 = primary
//     message, 0 = secondary), bit 5 FCB (frame count bit;
//     toggles on retries) or DFC (data flow control; ack-
//     buffer-overflow indicator) for secondary, bit 4 FCV
//     (frame count valid) or RES (reserved), bits 3-0
//     primary or secondary function code. The decoder
//     surfaces all five fields and the 4-bit code name.
//
//   - bytes 4-5: Destination address (uint16 LE).
//
//   - bytes 6-7: Source address (uint16 LE).
//
//   - bytes 8-9: Header CRC (uint16 LE; CRC-16 with
//     polynomial 0x3D65 over the 8-byte header; surfaced
//     as hex but not re-computed).
//
//   - **5-entry primary function code name table** (IEEE 1815-2012
//     §10.3.3): 0 RESET_LINK_STATES / 1 TEST_LINK_STATES / 2
//     CONFIRMED_USER_DATA / 3 UNCONFIRMED_USER_DATA / 9
//     REQUEST_LINK_STATUS.
//
//   - **4-entry secondary function code name table**: 0 ACK / 1
//     NACK / 11 LINK_STATUS / 14 NOT_FUNCTIONING.
//
//   - **User-data block walker** (IEEE 1815-2012 §10.3.2.5): user
//     data following the 10-byte header is split into blocks of
//     16 bytes each (last block may be shorter) followed by a
//     2-byte block CRC. The decoder strips the per-block CRCs
//     and reconstructs the user-data byte stream for higher-
//     layer parsing.
//
//   - **Transport function byte** (IEEE 1815-2012 §8.2, 1 byte at
//     the head of the reconstructed user-data stream): bit 7 FIN
//     (final segment of an application fragment chain), bit 6
//     FIR (first segment), bits 5-0 sequence number.
//
//   - **Application header** (IEEE 1815-2012 §4.2.2): byte 0 =
//     Application Control (bit 7 FIR + bit 6 FIN + bit 5 CON
//     (confirm requested) + bit 4 UNS (unsolicited) + bits 3-0
//     SEQ); byte 1 = Function Code; for responses (function
//     codes 0x81 / 0x82 / 0x83) bytes 2-3 = IIN (Internal
//     Indication, 16-bit LE).
//
//   - **20-entry application function code name table**
//     (selected high-runners from IEEE 1815-2012 §6.2): 0x00
//     CONFIRM / 0x01 READ / 0x02 WRITE / 0x03 SELECT / 0x04
//     OPERATE / 0x05 DIRECT_OPERATE / 0x06 DIRECT_OPERATE_NR /
//     0x07 IMMED_FREEZE / 0x08 IMMED_FREEZE_NR / 0x09
//     FREEZE_CLEAR / 0x0A FREEZE_CLEAR_NR / 0x0B FREEZE_AT_TIME
//     / 0x0D COLD_RESTART / 0x0E WARM_RESTART / 0x14
//     ENABLE_UNSOLICITED / 0x15 DISABLE_UNSOLICITED / 0x17
//     DELAY_MEASURE / 0x18 RECORD_CURRENT_TIME / 0x20
//     AUTHENTICATE_REQ / 0x81 RESPONSE / 0x82
//     UNSOLICITED_RESPONSE / 0x83 AUTHENTICATE_RESP.
//
//   - **16-entry IIN-bit name set** (IEEE 1815-2012 §4.2.4; both
//     bytes): IIN1 = BROADCAST / CLASS_1_EVENTS / CLASS_2_EVENTS
//     / CLASS_3_EVENTS / NEED_TIME / LOCAL_CONTROL / DEVICE_TROUBLE
//     / DEVICE_RESTART; IIN2 = NO_FUNC_CODE_SUPPORT / OBJECT_UNKNOWN
//     / PARAMETER_ERROR / EVENT_BUFFER_OVERFLOW / ALREADY_EXECUTING
//     / CONFIG_CORRUPT / reserved / reserved. The decoded comma-
//     separated set is surfaced alongside the raw 16-bit hex.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Transport framing** — IP/TCP port 20000 (default), UDP/
//     20000, or serial RS-232/422/485 lines. Feed DNP3 bytes
//     after the transport-header strip.
//   - **CRC verification** — the data-link header CRC and the
//     per-16-byte-block CRCs are surfaced as hex but not re-
//     computed against IEEE 1815-2012 §E (CRC-16-DNP, polynomial
//     0x3D65, init 0x0000, reflected, xorout 0xFFFF).
//   - **Object header walker** — past the application header
//     DNP3 carries a stream of Object headers (Group + Variation
//   - Qualifier + Range + count + objects). The per-group
//     decoder set is large (Binary Inputs, Counters, Analog
//     Inputs / Outputs, Time-and-Date, File-Control, Authentication
//     ...) and dataset-specific; remaining bytes are surfaced as
//     `object_data_hex` for future per-group walkers.
//   - **Secure Authentication payload** — function codes 0x20 /
//     0x21 / 0x83 carry HMAC-SHA256-protected Authentication
//     blocks per IEEE 1815-2012 §7; payload surfaced as hex.
//   - **Multi-fragment reassembly** — the transport-byte FIN/FIR
//     flags and sequence number identify multi-segment
//     application fragments; the decoder surfaces the flags but
//     does not reassemble across multiple input frames.
//   - **State-machine reasoning** — primary/secondary frame-count-
//     bit logic, ENABLE_UNSOLICITED timer state, freeze-counter
//     semantics; higher-level analysis.
package dnp3

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a DNP3 frame.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Data-link header
	StartHex         string `json:"start_hex"`
	Length           int    `json:"length"`
	ControlHex       string `json:"control_hex"`
	DIR              bool   `json:"dir_master_to_outstation"`
	PRM              bool   `json:"prm_primary_message"`
	FCBOrDFC         bool   `json:"fcb_or_dfc"`
	FCVOrRES         bool   `json:"fcv_or_res"`
	LinkFunctionCode int    `json:"link_function_code"`
	LinkFunctionName string `json:"link_function_name"`
	Destination      int    `json:"destination"`
	Source           int    `json:"source"`
	HeaderCRCHex     string `json:"header_crc_hex"`

	// Transport layer
	TransportFIN bool `json:"transport_fin,omitempty"`
	TransportFIR bool `json:"transport_fir,omitempty"`
	TransportSeq int  `json:"transport_seq,omitempty"`

	// Application layer
	AppControlHex   string `json:"app_control_hex,omitempty"`
	AppFIR          bool   `json:"app_fir,omitempty"`
	AppFIN          bool   `json:"app_fin,omitempty"`
	AppCON          bool   `json:"app_con_confirm_requested,omitempty"`
	AppUNS          bool   `json:"app_uns_unsolicited,omitempty"`
	AppSeq          int    `json:"app_seq,omitempty"`
	AppFunctionCode int    `json:"app_function_code,omitempty"`
	AppFunctionName string `json:"app_function_name,omitempty"`

	// Response-only
	IINHex         string `json:"iin_hex,omitempty"`
	IINBitsDecoded string `json:"iin_bits_decoded,omitempty"`

	// Remaining object data
	ObjectDataHex string `json:"object_data_hex,omitempty"`

	// Reconstructed user-data stream (post-CRC strip, no
	// transport/application bytes consumed) for callers who want
	// to feed it through their own walker.
	UserDataHex string `json:"user_data_hex,omitempty"`
}

// Decode parses a DNP3 frame from a hex string. Separators
// (':' '-' '_' whitespace) are tolerated; a leading '0x' prefix
// is stripped.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 10 {
		return nil, fmt.Errorf("DNP3 frame truncated (%d bytes; need ≥10 for data-link header)",
			len(b))
	}
	if b[0] != 0x05 || b[1] != 0x64 {
		return nil, fmt.Errorf("missing DNP3 sync 0x05 0x64 (got 0x%02X 0x%02X)",
			b[0], b[1])
	}

	r := &Result{
		TotalBytes:       len(b),
		StartHex:         "0x0564",
		Length:           int(b[2]),
		ControlHex:       fmt.Sprintf("0x%02X", b[3]),
		DIR:              b[3]&0x80 != 0,
		PRM:              b[3]&0x40 != 0,
		FCBOrDFC:         b[3]&0x20 != 0,
		FCVOrRES:         b[3]&0x10 != 0,
		LinkFunctionCode: int(b[3] & 0x0F),
		Destination:      int(binary.LittleEndian.Uint16(b[4:6])),
		Source:           int(binary.LittleEndian.Uint16(b[6:8])),
		HeaderCRCHex:     fmt.Sprintf("0x%04X", binary.LittleEndian.Uint16(b[8:10])),
	}
	r.LinkFunctionName = linkFunctionName(r.LinkFunctionCode, r.PRM)

	// Length excludes the Length byte itself + CRCs. Min legal
	// Length = 5 (Control + Dest + Src; no user data).
	if r.Length < 5 {
		return r, nil
	}
	userBytes := r.Length - 5
	if userBytes == 0 {
		return r, nil
	}

	// Walk 16-byte blocks (each followed by a 2-byte CRC),
	// reconstructing the user-data stream.
	user, ok := walkUserBlocks(b[10:], userBytes)
	if !ok {
		return r, nil
	}
	r.UserDataHex = strings.ToUpper(hex.EncodeToString(user))

	// Transport byte.
	if len(user) < 1 {
		return r, nil
	}
	tp := user[0]
	r.TransportFIN = tp&0x80 != 0
	r.TransportFIR = tp&0x40 != 0
	r.TransportSeq = int(tp & 0x3F)

	// Application header — Control + Function Code (+ IIN if
	// response).
	if len(user) < 3 {
		return r, nil
	}
	ac := user[1]
	r.AppControlHex = fmt.Sprintf("0x%02X", ac)
	r.AppFIR = ac&0x80 != 0
	r.AppFIN = ac&0x40 != 0
	r.AppCON = ac&0x20 != 0
	r.AppUNS = ac&0x10 != 0
	r.AppSeq = int(ac & 0x0F)
	r.AppFunctionCode = int(user[2])
	r.AppFunctionName = appFunctionName(r.AppFunctionCode)

	objOff := 3
	if isResponseFunctionCode(r.AppFunctionCode) {
		if len(user) < 5 {
			return r, nil
		}
		iin := binary.LittleEndian.Uint16(user[3:5])
		r.IINHex = fmt.Sprintf("0x%04X", iin)
		r.IINBitsDecoded = iinBitNames(iin)
		objOff = 5
	}

	if objOff < len(user) {
		r.ObjectDataHex = strings.ToUpper(hex.EncodeToString(user[objOff:]))
	}
	return r, nil
}

// walkUserBlocks strips per-16-byte-block CRCs from the on-wire
// user-data region, returning the concatenated user bytes.
func walkUserBlocks(b []byte, expectedBytes int) ([]byte, bool) {
	out := make([]byte, 0, expectedBytes)
	off := 0
	remaining := expectedBytes
	for remaining > 0 {
		blockSize := 16
		if remaining < 16 {
			blockSize = remaining
		}
		if off+blockSize+2 > len(b) {
			return nil, false
		}
		out = append(out, b[off:off+blockSize]...)
		off += blockSize + 2 // skip 2-byte block CRC
		remaining -= blockSize
	}
	return out, true
}

func linkFunctionName(code int, prm bool) string {
	if prm {
		switch code {
		case 0:
			return "RESET_LINK_STATES"
		case 1:
			return "TEST_LINK_STATES"
		case 2:
			return "CONFIRMED_USER_DATA"
		case 3:
			return "UNCONFIRMED_USER_DATA"
		case 9:
			return "REQUEST_LINK_STATUS"
		}
		return fmt.Sprintf("uncatalogued primary code %d", code)
	}
	switch code {
	case 0:
		return "ACK"
	case 1:
		return "NACK"
	case 11:
		return "LINK_STATUS"
	case 14:
		return "NOT_FUNCTIONING"
	}
	return fmt.Sprintf("uncatalogued secondary code %d", code)
}

func appFunctionName(code int) string {
	switch code {
	case 0x00:
		return "CONFIRM"
	case 0x01:
		return "READ"
	case 0x02:
		return "WRITE"
	case 0x03:
		return "SELECT"
	case 0x04:
		return "OPERATE"
	case 0x05:
		return "DIRECT_OPERATE"
	case 0x06:
		return "DIRECT_OPERATE_NR"
	case 0x07:
		return "IMMED_FREEZE"
	case 0x08:
		return "IMMED_FREEZE_NR"
	case 0x09:
		return "FREEZE_CLEAR"
	case 0x0A:
		return "FREEZE_CLEAR_NR"
	case 0x0B:
		return "FREEZE_AT_TIME"
	case 0x0D:
		return "COLD_RESTART"
	case 0x0E:
		return "WARM_RESTART"
	case 0x14:
		return "ENABLE_UNSOLICITED"
	case 0x15:
		return "DISABLE_UNSOLICITED"
	case 0x17:
		return "DELAY_MEASURE"
	case 0x18:
		return "RECORD_CURRENT_TIME"
	case 0x20:
		return "AUTHENTICATE_REQ"
	case 0x21:
		return "AUTH_REQ_NO_ACK"
	case 0x81:
		return "RESPONSE"
	case 0x82:
		return "UNSOLICITED_RESPONSE"
	case 0x83:
		return "AUTHENTICATE_RESP"
	}
	return fmt.Sprintf("uncatalogued function code 0x%02X", code)
}

func isResponseFunctionCode(code int) bool {
	return code == 0x81 || code == 0x82 || code == 0x83
}

// iinBitNames returns a comma-separated set of asserted IIN bits.
// The 16-bit IIN field is interpreted as IIN1 (low byte) +
// IIN2 (high byte) per IEEE 1815-2012 §4.2.4.
func iinBitNames(iin uint16) string {
	var names []string
	iin1 := byte(iin & 0xFF)
	iin2 := byte(iin >> 8)
	if iin1&0x01 != 0 {
		names = append(names, "BROADCAST")
	}
	if iin1&0x02 != 0 {
		names = append(names, "CLASS_1_EVENTS")
	}
	if iin1&0x04 != 0 {
		names = append(names, "CLASS_2_EVENTS")
	}
	if iin1&0x08 != 0 {
		names = append(names, "CLASS_3_EVENTS")
	}
	if iin1&0x10 != 0 {
		names = append(names, "NEED_TIME")
	}
	if iin1&0x20 != 0 {
		names = append(names, "LOCAL_CONTROL")
	}
	if iin1&0x40 != 0 {
		names = append(names, "DEVICE_TROUBLE")
	}
	if iin1&0x80 != 0 {
		names = append(names, "DEVICE_RESTART")
	}
	if iin2&0x01 != 0 {
		names = append(names, "NO_FUNC_CODE_SUPPORT")
	}
	if iin2&0x02 != 0 {
		names = append(names, "OBJECT_UNKNOWN")
	}
	if iin2&0x04 != 0 {
		names = append(names, "PARAMETER_ERROR")
	}
	if iin2&0x08 != 0 {
		names = append(names, "EVENT_BUFFER_OVERFLOW")
	}
	if iin2&0x10 != 0 {
		names = append(names, "ALREADY_EXECUTING")
	}
	if iin2&0x20 != 0 {
		names = append(names, "CONFIG_CORRUPT")
	}
	return strings.Join(names, ",")
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
