// SPDX-License-Identifier: AGPL-3.0-or-later

package aprs

import (
	"fmt"
	"strings"
)

// MicE is the decoded Mic-E (Microphone Encoder) position report (APRS101
// §10) — the compressed-position format used by the great majority of APRS
// trackers and mobile radios (Kenwood TM-D700/D710, Yaesu FTM series, the
// original Mic-Encoder). Mic-E packs latitude + message bits + N/S +
// longitude-offset + W/E into the 6-character AX.25 destination address, and
// longitude + speed + course + symbol into the information field.
type MicE struct {
	LatitudeDeg  float64 `json:"latitude_deg"`
	LongitudeDeg float64 `json:"longitude_deg"`
	// SpeedKnots is the ground speed (Mic-E encodes 0–799 knots).
	SpeedKnots int `json:"speed_knots"`
	// CourseDeg is the course over ground (0 = unknown/indefinite, 360 =
	// due north, per APRS101 §10).
	CourseDeg int `json:"course_deg"`

	MessageType string `json:"message_type"`

	SymbolTable string `json:"symbol_table"`
	SymbolCode  string `json:"symbol_code"`
	SymbolName  string `json:"symbol_name,omitempty"`

	// Ambiguity is the number of low-order latitude digits blanked by the
	// sender for position-ambiguity (APRS101 §6); 0 = full precision.
	Ambiguity int `json:"ambiguity,omitempty"`

	// DataType labels the information-field Data Type Identifier.
	DataType string `json:"data_type"`
	// StatusText is the optional Mic-E status text / telemetry after the
	// symbol (info bytes 10+), surfaced verbatim.
	StatusText string `json:"status_text,omitempty"`
}

// micEStdMessages / micECustomMessages map the A/B/C message-bit triple
// (index = A<<2 | B<<1 | C) to the message name. Index 0 (000) is Emergency.
var micEStdMessages = [8]string{ //nolint:gochecknoglobals // immutable table
	"Emergency", "M6: Priority", "M5: Special", "M4: Committed",
	"M3: Returning", "M2: In Service", "M1: En Route", "M0: Off Duty",
}

var micECustomMessages = [8]string{ //nolint:gochecknoglobals // immutable table
	"Emergency", "C6: Custom-6", "C5: Custom-5", "C4: Custom-4",
	"C3: Custom-3", "C2: Custom-2", "C1: Custom-1", "C0: Custom-0",
}

// decodeMicE decodes a Mic-E packet from the (already-parsed) 6-character
// destination callsign and the information field. Per APRS101 §10 the data
// type identifier is the first info byte; the packet must carry at least 9
// info bytes or it must be ignored.
func decodeMicE(f *Frame, info string) error {
	dest := f.Destination.Callsign
	if len(dest) != 6 {
		return fmt.Errorf("mic-e: destination callsign must be 6 chars, got %q", dest)
	}
	if len(info) < 9 {
		return fmt.Errorf("mic-e: information field must be >= 9 bytes, got %d", len(info))
	}

	m := &MicE{DataType: micEDataType(info[0])}

	// --- Destination address: latitude + message bits + N/S + offset + W/E.
	var latDigits [6]int
	var ambig int
	bitA, bitB, bitC := 0, 0, 0 // the A/B/C message-identifier bits
	custA, custB, custC := false, false, false
	for i := 0; i < 6; i++ {
		digit, blank, one, custom := micEDestChar(dest[i])
		if blank {
			ambig++
			latDigits[i] = 0
		} else {
			latDigits[i] = digit
		}
		switch i {
		case 0:
			bitA, custA = one, custom
		case 1:
			bitB, custB = one, custom
		case 2:
			bitC, custC = one, custom
		}
	}
	m.Ambiguity = ambig
	m.MessageType = micEMessage(bitA, bitB, bitC, custA, custB, custC)

	// Latitude DDMM.HH from the six digits; sign from byte 4 (N/S).
	latDeg := float64(latDigits[0]*10 + latDigits[1])
	latMin := float64(latDigits[2]*10+latDigits[3]) + float64(latDigits[4]*10+latDigits[5])/100.0
	m.LatitudeDeg = latDeg + latMin/60.0
	if !micEByteIsHigh(dest[3]) { // byte 4: high (P–Z) = North, low (0–9/L) = South
		m.LatitudeDeg = -m.LatitudeDeg
	}
	offsetHundred := micEByteIsHigh(dest[4]) // byte 5: longitude offset +100
	west := micEByteIsHigh(dest[5])          // byte 6: W/E (high = West)

	// --- Information field: longitude, speed, course, symbol, status.
	dPlus, mPlus, hPlus := int(info[1])-28, int(info[2])-28, int(info[3])-28
	lonDeg := dPlus
	if offsetHundred {
		lonDeg += 100
	}
	switch {
	case lonDeg >= 180 && lonDeg <= 189:
		lonDeg -= 80
	case lonDeg >= 190 && lonDeg <= 199:
		lonDeg -= 190
	}
	lonMin := mPlus
	if lonMin >= 60 {
		lonMin -= 60
	}
	m.LongitudeDeg = float64(lonDeg) + (float64(lonMin)+float64(hPlus)/100.0)/60.0
	if west {
		m.LongitudeDeg = -m.LongitudeDeg
	}

	sp, dc, se := int(info[4])-28, int(info[5])-28, int(info[6])-28
	speed := sp*10 + dc/10
	if speed >= 800 {
		speed -= 800
	}
	course := (dc%10)*100 + se
	if course >= 400 {
		course -= 400
	}
	m.SpeedKnots = speed
	m.CourseDeg = course

	m.SymbolCode = string(info[7])
	m.SymbolTable = string(info[8])
	m.SymbolName = symbolName(m.SymbolTable, m.SymbolCode)
	if len(info) > 9 {
		m.StatusText = strings.TrimSpace(info[9:])
	}

	f.MicE = m
	return nil
}

// micEDestChar decodes one destination-address character (APRS101 §10
// "Destination Address Field Encoding"): the latitude digit, whether the
// digit is blanked for ambiguity, the message-identifier bit (1/0), and
// whether a 1-bit is a Custom (vs Standard) 1. N/S, longitude-offset and W/E
// for bytes 4–6 are derived separately via micEByteIsHigh.
func micEDestChar(c byte) (digit int, blank bool, one int, custom bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), false, 0, false
	case c >= 'A' && c <= 'J': // custom 1, digits 0–9
		return int(c - 'A'), false, 1, true
	case c == 'K': // custom 1, blank (ambiguous) digit
		return 0, true, 1, true
	case c == 'L': // standard 0, blank digit
		return 0, true, 0, false
	case c >= 'P' && c <= 'Y': // standard 1, digits 0–9
		return int(c - 'P'), false, 1, false
	case c == 'Z': // standard 1, blank digit
		return 0, true, 1, false
	}
	return 0, true, 0, false
}

// micEByteIsHigh reports whether a destination byte is in the "high" group
// (P–Z), which selects North (byte 4), longitude offset +100 (byte 5) and
// West (byte 6). The "low" group (0–9 and L) selects South / +0 / East.
func micEByteIsHigh(c byte) bool {
	return c >= 'P' && c <= 'Z'
}

// micEMessage resolves the A/B/C message-identifier bits to a message name.
// All-zero is Emergency; a pure-standard triple selects from the Standard
// table, a pure-custom triple from the Custom table, and a mix is "Unknown"
// (APRS101 §10).
func micEMessage(a, b, c int, custA, custB, custC bool) string {
	idx := a<<2 | b<<1 | c
	if idx == 0 {
		return "Emergency"
	}
	anyStd := (a == 1 && !custA) || (b == 1 && !custB) || (c == 1 && !custC)
	anyCustom := (a == 1 && custA) || (b == 1 && custB) || (c == 1 && custC)
	switch {
	case anyStd && anyCustom:
		return "Unknown (mixed standard/custom message bits)"
	case anyCustom:
		return micECustomMessages[idx]
	default:
		return micEStdMessages[idx]
	}
}

// micEDataType labels the Mic-E information-field Data Type Identifier.
func micEDataType(c byte) string {
	switch c {
	case '`':
		return "current GPS data"
	case '\'':
		return "old GPS data"
	case 0x1c:
		return "current GPS data (Rev. 0 beta)"
	case 0x1d:
		return "old GPS data (Rev. 0 beta)"
	}
	return "Mic-E"
}
