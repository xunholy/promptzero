// SPDX-License-Identifier: AGPL-3.0-or-later

// Package aprs decodes APRS (Automatic Packet Reporting System)
// frames carried over AX.25 — the dominant ham-radio position
// + telemetry + messaging beacon family transmitted on 144.39
// MHz (NA), 144.80 MHz (EU), and a handful of HF bands.
//
// # Wrap-vs-native judgement
//
// Native. APRS is defined by the public APRS101.pdf protocol
// reference (TAPR, 2000) + AX.25 v2.2 (TAPR, 1998). Every
// frame is ASCII (or shifted-ASCII for AX.25 addresses) with
// well-documented info-field type prefixes. Pasting a TNC2
// line from a soundmodem (direwolf), kiss-tnc, or APRS-IS
// stream is enough. No vendor SDK, no handshake.
//
// # What this package covers
//
//   - TNC2 text frame parsing: SRC[-SSID]>DST[-SSID]
//     [,PATH[-SSID]...]:INFO. The address fields are split
//     on '-' for SSID, the path is comma-separated, and
//     digipeated entries are marked with a trailing '*' per
//     APRS101 §10.
//
//   - AX.25 hex byte parsing (alternative input form):
//     7-byte shifted-ASCII addresses (callsign << 1 + SSID
//     byte with end-of-address flag), control byte (0x03 =
//     UI frame), PID (0xF0 = no layer 3), and the info
//     field as the remaining bytes.
//
//   - Info field type dispatch via the first-byte prefix
//     table (APRS101 §5): '!', '=' position without
//     timestamp; '/', '@' position with timestamp; ':'
//     message; '>' status; ';' object; ')' item; '_'
//     weather; 'T' telemetry; '?' query; '<' station
//     capabilities; etc.
//
//   - Uncompressed position decode (APRS101 §8): lat in
//     "DDMM.MMN" + lon in "DDDMM.MME" with hemisphere
//     conversion to signed decimal degrees, symbol table
//     and symbol code extraction.
//
//   - Compressed position decode (APRS101 §9): the 13-byte
//     base-91 form (symbol table + 4-byte lat + 4-byte lon +
//     symbol code + cs + type), with the cs+type extension
//     decoded to course/speed, altitude, or radio range.
//
//   - PHG extension parse (APRS101 §7) — antenna
//     Power-Height-Gain-Directivity for fixed-station
//     coverage analysis.
//
//   - Status report ('>') text extraction.
//
//   - Message format (':') addressee + body + optional
//     message number suffix.
//
//   - Positionless weather report ('_') decode (APRS101
//     §12): the 8-char MDHM timestamp followed by the
//     fully-specified weather fields — wind direction
//     (c), sustained wind speed (s), gust (g), temperature
//     (t, incl. the -01..-99 below-zero form), rainfall last
//     hour / 24 h / since midnight (r/p/P, hundredths of an
//     inch → inches), humidity (h, 00 = 100%), barometric
//     pressure (b, tenths of hPa → hPa) and luminosity
//     (L ≤ 999 / l ≥ 1000 W/m²). Unknown sensors ('...' or
//     spaces) decode to a nil field, not a zero. Anchored to
//     the APRS101 §12 canonical example
//     `_10090556c220s004g005t077r000p000P000h50b09900wRSW`.
//
//   - Complete weather report decode (APRS101 §12): a
//     position report (with or without timestamp) whose
//     symbol code is '_' carries weather data in place of a
//     free-text comment. The 7-byte "ddd/sss" Wind
//     Direction/Speed Data Extension replaces the positionless
//     cccc/ssss fields; gust, temperature and the optional
//     fields then follow identically. Gated on the ddd/sss
//     pattern so a plain '_'-symbol position carrying a comment
//     is not mis-parsed. Anchored to the APRS101 §12 examples
//     `!4903.50N/07201.75W_220/004g005t077...` and the
//     timestamped `@092345z...W_220/004g005t-07...`.
//
//   - Mic-E decode (APRS101 §10): the dominant tracker /
//     mobile-radio compressed-position format. Latitude +
//     message bits + N/S + longitude-offset + W/E are packed
//     into the 6-character destination address; longitude +
//     speed + course + symbol into the information field
//     (data type identifiers: backtick = current GPS,
//     apostrophe = old GPS, plus the 0x1c/0x1d beta IDs).
//     Decodes lat/lon, speed (knots),
//     course, the 15 standard/custom/emergency message types,
//     symbol, latitude ambiguity, and surfaces the trailing
//     status text raw. Anchored byte-for-byte to the two
//     APRS101 §10 worked examples (destination S32U6T →
//     33°25.64'N / M3; info field `(_fn"Oj/ → 112°7.74'W /
//     20 kt / 251°). Mic-E telemetry fields are surfaced as
//     part of the raw status text rather than parsed.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Snowfall (tail 's'), the '#' raw rain counter, and the
//     trailing APRS-software / WX-unit code are under-specified
//     in APRS101 (no fixed width / scaling), so they are left
//     in the weather report's raw remainder rather than
//     decoded into a possibly-wrong value.
//   - Telemetry parameters / equations / units / bits names
//     (#PARM / #UNIT / #EQNS / #BITS) — only the basic
//     'T#nnn,a1,a2,...' parametric form is recognised here.
//   - AX.25 connection-mode frames (SABM / DISC / RR / RNR /
//     I-frames) — only the UI frame used by APRS is in scope.
//   - FCS / CRC validation on AX.25 frames — TNC2 strings
//     don't include FCS, and real captures via direwolf strip
//     it. Hex byte input is assumed to be the post-FCS-strip
//     bytes.
package aprs

import (
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Frame is the decoded view of one APRS packet.
type Frame struct {
	Source       Address    `json:"source"`
	Destination  Address    `json:"destination"`
	Path         []Address  `json:"path,omitempty"`
	InfoType     string     `json:"info_type"`
	InfoTypeName string     `json:"info_type_name"`
	InfoText     string     `json:"info_text"`
	Position     *Position  `json:"position,omitempty"`
	Status       string     `json:"status,omitempty"`
	Message      *Message   `json:"message,omitempty"`
	Telemetry    *Telemetry `json:"telemetry,omitempty"`
	PHG          *PHG       `json:"phg,omitempty"`
	Weather      *Weather   `json:"weather,omitempty"`
	MicE         *MicE      `json:"mic_e,omitempty"`
	Comment      string     `json:"comment,omitempty"`
}

// Address represents one AX.25 / TNC2 callsign + SSID slot.
//
// Digipeated is true when this entry has a '*' suffix in the
// TNC2 path field (or the H-bit is set in the raw AX.25
// SSID byte), indicating that the digipeater has already
// repeated the frame.
type Address struct {
	Callsign   string `json:"callsign"`
	SSID       int    `json:"ssid"`
	Digipeated bool   `json:"digipeated,omitempty"`
}

// Position is the decoded APRS position view (uncompressed §8 or
// compressed §9).
type Position struct {
	LatitudeDeg  float64 `json:"latitude_deg"`
	LongitudeDeg float64 `json:"longitude_deg"`
	SymbolTable  string  `json:"symbol_table"`
	SymbolCode   string  `json:"symbol_code"`
	SymbolName   string  `json:"symbol_name,omitempty"`
	Timestamp    string  `json:"timestamp,omitempty"`
	// Compressed is set when the position was carried in the §9
	// base-91 compressed format rather than the §8 text form.
	Compressed bool `json:"compressed,omitempty"`
	// CourseDeg / SpeedKnots / AltitudeFt / RadioRangeMi carry the
	// §9 compressed cs+type extension, when present. Exactly one of
	// {course+speed, altitude, radio-range} is set per the type byte.
	CourseDeg    int     `json:"course_deg,omitempty"`
	SpeedKnots   float64 `json:"speed_knots,omitempty"`
	AltitudeFt   float64 `json:"altitude_ft,omitempty"`
	RadioRangeMi float64 `json:"radio_range_mi,omitempty"`
}

// Message is the decoded ':' addressee + body packet.
type Message struct {
	Addressee     string `json:"addressee"`
	Body          string `json:"body"`
	MessageNumber string `json:"message_number,omitempty"`
}

// Telemetry is the basic 'T#nnn,v1,v2,...' parametric form.
type Telemetry struct {
	SequenceNumber int       `json:"sequence_number"`
	Analog         []float64 `json:"analog,omitempty"`
	DigitalBits    string    `json:"digital_bits,omitempty"`
}

// PHG is the antenna Power-Height-Gain-Directivity extension.
//
// The four digits after "PHG" encode an antenna profile that
// fixed stations broadcast so APRS aggregators can compute
// expected coverage.
type PHG struct {
	PowerW      int    `json:"power_w"`
	HeightFt    int    `json:"height_ft"`
	GainDBi     int    `json:"gain_dbi"`
	Directivity string `json:"directivity"`
}

// Decode parses an APRS packet from either a TNC2 text line
// or a hex-encoded AX.25 byte blob. The format is auto-
// detected: input containing '>' and ':' is treated as TNC2,
// otherwise it's parsed as hex.
func Decode(in string) (*Frame, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return nil, fmt.Errorf("aprs: empty input")
	}
	if looksLikeTNC2(s) {
		return decodeTNC2(s)
	}
	b, err := parseHex(s)
	if err != nil {
		return nil, err
	}
	return DecodeAX25Bytes(b)
}

// looksLikeTNC2 returns true when the input has the TNC2
// envelope (callsign>callsign...:info).
func looksLikeTNC2(s string) bool {
	gt := strings.Index(s, ">")
	colon := strings.Index(s, ":")
	return gt > 0 && colon > gt
}

// decodeTNC2 parses the canonical TNC2 text form. APRS101 §10
// defines the format as:
//
//	SOURCE[-SSID]>DEST[-SSID][,PATH[-SSID]*?...]:INFO
func decodeTNC2(s string) (*Frame, error) {
	gt := strings.Index(s, ">")
	colon := strings.Index(s, ":")
	if gt <= 0 || colon <= gt {
		return nil, fmt.Errorf("aprs: TNC2 envelope malformed (expected SRC>DST...:INFO)")
	}
	src, err := parseTNCAddress(s[:gt])
	if err != nil {
		return nil, fmt.Errorf("aprs: source: %w", err)
	}
	header := s[gt+1 : colon]
	parts := strings.Split(header, ",")
	dst, err := parseTNCAddress(parts[0])
	if err != nil {
		return nil, fmt.Errorf("aprs: destination: %w", err)
	}
	f := &Frame{Source: src, Destination: dst}
	for _, p := range parts[1:] {
		a, err := parseTNCAddress(p)
		if err != nil {
			return nil, fmt.Errorf("aprs: path entry %q: %w", p, err)
		}
		f.Path = append(f.Path, a)
	}
	info := s[colon+1:]
	if err := decodeInfoField(f, info); err != nil {
		return nil, fmt.Errorf("aprs: info field: %w", err)
	}
	return f, nil
}

// parseTNCAddress splits "CALL[-SSID][*]" into Address.
func parseTNCAddress(s string) (Address, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Address{}, fmt.Errorf("empty callsign")
	}
	a := Address{}
	if strings.HasSuffix(s, "*") {
		a.Digipeated = true
		s = s[:len(s)-1]
	}
	if dash := strings.LastIndex(s, "-"); dash > 0 {
		ssid, err := strconv.Atoi(s[dash+1:])
		if err != nil {
			return Address{}, fmt.Errorf("bad SSID %q: %w", s[dash+1:], err)
		}
		if ssid < 0 || ssid > 15 {
			return Address{}, fmt.Errorf("SSID %d out of range 0..15", ssid)
		}
		a.SSID = ssid
		s = s[:dash]
	}
	if len(s) == 0 || len(s) > 6 {
		return Address{}, fmt.Errorf("callsign %q must be 1-6 chars", s)
	}
	a.Callsign = s
	return a, nil
}

// DecodeAX25Bytes parses a raw AX.25 UI frame. The frame
// layout per AX.25 v2.2 §3.4 + APRS101 §6 is:
//
//	0-13  : Destination address (7 bytes)
//	7-13  : Source address (7 bytes)
//	14-?  : 0..8 digipeater addresses (7 bytes each)
//	(next): Control byte (0x03 for UI)
//	(next): PID (0xF0 for no layer-3)
//	rest  : Information field
//
// Each address is 6 chars of shifted-ASCII (left-shifted by 1)
// + 1 SSID byte. The end-of-address flag is bit 0 of the SSID
// byte: 1 = last address.
func DecodeAX25Bytes(b []byte) (*Frame, error) {
	if len(b) < 14 {
		return nil, fmt.Errorf("aprs: AX.25 frame too short (need at least 14 bytes for SRC+DST)")
	}
	f := &Frame{}
	off := 0
	dst, _, err := readAX25Address(b, off)
	if err != nil {
		return nil, fmt.Errorf("aprs: destination: %w", err)
	}
	f.Destination = dst
	off += 7
	src, srcLast, err := readAX25Address(b, off)
	if err != nil {
		return nil, fmt.Errorf("aprs: source: %w", err)
	}
	f.Source = src
	off += 7
	last := srcLast
	for !last && off+7 <= len(b) {
		var a Address
		a, last, err = readAX25Address(b, off)
		if err != nil {
			return nil, fmt.Errorf("aprs: path: %w", err)
		}
		f.Path = append(f.Path, a)
		off += 7
	}
	// Control + PID + info
	if off+2 > len(b) {
		return nil, fmt.Errorf("aprs: AX.25 frame truncated before control byte")
	}
	control := b[off]
	pid := b[off+1]
	if control != 0x03 {
		return nil, fmt.Errorf("aprs: AX.25 control byte 0x%02X is not a UI frame (0x03); APRS only uses UI", control)
	}
	if pid != 0xF0 {
		return nil, fmt.Errorf("aprs: AX.25 PID 0x%02X is not 0xF0 (no layer-3); APRS uses 0xF0", pid)
	}
	off += 2
	info := string(b[off:])
	if err := decodeInfoField(f, info); err != nil {
		return nil, fmt.Errorf("aprs: info field: %w", err)
	}
	return f, nil
}

// readAX25Address extracts a single 7-byte AX.25 address from
// b starting at off and returns the parsed Address plus the
// end-of-address flag from bit 0 of the SSID byte.
func readAX25Address(b []byte, off int) (Address, bool, error) {
	if off+7 > len(b) {
		return Address{}, false, fmt.Errorf("address truncated at offset %d", off)
	}
	cs := make([]byte, 0, 6)
	for i := 0; i < 6; i++ {
		c := b[off+i] >> 1
		if c != ' ' {
			cs = append(cs, c)
		}
	}
	ssidByte := b[off+6]
	ssid := int((ssidByte >> 1) & 0x0F)
	last := ssidByte&0x01 == 1
	digipeated := ssidByte&0x80 == 0x80
	return Address{
		Callsign:   string(cs),
		SSID:       ssid,
		Digipeated: digipeated,
	}, last, nil
}

// decodeInfoField looks at the first byte of the APRS info
// field to pick a decoder. Each branch attaches the
// corresponding structured sub-view to f and labels the type.
func decodeInfoField(f *Frame, info string) error {
	f.InfoText = info
	if info == "" {
		f.InfoType = ""
		f.InfoTypeName = "Empty info field"
		return nil
	}
	prefix := info[0:1]
	f.InfoType = prefix
	f.InfoTypeName = infoTypeName(prefix)
	switch prefix {
	case "!", "=":
		// Position without timestamp; data starts at offset 1.
		return decodePosition(f, info[1:], false)
	case "@", "/":
		// Position with timestamp (7-char DHM/HMS), then
		// position payload.
		if len(info) < 8 {
			return fmt.Errorf("position-with-timestamp too short (need 8+ chars)")
		}
		ts := info[1:8]
		if err := decodePosition(f, info[8:], false); err != nil {
			return err
		}
		if f.Position != nil {
			f.Position.Timestamp = ts
		}
		return nil
	case ":":
		return decodeMessage(f, info[1:])
	case ">":
		f.Status = info[1:]
		return nil
	case "T":
		if strings.HasPrefix(info, "T#") {
			return decodeTelemetry(f, info[2:])
		}
		return nil
	case "_":
		return decodeWeatherPositionless(f, info[1:])
	case "`", "'", "\x1c", "\x1d":
		// Mic-E: the data type identifier; latitude is in the
		// destination address, the rest in this info field.
		return decodeMicE(f, info)
	}
	return nil
}

// decodePosition parses the uncompressed APRS position format:
//
//	DDMM.MMH/dddmm.mmHc[comment]
//
// where H is the hemisphere letter ('N'/'S' or 'E'/'W'), c is
// the symbol code, and the character before '/' is the symbol
// table identifier.
//
// A compressed position (13 bytes, leading char is one of
// '/'/'\\'/A-Z/a-j) is dispatched to decodeCompressedPosition
// (APRS101 §9, base-91 lat/lon encoding).
func decodePosition(f *Frame, payload string, _ bool) error {
	if isCompressedPosition(payload) {
		return decodeCompressedPosition(f, payload)
	}
	// "DDMM.MMN/DDDMM.MMW" is 18 chars + 1 symbol char = 19;
	// symbol table is char 8 (sandwiched as the '/' or
	// alternative).
	if len(payload) < 19 {
		return fmt.Errorf("uncompressed position too short (need 19+ chars)")
	}
	latStr := payload[:8]
	symTable := payload[8:9]
	lonStr := payload[9:18]
	symCode := payload[18:19]
	lat, err := parseLatLonText(latStr, true)
	if err != nil {
		return fmt.Errorf("latitude: %w", err)
	}
	lon, err := parseLatLonText(lonStr, false)
	if err != nil {
		return fmt.Errorf("longitude: %w", err)
	}
	f.Position = &Position{
		LatitudeDeg:  lat,
		LongitudeDeg: lon,
		SymbolTable:  symTable,
		SymbolCode:   symCode,
		SymbolName:   symbolName(symTable, symCode),
	}
	rest := strings.TrimSpace(payload[19:])
	// Complete Weather Report (APRS101 §12): a position report whose symbol
	// code is '_' carries weather data (a "ddd/sss" wind extension + the
	// gust/temp/optional fields) in place of a free-text comment. Gated on
	// the ddd/sss pattern so a plain '_'-symbol position with a comment is
	// not mis-parsed.
	if symCode == "_" && decodeCompleteWeather(f, rest) {
		return nil
	}
	if rest != "" {
		f.Comment = rest
		// PHG appears at the start of the comment as "PHGnnnn".
		if strings.HasPrefix(rest, "PHG") && len(rest) >= 7 {
			if p, ok := parsePHG(rest[3:7]); ok {
				f.PHG = p
				// Strip the PHG token from the comment so the
				// remainder is the operator-supplied text only.
				f.Comment = strings.TrimSpace(rest[7:])
			}
		}
	}
	return nil
}

// isCompressedPosition reports whether payload is an APRS101 §9
// compressed position: a leading symbol-table char ('/', '\\', an
// A-Z or a-j overlay), then eight base-91 lat/lon chars in the
// printable range '!'..'{' (value 0..90). The §8 uncompressed form
// always begins with a digit (or a space for ambiguity), so the two
// are unambiguous.
func isCompressedPosition(p string) bool {
	if len(p) < 13 {
		return false
	}
	c := p[0]
	isSymTable := c == '/' || c == '\\' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'j')
	if !isSymTable {
		return false
	}
	for i := 1; i <= 8; i++ {
		if p[i] < '!' || p[i] > '{' {
			return false
		}
	}
	return true
}

// decodeCompressedPosition parses the 13-byte APRS101 §9 compressed
// position: symbol-table(1) + base-91 latitude(4) + base-91
// longitude(4) + symbol-code(1) + cs(2) + compression-type(1).
//
//	latitude  = 90  - base91(YYYY) / 380926
//	longitude = -180 + base91(XXXX) / 190463
//
// The cs+type bytes carry exactly one optional extension, selected as
// in the reference decoders: a space in either cs byte means none;
// else type&0x18==0x10 is altitude (1.002^(c1*91+s1) feet); else
// c1 0..89 is course (c1*4 deg, or 360 when 0) + speed (1.08^s1 - 1
// knots); else c1==90 is a pre-set radio range (2 * 1.08^s1 miles).
// Values are kept in their APRS-native units (knots / feet / miles).
func decodeCompressedPosition(f *Frame, payload string) error {
	c := payload[:13]
	symTable := c[0:1]
	symCode := c[9:10]
	lat := 90 - float64(base91(c[1:5]))/380926.0
	lon := -180 + float64(base91(c[5:9]))/190463.0
	pos := &Position{
		LatitudeDeg:  lat,
		LongitudeDeg: lon,
		SymbolTable:  symTable,
		SymbolCode:   symCode,
		SymbolName:   symbolName(symTable, symCode),
		Compressed:   true,
	}
	c1 := int(c[10]) - 33
	s1 := int(c[11]) - 33
	ctype := int(c[12]) - 33
	switch {
	case c[10] == ' ' || c[11] == ' ':
		// No cs extension present.
	case ctype&0x18 == 0x10:
		pos.AltitudeFt = math.Pow(1.002, float64(c1*91+s1))
	case c1 >= 0 && c1 <= 89:
		if c1 == 0 {
			pos.CourseDeg = 360
		} else {
			pos.CourseDeg = c1 * 4
		}
		pos.SpeedKnots = math.Pow(1.08, float64(s1)) - 1
	case c1 == 90:
		pos.RadioRangeMi = 2 * math.Pow(1.08, float64(s1))
	}
	f.Position = pos
	rest := payload[13:]
	// Compressed complete weather report (APRS101 §12): when the symbol code
	// is '_' (weather station), the bytes after the compressed position are a
	// weather block — and, unlike the uncompressed §12 form, there is no
	// leading "ddd/sss" wind extension (the wind is carried by the compressed
	// cs course/speed, decoded above), so the block begins directly at the
	// gust/temperature fields. Attach it only when at least one weather field
	// actually parsed, so a '_'-symbol position carrying a plain comment is not
	// mis-reported as empty weather.
	if symCode == "_" {
		w := &Weather{}
		parseWeatherTail(w, rest)
		if weatherPopulated(w) {
			f.Weather = w
			return nil
		}
	}
	if r := strings.TrimSpace(rest); r != "" {
		f.Comment = r
	}
	return nil
}

// weatherPopulated reports whether a Weather has at least one decoded
// measurement (i.e. the trailing block really was a weather report, not a
// free-text comment).
func weatherPopulated(w *Weather) bool {
	return w.WindDirectionDeg != nil || w.WindSpeedMph != nil || w.GustMph != nil ||
		w.TemperatureF != nil || w.RainLastHourIn != nil || w.RainLast24hIn != nil ||
		w.RainSinceMidnightIn != nil || w.HumidityPct != nil || w.PressureHpa != nil ||
		w.LuminosityWm2 != nil
}

// base91 decodes a big-endian base-91 string (each char value =
// byte - 33), as used by the APRS101 §9 compressed position fields.
func base91(s string) int {
	v := 0
	for i := 0; i < len(s); i++ {
		v = v*91 + (int(s[i]) - 33)
	}
	return v
}

// parseLatLonText converts a single hemispheric position field
// to signed decimal degrees. APRS101 §8 specifies a fixed
// "DDMM.MMH" form for latitude (8 chars) and "DDDMM.MMH" form
// for longitude (9 chars). H is N/S (lat) or E/W (lon); a
// space character in the mm field denotes ambiguity.
func parseLatLonText(s string, isLat bool) (float64, error) {
	want := 8
	if !isLat {
		want = 9
	}
	if len(s) != want {
		return 0, fmt.Errorf("expected %d-char field, got %d", want, len(s))
	}
	hem := s[len(s)-1]
	digits := strings.ReplaceAll(s[:len(s)-1], " ", "0")
	var degField, minField int
	var err error
	if isLat {
		degField, err = strconv.Atoi(digits[0:2])
		if err != nil {
			return 0, fmt.Errorf("degrees: %w", err)
		}
	} else {
		degField, err = strconv.Atoi(digits[0:3])
		if err != nil {
			return 0, fmt.Errorf("degrees: %w", err)
		}
	}
	minDigits := digits[len(digits)-5:]
	minField, err = strconv.Atoi(minDigits[0:2])
	if err != nil {
		return 0, fmt.Errorf("minutes: %w", err)
	}
	minFrac, err := strconv.Atoi(minDigits[3:5])
	if err != nil {
		return 0, fmt.Errorf("minutes frac: %w", err)
	}
	v := float64(degField) + (float64(minField)+float64(minFrac)/100.0)/60.0
	switch hem {
	case 'N', 'E':
		return v, nil
	case 'S', 'W':
		return -v, nil
	}
	return 0, fmt.Errorf("hemisphere %q must be N/S/E/W", hem)
}

// decodeMessage parses the APRS message info field:
//
//	:ADDRESSEE:body{message-number}
//
// where ADDRESSEE is exactly 9 chars (callsign-SSID padded
// right with spaces) and message-number is optional.
func decodeMessage(f *Frame, payload string) error {
	if len(payload) < 11 {
		return fmt.Errorf("message info field too short (need 11+ chars)")
	}
	if payload[9] != ':' {
		return fmt.Errorf("expected ':' after 9-char addressee; got %q", payload[9])
	}
	addr := strings.TrimSpace(payload[:9])
	body := payload[10:]
	msg := &Message{Addressee: addr, Body: body}
	if i := strings.LastIndex(body, "{"); i >= 0 {
		msg.Body = body[:i]
		msg.MessageNumber = body[i+1:]
	}
	f.Message = msg
	return nil
}

// decodeTelemetry parses the basic 'T#seq,a1,a2,a3,a4,a5,bits'
// telemetry packet. Per APRS101 §13.
func decodeTelemetry(f *Frame, payload string) error {
	parts := strings.Split(payload, ",")
	if len(parts) < 1 {
		return fmt.Errorf("telemetry payload empty")
	}
	seq, err := strconv.Atoi(parts[0])
	if err != nil {
		// Some implementations zero-pad and include a
		// sequence range like "MIC" or "000" — fall back to 0
		// rather than erroring out.
		seq = 0
	}
	t := &Telemetry{SequenceNumber: seq}
	for i := 1; i < len(parts) && i <= 5; i++ {
		v, err := strconv.ParseFloat(parts[i], 64)
		if err != nil {
			continue
		}
		t.Analog = append(t.Analog, v)
	}
	if len(parts) > 6 {
		t.DigitalBits = parts[6]
	}
	f.Telemetry = t
	return nil
}

// parsePHG decodes a 4-digit PHG payload into the structured
// PHG view. Per APRS101 §7:
//
//	digit 1 : Power code (0-9) → P × P watts
//	digit 2 : Height code (0-9) → 10 × 2^h feet
//	digit 3 : Gain code (0-9) → dBi
//	digit 4 : Directivity code (0-8) → degrees
func parsePHG(s string) (*PHG, bool) {
	if len(s) != 4 {
		return nil, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, false
		}
	}
	p := int(s[0] - '0')
	h := int(s[1] - '0')
	g := int(s[2] - '0')
	d := int(s[3] - '0')
	return &PHG{
		PowerW:      p * p,
		HeightFt:    10 * (1 << h),
		GainDBi:     g,
		Directivity: phgDirectivity(d),
	}, true
}

func phgDirectivity(d int) string {
	switch d {
	case 0:
		return "Omnidirectional"
	case 1, 2, 3, 4, 5, 6, 7, 8:
		// d × 45° starting at 45° (NE) → 360° (N)
		return fmt.Sprintf("%d°", d*45)
	}
	return ""
}

// infoTypeName labels the first byte of the APRS info field
// per APRS101 §5 Table 5-1.
func infoTypeName(p string) string {
	switch p {
	case "!":
		return "Position without timestamp (no APRS messaging)"
	case "=":
		return "Position without timestamp (with APRS messaging)"
	case "/":
		return "Position with timestamp (no APRS messaging)"
	case "@":
		return "Position with timestamp (with APRS messaging)"
	case ":":
		return "Message"
	case ";":
		return "Object"
	case ")":
		return "Item"
	case "_":
		return "Weather report (positionless)"
	case ">":
		return "Status report"
	case "?":
		return "Query"
	case "<":
		return "Station capabilities"
	case "T":
		return "Telemetry"
	case "$":
		return "Raw GPS / Ultimeter 2000"
	case "&":
		return "Reserved (Map Feature)"
	case "{":
		return "User-defined APRS packet"
	case "}":
		return "Third-party traffic"
	case "`":
		return "Mic-E (current GPS data)"
	case "'":
		return "Mic-E (old GPS data)"
	case "\x1c":
		return "Mic-E (current GPS data, Rev. 0 beta)"
	case "\x1d":
		return "Mic-E (old GPS data, Rev. 0 beta)"
	}
	return fmt.Sprintf("Reserved (prefix %q)", p)
}

// symbolName decodes a small but operationally-important subset
// of APRS symbol-table+code combinations into a human-readable
// label. The full table is hundreds of entries (APRS101 Appx 2);
// here we cover the high-traffic ones operators see in real
// captures.
//
// Symbol table '/' is primary, '\\' is alternate. The full
// catalog is intentionally narrow — unknown combinations
// return "" so the caller can still surface the raw chars.
func symbolName(table, code string) string {
	primary := map[string]string{
		"/":  "Police station",
		"!":  "Digipeater",
		"\"": "Phone",
		"#":  "Digi (green star)",
		"$":  "Phone",
		"%":  "DX cluster",
		"&":  "HF gateway",
		"-":  "House (QTH)",
		">":  "Car",
		"<":  "Motorcycle",
		"R":  "Recreational vehicle",
		"U":  "Bus",
		"X":  "Helicopter",
		"Y":  "Yacht (sailboat)",
		"^":  "Aircraft (large)",
		"[":  "Jogger",
		"k":  "Truck",
		"v":  "Van",
	}
	alternate := map[string]string{
		"!": "Emergency",
		"#": "Number (digit)",
		"$": "ATM",
		"&": "Gateway",
		"-": "House (alternate)",
		">": "Car (alternate)",
		"O": "Balloon",
		"R": "Restaurant",
		"S": "Satellite",
		"U": "Sunny",
		"_": "Weather station",
		"a": "Ambulance",
		"b": "Bicycle",
		"c": "Coast guard",
		"f": "Fire engine",
		"h": "Hospital",
		"k": "School",
		"n": "Triangle",
		"p": "Rover",
		"r": "Repeater",
		"s": "Power boat",
		"u": "Truck (alternate)",
		"v": "Van (alternate)",
	}
	switch table {
	case "/":
		return primary[code]
	case "\\":
		return alternate[code]
	}
	// Overlay symbols (table char 0-9 or A-Z) use the alternate
	// table under the hood.
	if (table >= "0" && table <= "9") || (table >= "A" && table <= "Z") {
		return alternate[code]
	}
	return ""
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("aprs: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("aprs: invalid hex: %w", err)
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
