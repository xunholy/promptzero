// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ubx decodes the u-blox UBX binary protocol — the native
// binary message format that u-blox GNSS receivers speak as the
// compact alternative to NMEA 0183 text. It is the binary
// counterpart to internal/nmea (gps_nmea_decode): a GPS / GNSS
// capture from a u-blox module (the dominant GNSS chip family —
// NEO-6/7/8/9, the modules in countless wardriving / drone /
// tracker rigs) may be UBX rather than NMEA, and UBX is undecodable
// as text.
//
// # Wrap-vs-native judgement
//
//	Native. The UBX framing is a fixed, fully-public wire format
//	(two sync bytes 0xB5 0x62, a class + id, a little-endian
//	length, the payload, and an 8-bit Fletcher checksum) and the
//	NAV-PVT payload is a fixed 92-byte little-endian struct
//	documented in every u-blox receiver protocol spec. It is byte-
//	field extraction plus a two-byte checksum loop — a Go port is
//	a few hundred lines, so a runtime dependency on a UBX library
//	would not be justified. stdlib only, no new go.mod dep.
//
// # What this package covers
//
//   - UBX frame envelope: the 0xB5 0x62 sync, message class + id
//     (named for the common NAV classes), little-endian length,
//     and the 8-bit Fletcher checksum (CK_A / CK_B over class +
//     id + length + payload), validated. A capture with several
//     back-to-back frames decodes to a list; leading non-sync
//     bytes are skipped so a mid-stream capture still parses.
//   - NAV-PVT (class 0x01 id 0x07) — the flagship "navigation
//     position velocity time" message that bundles a complete
//     fix into one record: iTOW, the UTC date/time with its
//     validity flags and time accuracy, fix type (no-fix / dead-
//     reckoning / 2D / 3D / GNSS+DR / time-only) and the
//     gnssFixOK flag, satellites used, longitude / latitude
//     (1e-7 deg), height above ellipsoid and above mean sea
//     level, horizontal / vertical accuracy, the NED velocity
//     vector, ground speed, heading of motion, and position DOP.
//     Raw integer units (mm, mm/s, deg x 1e-7, deg x 1e-5,
//     0.01 DOP) are converted to metres / m·s⁻¹ / degrees.
//   - NAV-SAT (class 0x01 id 0x35) — per-satellite signal info:
//     for each tracked SV the constellation (gnssId → GPS /
//     SBAS / Galileo / BeiDou / QZSS / GLONASS / NavIC), the
//     satellite id, carrier-to-noise C/N0, elevation / azimuth,
//     pseudorange residual, the signal-quality indicator,
//     whether the SV is used in the solution, and its health.
//     Anomalous per-satellite C/N0 or geometry is a primary
//     tell of GPS spoofing / jamming, so this is the UBX
//     counterpart to the NMEA GSV decode.
//   - NAV-STATUS (class 0x01 id 0x03) — fix type + status flags
//     (gpsFixOK, differential solution, week-number / time-of-
//     week valid) + time-to-first-fix + receiver uptime.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Other UBX messages (NAV-POSLLH, NAV-VELNED, NAV-TIMEUTC,
//     RXM-*, CFG-*, MON-*, etc.) — the frame envelope is decoded
//     and the class/id named, but the body is surfaced as a raw
//     hex payload rather than guessed. The messages that carry a
//     full fix / satellite picture (NAV-PVT, NAV-SAT, NAV-STATUS)
//     are bodied out; the others can land in a future change
//     against a reference vector.
//   - UBX message *encoding* / polling (sending CFG-* to a live
//     receiver) — this is an offline read-only decoder.
//   - The RTCM / SPARTN correction streams a u-blox module can
//     also emit — separate protocols.
package ubx

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Message is one decoded UBX frame.
type Message struct {
	ClassID    int        `json:"class"`
	ClassHex   string     `json:"class_hex"`
	MessageID  int        `json:"id"`
	IDHex      string     `json:"id_hex"`
	Name       string     `json:"name"`
	Length     int        `json:"payload_length"`
	ChecksumOK bool       `json:"checksum_ok"`
	NavPVT     *NavPVT    `json:"nav_pvt,omitempty"`
	NavSAT     *NavSAT    `json:"nav_sat,omitempty"`
	NavStatus  *NavStatus `json:"nav_status,omitempty"`
	PayloadHex string     `json:"payload_hex,omitempty"`
	Notes      []string   `json:"notes,omitempty"`
}

// NavPVT is the decoded NAV-PVT (Navigation Position Velocity Time)
// payload — a complete GNSS fix in a single message.
type NavPVT struct {
	ITOWms         uint32  `json:"itow_ms"`
	UTC            string  `json:"utc,omitempty"`
	Year           int     `json:"year"`
	Month          int     `json:"month"`
	Day            int     `json:"day"`
	Hour           int     `json:"hour"`
	Minute         int     `json:"minute"`
	Second         int     `json:"second"`
	ValidDate      bool    `json:"valid_date"`
	ValidTime      bool    `json:"valid_time"`
	FullyResolved  bool    `json:"fully_resolved"`
	TimeAccuracyNs uint32  `json:"time_accuracy_ns"`
	FixType        int     `json:"fix_type"`
	FixTypeName    string  `json:"fix_type_name"`
	GNSSFixOK      bool    `json:"gnss_fix_ok"`
	NumSV          int     `json:"num_sv"`
	LongitudeDeg   float64 `json:"longitude_deg"`
	LatitudeDeg    float64 `json:"latitude_deg"`
	HeightM        float64 `json:"height_ellipsoid_m"`
	HeightMSLM     float64 `json:"height_msl_m"`
	HorizAccuracyM float64 `json:"horizontal_accuracy_m"`
	VertAccuracyM  float64 `json:"vertical_accuracy_m"`
	VelNorthMS     float64 `json:"velocity_north_ms"`
	VelEastMS      float64 `json:"velocity_east_ms"`
	VelDownMS      float64 `json:"velocity_down_ms"`
	GroundSpeedMS  float64 `json:"ground_speed_ms"`
	HeadingDeg     float64 `json:"heading_of_motion_deg"`
	PositionDOP    float64 `json:"position_dop"`
}

// NavSAT is the decoded NAV-SAT (satellite information) payload —
// per-satellite signal strength, elevation/azimuth, pseudorange
// residual and the quality / used / health flags. Anomalous
// per-satellite C/N0 or geometry is a primary tell of GPS
// spoofing / jamming, so this is the UBX counterpart to the NMEA
// GSV decode.
type NavSAT struct {
	ITOWms     uint32       `json:"itow_ms"`
	Version    int          `json:"version"`
	NumSVs     int          `json:"num_svs"`
	Satellites []NavSatInfo `json:"satellites"`
}

// NavSatInfo is one satellite row of a NAV-SAT message.
type NavSatInfo struct {
	GNSSID         int     `json:"gnss_id"`
	GNSSName       string  `json:"gnss_name"`
	SVID           int     `json:"sv_id"`
	CNoDBHz        int     `json:"cno_dbhz"`
	ElevationDeg   int     `json:"elevation_deg"`
	AzimuthDeg     int     `json:"azimuth_deg"`
	PseudoRangeRes float64 `json:"pseudorange_residual_m"`
	QualityInd     int     `json:"quality_indicator"`
	QualityName    string  `json:"quality_name"`
	Used           bool    `json:"used_in_solution"`
	Health         int     `json:"health"`
	HealthName     string  `json:"health_name"`
	EphemerisAvail bool    `json:"ephemeris_available"`
	AlmanacAvail   bool    `json:"almanac_available"`
}

// NavStatus is the decoded NAV-STATUS (receiver navigation status)
// payload — fix type + status flags + time-to-first-fix.
type NavStatus struct {
	ITOWms       uint32 `json:"itow_ms"`
	GPSFix       int    `json:"gps_fix"`
	GPSFixName   string `json:"gps_fix_name"`
	GPSFixOK     bool   `json:"gps_fix_ok"`
	DiffSoln     bool   `json:"differential_solution"`
	WeekNumSet   bool   `json:"week_number_set"`
	TimeOfWeekOK bool   `json:"time_of_week_set"`
	TTFFms       uint32 `json:"time_to_first_fix_ms"`
	UptimeMs     uint32 `json:"uptime_ms"`
}

const (
	syncChar1 = 0xB5
	syncChar2 = 0x62
)

// Decode parses every UBX frame found in the input. The input may
// be a hex string (whitespace / ':' / '-' separators and a '0x'
// prefix tolerated) carrying one or more back-to-back UBX frames.
func Decode(input string) ([]Message, error) {
	raw, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(raw) < 8 {
		return nil, fmt.Errorf("ubx: input too short (%d bytes) for a UBX frame (min 8)", len(raw))
	}
	var out []Message
	i := 0
	for i+8 <= len(raw) {
		// Scan for the next sync pair.
		if raw[i] != syncChar1 || raw[i+1] != syncChar2 {
			i++
			continue
		}
		msg, consumed, perr := parseFrame(raw[i:])
		if perr != nil {
			// Not a valid frame at this offset; skip the sync byte
			// and keep scanning rather than aborting the whole stream.
			i++
			continue
		}
		out = append(out, *msg)
		i += consumed
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ubx: no UBX frame found (expected 0x%02X 0x%02X sync)", syncChar1, syncChar2)
	}
	return out, nil
}

func parseFrame(b []byte) (*Message, int, error) {
	if len(b) < 8 {
		return nil, 0, fmt.Errorf("truncated header")
	}
	cls := int(b[2])
	id := int(b[3])
	length := int(binary.LittleEndian.Uint16(b[4:6]))
	frameLen := 6 + length + 2 // header + payload + checksum
	if len(b) < frameLen {
		return nil, 0, fmt.Errorf("truncated frame: need %d bytes, have %d", frameLen, len(b))
	}
	payload := b[6 : 6+length]
	ckA, ckB := fletcher(b[2 : 6+length]) // over class+id+length+payload
	gotA, gotB := b[6+length], b[6+length+1]
	m := &Message{
		ClassID:    cls,
		ClassHex:   fmt.Sprintf("0x%02X", cls),
		MessageID:  id,
		IDHex:      fmt.Sprintf("0x%02X", id),
		Name:       messageName(cls, id),
		Length:     length,
		ChecksumOK: ckA == gotA && ckB == gotB,
	}
	if !m.ChecksumOK {
		m.Notes = append(m.Notes, fmt.Sprintf(
			"checksum mismatch: computed %02X%02X, frame carries %02X%02X", ckA, ckB, gotA, gotB))
	}
	switch {
	case cls == 0x01 && id == 0x07:
		bodyOrHex(m, payload, func() (bool, error) {
			pvt, perr := decodeNavPVT(payload)
			m.NavPVT = pvt
			return pvt != nil, perr
		})
	case cls == 0x01 && id == 0x35:
		bodyOrHex(m, payload, func() (bool, error) {
			sat, perr := decodeNavSAT(payload)
			m.NavSAT = sat
			return sat != nil, perr
		})
	case cls == 0x01 && id == 0x03:
		bodyOrHex(m, payload, func() (bool, error) {
			st, perr := decodeNavStatus(payload)
			m.NavStatus = st
			return st != nil, perr
		})
	default:
		m.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		m.Notes = append(m.Notes, "message body not decoded (NAV-PVT / NAV-SAT / NAV-STATUS are bodied out); frame + checksum validated")
	}
	return m, frameLen, nil
}

// bodyOrHex runs a body decoder; on error it records the reason and
// falls back to surfacing the raw payload as hex.
func bodyOrHex(m *Message, payload []byte, decode func() (bool, error)) {
	ok, err := decode()
	if !ok || err != nil {
		if err != nil {
			m.Notes = append(m.Notes, err.Error())
		}
		m.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
	}
}

// fletcher computes the UBX 8-bit Fletcher checksum (CK_A, CK_B).
func fletcher(b []byte) (byte, byte) {
	var ckA, ckB byte
	for _, c := range b {
		ckA += c
		ckB += ckA
	}
	return ckA, ckB
}

func decodeNavPVT(p []byte) (*NavPVT, error) {
	if len(p) < 92 {
		return nil, fmt.Errorf("NAV-PVT payload truncated (%d bytes, need 92)", len(p))
	}
	u16 := func(o int) uint16 { return binary.LittleEndian.Uint16(p[o:]) }
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(p[o:]) }
	i32 := func(o int) int32 { return int32(binary.LittleEndian.Uint32(p[o:])) }

	valid := p[11]
	flags := p[21]
	v := &NavPVT{
		ITOWms:         u32(0),
		Year:           int(u16(4)),
		Month:          int(p[6]),
		Day:            int(p[7]),
		Hour:           int(p[8]),
		Minute:         int(p[9]),
		Second:         int(p[10]),
		ValidDate:      valid&0x01 != 0,
		ValidTime:      valid&0x02 != 0,
		FullyResolved:  valid&0x04 != 0,
		TimeAccuracyNs: u32(12),
		FixType:        int(p[20]),
		GNSSFixOK:      flags&0x01 != 0,
		NumSV:          int(p[23]),
		LongitudeDeg:   float64(i32(24)) * 1e-7,
		LatitudeDeg:    float64(i32(28)) * 1e-7,
		HeightM:        float64(i32(32)) / 1000.0,
		HeightMSLM:     float64(i32(36)) / 1000.0,
		HorizAccuracyM: float64(u32(40)) / 1000.0,
		VertAccuracyM:  float64(u32(44)) / 1000.0,
		VelNorthMS:     float64(i32(48)) / 1000.0,
		VelEastMS:      float64(i32(52)) / 1000.0,
		VelDownMS:      float64(i32(56)) / 1000.0,
		GroundSpeedMS:  float64(i32(60)) / 1000.0,
		HeadingDeg:     float64(i32(64)) * 1e-5,
		PositionDOP:    float64(u16(76)) * 0.01,
	}
	v.FixTypeName = fixTypeName(v.FixType)
	if v.ValidDate && v.ValidTime {
		v.UTC = fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",
			v.Year, v.Month, v.Day, v.Hour, v.Minute, v.Second)
	}
	return v, nil
}

func decodeNavSAT(p []byte) (*NavSAT, error) {
	if len(p) < 8 {
		return nil, fmt.Errorf("NAV-SAT payload truncated (%d bytes, need >=8)", len(p))
	}
	numSvs := int(p[5])
	need := 8 + 12*numSvs
	if len(p) < need {
		return nil, fmt.Errorf("NAV-SAT payload truncated (%d bytes, need %d for %d SVs)", len(p), need, numSvs)
	}
	s := &NavSAT{
		ITOWms:  binary.LittleEndian.Uint32(p[0:]),
		Version: int(p[4]),
		NumSVs:  numSvs,
	}
	for i := 0; i < numSvs; i++ {
		o := 8 + 12*i
		flags := binary.LittleEndian.Uint32(p[o+8:])
		qual := int(flags & 0x07)
		health := int((flags >> 4) & 0x03)
		sat := NavSatInfo{
			GNSSID:         int(p[o]),
			SVID:           int(p[o+1]),
			CNoDBHz:        int(p[o+2]),
			ElevationDeg:   int(int8(p[o+3])),
			AzimuthDeg:     int(int16(binary.LittleEndian.Uint16(p[o+4:]))),
			PseudoRangeRes: float64(int16(binary.LittleEndian.Uint16(p[o+6:]))) * 0.1,
			QualityInd:     qual,
			QualityName:    satQualityName(qual),
			Used:           flags&0x08 != 0,
			Health:         health,
			HealthName:     satHealthName(health),
			EphemerisAvail: flags&(1<<11) != 0,
			AlmanacAvail:   flags&(1<<12) != 0,
		}
		sat.GNSSName = gnssName(sat.GNSSID)
		s.Satellites = append(s.Satellites, sat)
	}
	return s, nil
}

func decodeNavStatus(p []byte) (*NavStatus, error) {
	if len(p) < 16 {
		return nil, fmt.Errorf("NAV-STATUS payload truncated (%d bytes, need 16)", len(p))
	}
	flags := p[5]
	st := &NavStatus{
		ITOWms:       binary.LittleEndian.Uint32(p[0:]),
		GPSFix:       int(p[4]),
		GPSFixOK:     flags&0x01 != 0,
		DiffSoln:     flags&0x02 != 0,
		WeekNumSet:   flags&0x04 != 0,
		TimeOfWeekOK: flags&0x08 != 0,
		TTFFms:       binary.LittleEndian.Uint32(p[8:]),
		UptimeMs:     binary.LittleEndian.Uint32(p[12:]),
	}
	st.GPSFixName = fixTypeName(st.GPSFix)
	return st, nil
}

// gnssName maps the UBX gnssId to its constellation name.
func gnssName(id int) string {
	switch id {
	case 0:
		return "GPS"
	case 1:
		return "SBAS"
	case 2:
		return "Galileo"
	case 3:
		return "BeiDou"
	case 4:
		return "IMES"
	case 5:
		return "QZSS"
	case 6:
		return "GLONASS"
	case 7:
		return "NavIC"
	}
	return fmt.Sprintf("gnssId %d", id)
}

// satQualityName labels the NAV-SAT signal-quality indicator.
func satQualityName(q int) string {
	switch q {
	case 0:
		return "no signal"
	case 1:
		return "searching signal"
	case 2:
		return "signal acquired"
	case 3:
		return "signal detected but unusable"
	case 4:
		return "code locked + time synced"
	case 5, 6, 7:
		return "code + carrier locked + time synced"
	}
	return fmt.Sprintf("quality %d", q)
}

// satHealthName labels the NAV-SAT 2-bit health field.
func satHealthName(h int) string {
	switch h {
	case 0:
		return "unknown"
	case 1:
		return "healthy"
	case 2:
		return "unhealthy"
	}
	return "reserved"
}

func fixTypeName(t int) string {
	switch t {
	case 0:
		return "no fix"
	case 1:
		return "dead reckoning only"
	case 2:
		return "2D fix"
	case 3:
		return "3D fix"
	case 4:
		return "GNSS + dead reckoning"
	case 5:
		return "time only"
	}
	return fmt.Sprintf("reserved (%d)", t)
}

// messageName names the common UBX classes/messages; an unknown
// class/id is labelled by its numeric class/id rather than guessed.
func messageName(cls, id int) string {
	switch cls {
	case 0x01: // NAV
		switch id {
		case 0x07:
			return "NAV-PVT"
		case 0x02:
			return "NAV-POSLLH"
		case 0x03:
			return "NAV-STATUS"
		case 0x12:
			return "NAV-VELNED"
		case 0x21:
			return "NAV-TIMEUTC"
		case 0x35:
			return "NAV-SAT"
		}
		return fmt.Sprintf("NAV-0x%02X", id)
	case 0x02:
		return fmt.Sprintf("RXM-0x%02X", id)
	case 0x05:
		return fmt.Sprintf("ACK-0x%02X", id)
	case 0x06:
		return fmt.Sprintf("CFG-0x%02X", id)
	case 0x0A:
		return fmt.Sprintf("MON-0x%02X", id)
	case 0x0D:
		return fmt.Sprintf("TIM-0x%02X", id)
	case 0x21:
		return fmt.Sprintf("LOG-0x%02X", id)
	case 0x27:
		return fmt.Sprintf("SEC-0x%02X", id)
	}
	return fmt.Sprintf("class 0x%02X id 0x%02X", cls, id)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	r := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = r.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("ubx: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ubx: input is not valid hex: %w", err)
	}
	return b, nil
}
