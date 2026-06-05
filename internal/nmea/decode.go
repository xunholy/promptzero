// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nmea decodes NMEA 0183 sentences — the line-based ASCII output of
// virtually every GPS/GNSS receiver, including the GPS modules used with the
// Flipper Zero and the ESP32 Marauder devboard. It is the offline complement to
// the device-side gps_* / marauder_nmea tools, which only stream the raw
// sentences: paste a captured NMEA log (a wardriving track, a geotag stream, a
// drone-telemetry dump) and get the fix — latitude/longitude, time, fix quality,
// satellites, speed/course, altitude — with the sentence checksum validated.
//
// Beyond the GPS/GNSS sentences it also decodes the marine-instrument
// sentences carried on a vessel's NMEA 0183 bus — heading (HDT / HDG),
// water speed and heading (VHW), depth (DBT / DPT), water temperature
// (MTW), wind (MWV / MWD) and rate of turn (ROT). NMEA 0183 is an
// unauthenticated bus, so a spoofed depth / heading / wind value injected
// onto it can mislead an autopilot or crew — the maritime counterpart to
// GPS spoofing — which makes decoding a captured marine NMEA stream a
// genuine integrity-analysis surface (companion to ais_nmea_decode).
//
// # Wrap-vs-native judgement
//
// Native. NMEA 0183 is a fully public, comma-delimited ASCII format with a
// trivial XOR checksum (the byte-wise XOR of everything between '$' and '*');
// each sentence is a fixed field layout. Parsing it is string splitting +
// ddmm.mmmm→decimal-degree arithmetic — there is nothing to wrap, and a
// third-party NMEA library (e.g. adrianmo/go-nmea) would be a runtime dep for a
// few hundred lines of field handling. Consistent with the other in-tree
// decoders (internal/aprs, internal/ais).
//
// # Verifiable / no confidently-wrong output
//
// The position/velocity/fix sentences (GGA, RMC, GLL, VTG, GSA, GSV) and the
// marine-instrument sentences (HDT, HDG, VHW, DBT, DPT, MTW, MWV, MWD, ROT)
// are anchored to the pynmea2 reference library: the canonical example
// sentences reproduce its decoded fields (latitude/longitude/time/speed/
// course/fix, and heading/depth/wind/temperature) exactly. The checksum is validated and surfaced (checksum_ok); a sentence
// with a bad or absent checksum is still parsed but flagged. An empty field
// (no fix yet) decodes to a null value, never a zero. An unrecognised sentence
// type is surfaced with its raw comma fields rather than guessed.
package nmea

import (
	"fmt"
	"strconv"
	"strings"
)

// Sentence is the decoded view of one NMEA 0183 sentence. Every measurement is
// a pointer so an absent field (an empty comma slot — e.g. no fix yet) is
// distinguishable from a genuine zero.
type Sentence struct {
	Raw        string `json:"raw"`
	Talker     string `json:"talker,omitempty"` // GP, GN, GL, GA, GB/BD, ...
	TalkerName string `json:"talker_name,omitempty"`
	Type       string `json:"type"` // GGA, RMC, GLL, VTG, GSA, GSV, ...
	TypeName   string `json:"type_name,omitempty"`
	ChecksumOK bool   `json:"checksum_ok"`
	Checksum   string `json:"checksum,omitempty"`

	LatitudeDeg  *float64 `json:"latitude_deg,omitempty"`
	LongitudeDeg *float64 `json:"longitude_deg,omitempty"`
	TimeUTC      string   `json:"time_utc,omitempty"`
	Date         string   `json:"date,omitempty"`

	FixQuality     *int   `json:"fix_quality,omitempty"` // GGA 0..8
	FixQualityName string `json:"fix_quality_name,omitempty"`
	Status         string `json:"status,omitempty"` // A=valid / V=void
	FixType        *int   `json:"fix_type,omitempty"`
	FixTypeName    string `json:"fix_type_name,omitempty"` // GSA 1/2/3

	NumSatellites   *int `json:"num_satellites,omitempty"`     // GGA
	SatellitesInVie *int `json:"satellites_in_view,omitempty"` // GSV

	HDOP *float64 `json:"hdop,omitempty"`
	PDOP *float64 `json:"pdop,omitempty"`
	VDOP *float64 `json:"vdop,omitempty"`

	AltitudeM       *float64 `json:"altitude_m,omitempty"`
	SpeedKnots      *float64 `json:"speed_knots,omitempty"`
	SpeedKmh        *float64 `json:"speed_kmh,omitempty"`
	CourseDeg       *float64 `json:"course_deg,omitempty"`
	CourseMagDeg    *float64 `json:"course_magnetic_deg,omitempty"`
	MagVariationDeg *float64 `json:"mag_variation_deg,omitempty"`

	// GST pseudorange-error statistics (metres / degrees).
	RMS            *float64 `json:"rms,omitempty"`
	StdDevMajorM   *float64 `json:"std_dev_major_m,omitempty"`
	StdDevMinorM   *float64 `json:"std_dev_minor_m,omitempty"`
	OrientationDeg *float64 `json:"orientation_deg,omitempty"`
	StdDevLatM     *float64 `json:"std_dev_lat_m,omitempty"`
	StdDevLonM     *float64 `json:"std_dev_lon_m,omitempty"`
	StdDevAltM     *float64 `json:"std_dev_alt_m,omitempty"`

	// Marine instrument sentences — heading / depth / wind / speed /
	// temperature carried on a vessel's NMEA 0183 bus alongside GPS.
	// (NMEA 0183 is unauthenticated, so a spoofed depth / heading /
	// wind value injected onto the bus can mislead an autopilot or
	// crew — the maritime counterpart to GPS spoofing.)
	HeadingTrueDeg   *float64 `json:"heading_true_deg,omitempty"`            // HDT / VHW
	HeadingMagDeg    *float64 `json:"heading_magnetic_deg,omitempty"`        // HDG / VHW
	MagDeviationDeg  *float64 `json:"mag_deviation_deg,omitempty"`           // HDG (signed E+/W-)
	WaterSpeedKnots  *float64 `json:"water_speed_knots,omitempty"`           // VHW
	WaterSpeedKmh    *float64 `json:"water_speed_kmh,omitempty"`             // VHW
	DepthMeters      *float64 `json:"depth_meters,omitempty"`                // DBT / DPT
	DepthFeet        *float64 `json:"depth_feet,omitempty"`                  // DBT
	DepthFathoms     *float64 `json:"depth_fathoms,omitempty"`               // DBT
	DepthOffsetM     *float64 `json:"depth_offset_m,omitempty"`              // DPT transducer offset
	WaterTempC       *float64 `json:"water_temp_c,omitempty"`                // MTW
	WindAngleDeg     *float64 `json:"wind_angle_deg,omitempty"`              // MWV
	WindReference    string   `json:"wind_reference,omitempty"`              // MWV R=relative / T=true
	WindSpeed        *float64 `json:"wind_speed,omitempty"`                  // MWV
	WindSpeedUnits   string   `json:"wind_speed_units,omitempty"`            // MWV K/M/N
	WindDirTrueDeg   *float64 `json:"wind_direction_true_deg,omitempty"`     // MWD
	WindDirMagDeg    *float64 `json:"wind_direction_magnetic_deg,omitempty"` // MWD
	WindSpeedKnots   *float64 `json:"wind_speed_knots,omitempty"`            // MWD
	WindSpeedMS      *float64 `json:"wind_speed_ms,omitempty"`               // MWD
	RateOfTurnDegMin *float64 `json:"rate_of_turn_deg_min,omitempty"`        // ROT

	// Satellites carries the per-satellite detail of a GSV sentence.
	Satellites []Satellite `json:"satellites,omitempty"`

	Fields []string `json:"fields,omitempty"` // raw comma fields for an unrecognised type
	Note   string   `json:"note,omitempty"`
}

// Satellite is one entry of a GSV (satellites-in-view) sentence. SNR is nil when
// the satellite is tracked but not used (blank SNR field). Useful for GPS
// signal-quality and spoofing/jamming analysis (anomalous SNR or geometry).
type Satellite struct {
	PRN          int  `json:"prn"`
	ElevationDeg *int `json:"elevation_deg,omitempty"`
	AzimuthDeg   *int `json:"azimuth_deg,omitempty"`
	SNR          *int `json:"snr_db,omitempty"`
}

var talkerNames = map[string]string{
	"GP": "GPS", "GN": "GNSS (combined)", "GL": "GLONASS", "GA": "Galileo",
	"GB": "BeiDou", "BD": "BeiDou", "GQ": "QZSS", "GI": "NavIC",
}

var typeNames = map[string]string{
	"GGA": "Global Positioning System Fix Data",
	"RMC": "Recommended Minimum Navigation Information",
	"GLL": "Geographic Position — Latitude/Longitude",
	"VTG": "Track Made Good and Ground Speed",
	"GSA": "GNSS DOP and Active Satellites",
	"GSV": "GNSS Satellites in View",
	"GST": "GNSS Pseudorange Error Statistics",
	"ZDA": "Time and Date",
	"HDT": "Heading — True",
	"HDG": "Heading, Deviation & Variation",
	"VHW": "Water Speed and Heading",
	"DBT": "Depth Below Transducer",
	"DPT": "Depth of Water",
	"MTW": "Water Temperature",
	"MWV": "Wind Speed and Angle",
	"MWD": "Wind Direction and Speed",
	"ROT": "Rate of Turn",
}

var fixQualityNames = map[int]string{
	0: "invalid", 1: "GPS fix (SPS)", 2: "DGPS fix", 3: "PPS fix",
	4: "Real-Time Kinematic", 5: "Float RTK", 6: "estimated (dead reckoning)",
	7: "manual input", 8: "simulation",
}

// Decode parses one or more NMEA 0183 sentences (newline-separated). It returns
// the decoded sentences in order; a malformed line yields a Sentence with a Note
// rather than failing the whole batch.
func Decode(in string) ([]*Sentence, error) {
	var out []*Sentence
	for _, line := range strings.Split(in, "\n") {
		line = strings.TrimRight(strings.TrimSpace(line), "\r")
		if line == "" {
			continue
		}
		out = append(out, decodeLine(line))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("nmea: no sentences found")
	}
	return out, nil
}

func decodeLine(line string) *Sentence {
	s := &Sentence{Raw: line}
	start := strings.IndexAny(line, "$!")
	if start < 0 {
		s.Note = "not an NMEA sentence (no leading '$')"
		return s
	}
	body := line[start+1:]

	// Split off the *HH checksum, if present, and validate it (XOR of the
	// bytes between '$' and '*').
	payload := body
	if star := strings.LastIndexByte(body, '*'); star >= 0 {
		payload = body[:star]
		s.Checksum = strings.TrimSpace(body[star+1:])
		s.ChecksumOK = validChecksum(payload, s.Checksum)
	} else {
		s.Note = "no checksum present"
	}

	fields := strings.Split(payload, ",")
	addr := fields[0]
	if len(addr) >= 5 {
		s.Talker = addr[:2]
		s.TalkerName = talkerNames[s.Talker]
		s.Type = addr[2:]
	} else {
		s.Type = addr
	}
	s.TypeName = typeNames[s.Type]

	switch s.Type {
	case "GGA":
		decodeGGA(s, fields)
	case "RMC":
		decodeRMC(s, fields)
	case "GLL":
		decodeGLL(s, fields)
	case "VTG":
		decodeVTG(s, fields)
	case "GSA":
		decodeGSA(s, fields)
	case "GSV":
		decodeGSV(s, fields)
	case "GST":
		decodeGST(s, fields)
	case "ZDA":
		decodeZDA(s, fields)
	case "HDT":
		decodeHDT(s, fields)
	case "HDG":
		decodeHDG(s, fields)
	case "VHW":
		decodeVHW(s, fields)
	case "DBT":
		decodeDBT(s, fields)
	case "DPT":
		decodeDPT(s, fields)
	case "MTW":
		decodeMTW(s, fields)
	case "MWV":
		decodeMWV(s, fields)
	case "MWD":
		decodeMWD(s, fields)
	case "ROT":
		decodeROT(s, fields)
	default:
		s.Fields = fields[1:]
		if s.Note == "" {
			s.Note = "sentence type not individually decoded; raw fields surfaced"
		}
	}
	return s
}

// validChecksum reports whether the given two-hex-digit checksum equals the XOR
// of every byte of payload (the content between '$' and '*').
func validChecksum(payload, want string) bool {
	if len(want) != 2 {
		return false
	}
	var x byte
	for i := 0; i < len(payload); i++ {
		x ^= payload[i]
	}
	got, err := strconv.ParseUint(want, 16, 16)
	return err == nil && byte(got) == x
}

func decodeGGA(s *Sentence, f []string) {
	// time, lat, N/S, lon, E/W, fixqual, numsats, hdop, alt, M, ...
	s.TimeUTC = field(f, 1, parseTime)
	s.LatitudeDeg = latLon(f, 2, 3, true)
	s.LongitudeDeg = latLon(f, 4, 5, false)
	s.FixQuality = intPtr(f, 6)
	if s.FixQuality != nil {
		s.FixQualityName = fixQualityNames[*s.FixQuality]
	}
	s.NumSatellites = intPtr(f, 7)
	s.HDOP = floatPtr(f, 8)
	s.AltitudeM = floatPtr(f, 9)
}

func decodeRMC(s *Sentence, f []string) {
	// time, status, lat, N/S, lon, E/W, speed(kn), course, date, magvar, E/W
	s.TimeUTC = field(f, 1, parseTime)
	s.Status = statusName(at(f, 2))
	s.LatitudeDeg = latLon(f, 3, 4, true)
	s.LongitudeDeg = latLon(f, 5, 6, false)
	s.SpeedKnots = floatPtr(f, 7)
	s.CourseDeg = floatPtr(f, 8)
	s.Date = field(f, 9, parseDate)
	s.MagVariationDeg = signedMagVar(f, 10, 11)
}

func decodeGLL(s *Sentence, f []string) {
	// lat, N/S, lon, E/W, time, status
	s.LatitudeDeg = latLon(f, 1, 2, true)
	s.LongitudeDeg = latLon(f, 3, 4, false)
	s.TimeUTC = field(f, 5, parseTime)
	s.Status = statusName(at(f, 6))
}

func decodeVTG(s *Sentence, f []string) {
	// course(T), T, course(M), M, speed(kn), N, speed(kmh), K
	s.CourseDeg = floatPtr(f, 1)
	s.CourseMagDeg = floatPtr(f, 3)
	s.SpeedKnots = floatPtr(f, 5)
	s.SpeedKmh = floatPtr(f, 7)
}

func decodeGSA(s *Sentence, f []string) {
	// mode(A/M), fixtype(1/2/3), 12x PRN, pdop, hdop, vdop
	s.FixType = intPtr(f, 2)
	if s.FixType != nil {
		switch *s.FixType {
		case 1:
			s.FixTypeName = "no fix"
		case 2:
			s.FixTypeName = "2D fix"
		case 3:
			s.FixTypeName = "3D fix"
		}
	}
	n := len(f)
	if n >= 3 {
		s.PDOP = floatPtr(f, n-3)
		s.HDOP = floatPtr(f, n-2)
		s.VDOP = floatPtr(f, n-1)
	}
}

func decodeGSV(s *Sentence, f []string) {
	// num_messages, msg_num, sats_in_view, then groups of 4:
	// [PRN, elevation_deg, azimuth_deg, SNR_dB] per satellite.
	s.SatellitesInVie = intPtr(f, 3)
	for i := 4; i+3 < len(f); i += 4 {
		prn := intPtr(f, i)
		if prn == nil {
			continue // empty slot
		}
		s.Satellites = append(s.Satellites, Satellite{
			PRN:          *prn,
			ElevationDeg: intPtr(f, i+1),
			AzimuthDeg:   intPtr(f, i+2),
			SNR:          intPtr(f, i+3), // nil when tracked-but-unused (blank SNR)
		})
	}
}

func decodeGST(s *Sentence, f []string) {
	// time, rms, stddev_major, stddev_minor, orientation, stddev_lat,
	// stddev_lon, stddev_alt
	s.TimeUTC = field(f, 1, parseTime)
	s.RMS = floatPtr(f, 2)
	s.StdDevMajorM = floatPtr(f, 3)
	s.StdDevMinorM = floatPtr(f, 4)
	s.OrientationDeg = floatPtr(f, 5)
	s.StdDevLatM = floatPtr(f, 6)
	s.StdDevLonM = floatPtr(f, 7)
	s.StdDevAltM = floatPtr(f, 8)
}

func decodeZDA(s *Sentence, f []string) {
	// time, day, month, year, local_zone_hours, local_zone_minutes
	s.TimeUTC = field(f, 1, parseTime)
	day, mon, yr := intPtr(f, 2), intPtr(f, 3), intPtr(f, 4)
	if day != nil && mon != nil && yr != nil {
		s.Date = fmt.Sprintf("%04d-%02d-%02d", *yr, *mon, *day)
	}
}

func decodeHDT(s *Sentence, f []string) {
	// heading, T
	s.HeadingTrueDeg = floatPtr(f, 1)
}

func decodeHDG(s *Sentence, f []string) {
	// magnetic_sensor_heading, deviation, dev_dir(E/W), variation, var_dir(E/W)
	s.HeadingMagDeg = floatPtr(f, 1)
	s.MagDeviationDeg = signedMagVar(f, 2, 3)
	s.MagVariationDeg = signedMagVar(f, 4, 5)
}

func decodeVHW(s *Sentence, f []string) {
	// heading_true, T, heading_mag, M, speed_knots, N, speed_kmh, K
	s.HeadingTrueDeg = floatPtr(f, 1)
	s.HeadingMagDeg = floatPtr(f, 3)
	s.WaterSpeedKnots = floatPtr(f, 5)
	s.WaterSpeedKmh = floatPtr(f, 7)
}

func decodeDBT(s *Sentence, f []string) {
	// depth_feet, f, depth_meters, M, depth_fathoms, F
	s.DepthFeet = floatPtr(f, 1)
	s.DepthMeters = floatPtr(f, 3)
	s.DepthFathoms = floatPtr(f, 5)
}

func decodeDPT(s *Sentence, f []string) {
	// depth_meters, transducer_offset_meters, [max_range_meters]
	s.DepthMeters = floatPtr(f, 1)
	s.DepthOffsetM = floatPtr(f, 2)
}

func decodeMTW(s *Sentence, f []string) {
	// temperature, C
	s.WaterTempC = floatPtr(f, 1)
}

func decodeMWV(s *Sentence, f []string) {
	// wind_angle, reference(R/T), wind_speed, units(K/M/N), status(A/V)
	s.WindAngleDeg = floatPtr(f, 1)
	s.WindReference = at(f, 2)
	s.WindSpeed = floatPtr(f, 3)
	s.WindSpeedUnits = at(f, 4)
	s.Status = at(f, 5)
}

func decodeMWD(s *Sentence, f []string) {
	// dir_true, T, dir_mag, M, speed_knots, N, speed_ms, M
	s.WindDirTrueDeg = floatPtr(f, 1)
	s.WindDirMagDeg = floatPtr(f, 3)
	s.WindSpeedKnots = floatPtr(f, 5)
	s.WindSpeedMS = floatPtr(f, 7)
}

func decodeROT(s *Sentence, f []string) {
	// rate_of_turn (deg/min, bow-up positive), status(A/V)
	s.RateOfTurnDegMin = floatPtr(f, 1)
	s.Status = at(f, 2)
}

// latLon converts the ddmm.mmmm / dddmm.mmmm field at index valIdx plus the
// hemisphere letter at hemIdx into signed decimal degrees. Latitude uses 2
// degree digits, longitude 3. An empty field returns nil.
func latLon(f []string, valIdx, hemIdx int, isLat bool) *float64 {
	v := at(f, valIdx)
	hem := at(f, hemIdx)
	if v == "" || hem == "" {
		return nil
	}
	degLen := 3
	if isLat {
		degLen = 2
	}
	if len(v) < degLen+2 {
		return nil
	}
	deg, err1 := strconv.ParseFloat(v[:degLen], 64)
	min, err2 := strconv.ParseFloat(v[degLen:], 64)
	if err1 != nil || err2 != nil {
		return nil
	}
	d := deg + min/60.0
	if hem == "S" || hem == "W" {
		d = -d
	}
	return &d
}

func signedMagVar(f []string, valIdx, hemIdx int) *float64 {
	p := floatPtr(f, valIdx)
	if p == nil {
		return nil
	}
	if at(f, hemIdx) == "W" {
		v := -*p
		return &v
	}
	return p
}

func at(f []string, i int) string {
	if i < 0 || i >= len(f) {
		return ""
	}
	return strings.TrimSpace(f[i])
}

func field(f []string, i int, conv func(string) string) string {
	v := at(f, i)
	if v == "" {
		return ""
	}
	return conv(v)
}

func intPtr(f []string, i int) *int {
	v := at(f, i)
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return &n
}

func floatPtr(f []string, i int) *float64 {
	v := at(f, i)
	if v == "" {
		return nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return nil
	}
	return &n
}

// parseTime turns "HHMMSS" or "HHMMSS.ss" into "HH:MM:SS".
func parseTime(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	if len(v) < 6 {
		return v
	}
	return v[0:2] + ":" + v[2:4] + ":" + v[4:6]
}

// parseDate turns "DDMMYY" into "YYYY-MM-DD" (NMEA years 70-99 → 19xx, else 20xx).
func parseDate(v string) string {
	if len(v) != 6 {
		return v
	}
	dd, mm, yy := v[0:2], v[2:4], v[4:6]
	century := "20"
	if y, err := strconv.Atoi(yy); err == nil && y >= 70 {
		century = "19"
	}
	return century + yy + "-" + mm + "-" + dd
}

func statusName(s string) string {
	switch s {
	case "A":
		return "A (valid)"
	case "V":
		return "V (void)"
	}
	return s
}
