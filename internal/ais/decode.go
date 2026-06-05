// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ais decodes AIS (Automatic Identification System)
// NMEA 0183 sentences carried over the standard AIS VHF
// channels (161.975 / 162.025 MHz) — the maritime counterpart
// of ADS-B, mandatory on commercial vessels >300 GT and on
// most passenger ships under SOLAS Chapter V.
//
// # Wrap-vs-native judgement
//
// Native. AIS is defined by the public ITU-R M.1371-5 standard
// (with the NMEA 0183 wire envelope per IEC 61162-1). Every
// payload is 6-bit ASCII-packed binary with well-documented
// per-message-type field layouts. Pasting a sentence from
// rtl_ais / AIS-catcher / NMEA-feed dump is enough — no
// vendor SDK, no handshake, no cryptography.
//
// # What this package covers
//
//   - NMEA 0183 envelope: !AIVDM / !AIVDO talker IDs,
//     fragment count + index + sequence ID + AIS channel
//     (A/B), payload field, padding bits, and XOR checksum.
//     Multi-fragment messages (Type 5 is always 2 fragments)
//     are reassembled when newline-separated sentences are
//     passed together.
//   - 6-bit ASCII payload unpack: the canonical AIS bit-soup
//     decode (char - 48; if >40 subtract another 8) followed
//     by 6-bit-at-a-time packing into a bit string with the
//     trailing padding bits stripped.
//   - Type-1, Type-2, Type-3 Position Report Class A: MMSI,
//     Navigation Status (16-state table — Under Way Using
//     Engine, At Anchor, Not Under Command, Restricted
//     Manoeuvrability, etc.), Rate Of Turn, Speed Over
//     Ground, Position Accuracy, Longitude / Latitude
//     (signed 28/27 bits at 1/10000 minute), Course Over
//     Ground, True Heading, Timestamp, Manoeuvre Indicator,
//     RAIM flag.
//   - Type-4 Base Station Report: MMSI, UTC year / month /
//     day / hour / minute / second + position.
//   - Type-5 Static & Voyage: MMSI, AIS version, IMO
//     number, callsign, vessel name, ship type (full 100-
//     entry table), dimensions to bow / stern / port /
//     starboard, EPFD type, ETA (month / day / hour /
//     minute), draught, destination. Reassembled from the
//     2 fragments that this type always uses.
//   - Type-18 Standard Class B Position Report: the
//     smaller-vessel position broadcast with MMSI, Speed,
//     Position Accuracy, Longitude / Latitude, Course,
//     True Heading, Timestamp, RAIM.
//   - Type-19 Extended Class B Position Report: Type-18's
//     position fields plus the vessel name, ship type and
//     dimensions, so a single 312-bit message carries both
//     dynamic and static data for the craft.
//   - Type-21 Aid-to-Navigation Report: aid type (32-entry
//     table — buoys, lighthouses, RACONs, beacons), name
//     (with the 0-88-bit extension field), position,
//     dimensions, EPFD, timestamp, and the off-position /
//     virtual-aid / assigned flags that distinguish a real
//     mark from a transmitted "virtual" AtoN.
//   - Type-24 Static Data Class B: Part A (vessel name)
//     or Part B (ship type + vendor ID + callsign +
//     dimensions or mother-ship MMSI).
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Type 6 / 8 Binary Addressed/Broadcast Message — the
//     application-specific payloads are vendor-defined and
//     would each need their own decoder; the type label and
//     destination MMSI / DAC / FI fields are surfaced but
//     the body is exposed as a raw hex string.
//   - Type 9 SAR Aircraft Position, Type 11 UTC/Date
//     Response, Type 14 Safety Related Broadcast, Type
//     15 Interrogation, Type 16 Assigned-Mode Command,
//     Type 17 DGNSS Broadcast, Type 20 Data Link
//     Management, Type 22 Channel Management, Type 23
//     Group Assignment, Type 25 / 26 / 27 Long-Range
//     Application — recognised by name but body decode
//     deferred.
//   - Live demodulation from raw I/Q samples — sentences
//     must be pre-decoded to NMEA text by an upstream
//     receiver (rtl_ais / AIS-catcher / AISHub).
package ais

import (
	"fmt"
	"strconv"
	"strings"
)

// Message is one decoded AIS message.
//
// Exactly one of the typed sub-pointers is set per call (the
// one matching MessageType). For unsupported types the body
// stays nil but TypeName labels what was seen.
type Message struct {
	Sentences       []string                `json:"sentences"`
	Channel         string                  `json:"channel"`
	MessageType     int                     `json:"message_type"`
	TypeName        string                  `json:"type_name"`
	Repeat          int                     `json:"repeat_indicator"`
	MMSI            int                     `json:"mmsi"`
	PositionClassA  *PositionReportClassA   `json:"position_class_a,omitempty"`
	BaseStation     *BaseStationReport      `json:"base_station,omitempty"`
	StaticAndVoyage *StaticAndVoyageData    `json:"static_and_voyage,omitempty"`
	PositionClassB  *PositionReportClassB   `json:"position_class_b,omitempty"`
	ExtendedClassB  *ExtendedPositionClassB `json:"extended_class_b,omitempty"`
	StaticClassB    *StaticDataReportClassB `json:"static_class_b,omitempty"`
	AidToNavigation *AidToNavigationReport  `json:"aid_to_navigation,omitempty"`
}

// PositionReportClassA is the Type-1/2/3 body — the high-
// frequency position broadcast from SOLAS-class vessels.
type PositionReportClassA struct {
	NavStatus           int      `json:"nav_status"`
	NavStatusName       string   `json:"nav_status_name"`
	RateOfTurnDegPerMin *int     `json:"rate_of_turn_deg_per_min,omitempty"`
	SpeedOverGroundKts  *float64 `json:"speed_over_ground_kts,omitempty"`
	PositionAccuracy    bool     `json:"position_accuracy"`
	LongitudeDeg        *float64 `json:"longitude_deg,omitempty"`
	LatitudeDeg         *float64 `json:"latitude_deg,omitempty"`
	CourseOverGroundDeg *float64 `json:"course_over_ground_deg,omitempty"`
	TrueHeadingDeg      *int     `json:"true_heading_deg,omitempty"`
	Timestamp           int      `json:"timestamp_sec"`
	ManeuverIndicator   int      `json:"maneuver_indicator"`
	RAIM                bool     `json:"raim"`
}

// BaseStationReport is Type-4 — UTC time + position of a
// shore-side AIS base station.
type BaseStationReport struct {
	Year             int      `json:"year"`
	Month            int      `json:"month"`
	Day              int      `json:"day"`
	Hour             int      `json:"hour"`
	Minute           int      `json:"minute"`
	Second           int      `json:"second"`
	PositionAccuracy bool     `json:"position_accuracy"`
	LongitudeDeg     *float64 `json:"longitude_deg,omitempty"`
	LatitudeDeg      *float64 `json:"latitude_deg,omitempty"`
	EPFDType         int      `json:"epfd_type"`
	EPFDName         string   `json:"epfd_name"`
	RAIM             bool     `json:"raim"`
}

// StaticAndVoyageData is Type-5 — assembled from the two
// fragments this type always uses.
type StaticAndVoyageData struct {
	AISVersion     int     `json:"ais_version"`
	IMONumber      int     `json:"imo_number"`
	CallSign       string  `json:"call_sign"`
	VesselName     string  `json:"vessel_name"`
	ShipType       int     `json:"ship_type"`
	ShipTypeName   string  `json:"ship_type_name"`
	DimensionBow   int     `json:"dimension_to_bow_m"`
	DimensionStern int     `json:"dimension_to_stern_m"`
	DimensionPort  int     `json:"dimension_to_port_m"`
	DimensionStbd  int     `json:"dimension_to_starboard_m"`
	EPFDType       int     `json:"epfd_type"`
	EPFDName       string  `json:"epfd_name"`
	ETAMonth       int     `json:"eta_month"`
	ETADay         int     `json:"eta_day"`
	ETAHour        int     `json:"eta_hour"`
	ETAMinute      int     `json:"eta_minute"`
	DraughtM       float64 `json:"draught_m"`
	Destination    string  `json:"destination"`
	DTE            int     `json:"dte"`
}

// PositionReportClassB is Type-18 — the lighter, more frequent
// position broadcast from Class-B (small-vessel) transponders.
type PositionReportClassB struct {
	SpeedOverGroundKts  *float64 `json:"speed_over_ground_kts,omitempty"`
	PositionAccuracy    bool     `json:"position_accuracy"`
	LongitudeDeg        *float64 `json:"longitude_deg,omitempty"`
	LatitudeDeg         *float64 `json:"latitude_deg,omitempty"`
	CourseOverGroundDeg *float64 `json:"course_over_ground_deg,omitempty"`
	TrueHeadingDeg      *int     `json:"true_heading_deg,omitempty"`
	Timestamp           int      `json:"timestamp_sec"`
	CSUnit              bool     `json:"cs_unit"`
	DisplayFlag         bool     `json:"display_flag"`
	DSCFlag             bool     `json:"dsc_flag"`
	BandFlag            bool     `json:"band_flag"`
	Msg22Flag           bool     `json:"msg22_flag"`
	Assigned            bool     `json:"assigned"`
	RAIM                bool     `json:"raim"`
}

// ExtendedPositionClassB is Type-19 — the richer Class-B
// position broadcast that, unlike Type-18, also carries the
// vessel name, ship type and dimensions in a single 312-bit
// message (so it doubles as static data for small craft).
type ExtendedPositionClassB struct {
	SpeedOverGroundKts  *float64 `json:"speed_over_ground_kts,omitempty"`
	PositionAccuracy    bool     `json:"position_accuracy"`
	LongitudeDeg        *float64 `json:"longitude_deg,omitempty"`
	LatitudeDeg         *float64 `json:"latitude_deg,omitempty"`
	CourseOverGroundDeg *float64 `json:"course_over_ground_deg,omitempty"`
	TrueHeadingDeg      *int     `json:"true_heading_deg,omitempty"`
	Timestamp           int      `json:"timestamp_sec"`
	VesselName          string   `json:"vessel_name"`
	ShipType            int      `json:"ship_type"`
	ShipTypeName        string   `json:"ship_type_name"`
	DimensionBow        int      `json:"dimension_to_bow_m"`
	DimensionStern      int      `json:"dimension_to_stern_m"`
	DimensionPort       int      `json:"dimension_to_port_m"`
	DimensionStbd       int      `json:"dimension_to_starboard_m"`
	EPFDType            int      `json:"epfd_type"`
	EPFDName            string   `json:"epfd_name"`
	RAIM                bool     `json:"raim"`
	DTE                 int      `json:"dte"`
	Assigned            bool     `json:"assigned"`
}

// AidToNavigationReport is Type-21 — broadcast by (or on behalf
// of) a navigation aid: a buoy, lighthouse, RACON, beacon or a
// "virtual" AtoN that exists only as a transmitted mark. The
// name can overflow into a 0-88-bit extension field.
type AidToNavigationReport struct {
	AidType          int      `json:"aid_type"`
	AidTypeName      string   `json:"aid_type_name"`
	Name             string   `json:"name"`
	NameExtension    string   `json:"name_extension,omitempty"`
	PositionAccuracy bool     `json:"position_accuracy"`
	LongitudeDeg     *float64 `json:"longitude_deg,omitempty"`
	LatitudeDeg      *float64 `json:"latitude_deg,omitempty"`
	DimensionBow     int      `json:"dimension_to_bow_m"`
	DimensionStern   int      `json:"dimension_to_stern_m"`
	DimensionPort    int      `json:"dimension_to_port_m"`
	DimensionStbd    int      `json:"dimension_to_starboard_m"`
	EPFDType         int      `json:"epfd_type"`
	EPFDName         string   `json:"epfd_name"`
	Timestamp        int      `json:"timestamp_sec"`
	OffPosition      bool     `json:"off_position"`
	RAIM             bool     `json:"raim"`
	VirtualAid       bool     `json:"virtual_aid"`
	Assigned         bool     `json:"assigned"`
}

// StaticDataReportClassB is Type-24 — Part A (vessel name) or
// Part B (ship type + dimensions). PartA / PartB are mutually
// exclusive in a single sentence.
type StaticDataReportClassB struct {
	PartNumber     int    `json:"part_number"`
	VesselName     string `json:"vessel_name,omitempty"`
	ShipType       int    `json:"ship_type,omitempty"`
	ShipTypeName   string `json:"ship_type_name,omitempty"`
	VendorID       string `json:"vendor_id,omitempty"`
	CallSign       string `json:"call_sign,omitempty"`
	DimensionBow   int    `json:"dimension_to_bow_m,omitempty"`
	DimensionStern int    `json:"dimension_to_stern_m,omitempty"`
	DimensionPort  int    `json:"dimension_to_port_m,omitempty"`
	DimensionStbd  int    `json:"dimension_to_starboard_m,omitempty"`
	MothershipMMSI int    `json:"mothership_mmsi,omitempty"`
}

// Decode parses one or more AIS NMEA sentences (newline-
// separated) into a single Message. Multi-fragment payloads
// are reassembled in input order — pass all fragments in one
// call.
func Decode(input string) (*Message, error) {
	lines := splitSentences(input)
	if len(lines) == 0 {
		return nil, fmt.Errorf("ais: empty input")
	}
	var payload strings.Builder
	var paddingBits int
	var channel string
	expectedTotal := 0
	for i, raw := range lines {
		s, err := parseSentence(raw)
		if err != nil {
			return nil, fmt.Errorf("ais: sentence %d: %w", i+1, err)
		}
		if i == 0 {
			expectedTotal = s.FragmentCount
			channel = s.Channel
		} else if s.FragmentCount != expectedTotal {
			return nil, fmt.Errorf(
				"ais: sentence %d declares fragment count %d but first sentence said %d",
				i+1, s.FragmentCount, expectedTotal)
		}
		if s.FragmentIndex != i+1 {
			return nil, fmt.Errorf(
				"ais: sentence %d carries fragment index %d (out of order)",
				i+1, s.FragmentIndex)
		}
		payload.WriteString(s.Payload)
		// Padding only applies to the last fragment.
		if i == len(lines)-1 {
			paddingBits = s.PaddingBits
		}
	}
	if expectedTotal != len(lines) {
		return nil, fmt.Errorf(
			"ais: declared %d fragments but %d sentence(s) provided",
			expectedTotal, len(lines))
	}
	bits, err := unpack6BitASCII(payload.String(), paddingBits)
	if err != nil {
		return nil, fmt.Errorf("ais: payload unpack: %w", err)
	}
	if len(bits) < 38 {
		return nil, fmt.Errorf("ais: payload too short (%d bits) for any documented type", len(bits))
	}
	typ := readUint(bits, 0, 6)
	m := &Message{
		Sentences:   lines,
		Channel:     channel,
		MessageType: typ,
		TypeName:    messageTypeName(typ),
		Repeat:      readUint(bits, 6, 2),
		MMSI:        readUint(bits, 8, 30),
	}
	switch typ {
	case 1, 2, 3:
		m.PositionClassA = decodePositionClassA(bits)
	case 4:
		m.BaseStation = decodeBaseStation(bits)
	case 5:
		if len(bits) < 424 {
			return nil, fmt.Errorf("ais: Type 5 payload truncated (%d bits, need 424)", len(bits))
		}
		m.StaticAndVoyage = decodeStaticAndVoyage(bits)
	case 18:
		m.PositionClassB = decodePositionClassB(bits)
	case 19:
		if len(bits) < 311 {
			return nil, fmt.Errorf("ais: Type 19 payload truncated (%d bits, need 311)", len(bits))
		}
		m.ExtendedClassB = decodeExtendedClassB(bits)
	case 21:
		if len(bits) < 272 {
			return nil, fmt.Errorf("ais: Type 21 payload truncated (%d bits, need 272)", len(bits))
		}
		m.AidToNavigation = decodeAidToNavigation(bits)
	case 24:
		m.StaticClassB = decodeStaticClassB(bits, m.MMSI)
	}
	return m, nil
}

// Sentence is a parsed !AIVDM / !AIVDO line.
type Sentence struct {
	Talker        string
	FragmentCount int
	FragmentIndex int
	SequenceID    string
	Channel       string
	Payload       string
	PaddingBits   int
}

func parseSentence(raw string) (*Sentence, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("empty sentence")
	}
	if !strings.HasPrefix(s, "!AIVDM") && !strings.HasPrefix(s, "!AIVDO") {
		return nil, fmt.Errorf("expected !AIVDM or !AIVDO prefix")
	}
	star := strings.LastIndex(s, "*")
	if star < 0 || star >= len(s)-2 {
		return nil, fmt.Errorf("missing checksum suffix")
	}
	body := s[1:star]
	want, err := strconv.ParseUint(s[star+1:], 16, 8)
	if err != nil {
		return nil, fmt.Errorf("malformed checksum %q: %w", s[star+1:], err)
	}
	got := nmeaChecksum(body)
	if byte(want) != got {
		return nil, fmt.Errorf("checksum mismatch: declared %02X, computed %02X", want, got)
	}
	parts := strings.Split(body, ",")
	if len(parts) < 7 {
		return nil, fmt.Errorf("expected 7 comma fields, got %d", len(parts))
	}
	out := &Sentence{
		Talker:     parts[0],
		SequenceID: parts[3],
		Channel:    parts[4],
		Payload:    parts[5],
	}
	if out.FragmentCount, err = strconv.Atoi(parts[1]); err != nil {
		return nil, fmt.Errorf("bad fragment count %q: %w", parts[1], err)
	}
	if out.FragmentIndex, err = strconv.Atoi(parts[2]); err != nil {
		return nil, fmt.Errorf("bad fragment index %q: %w", parts[2], err)
	}
	if out.PaddingBits, err = strconv.Atoi(parts[6]); err != nil {
		return nil, fmt.Errorf("bad padding %q: %w", parts[6], err)
	}
	if out.PaddingBits < 0 || out.PaddingBits > 5 {
		return nil, fmt.Errorf("padding %d out of 0..5", out.PaddingBits)
	}
	return out, nil
}

// nmeaChecksum is the XOR-of-bytes checksum used by NMEA 0183
// for every character between '!'/'$' and '*'.
func nmeaChecksum(body string) byte {
	var c byte
	for i := 0; i < len(body); i++ {
		c ^= body[i]
	}
	return c
}

// unpack6BitASCII walks the payload chars (each carrying 6
// bits per the AIS character table) and returns a bit string
// where each byte is 0 or 1. The trailing padding bits are
// trimmed.
func unpack6BitASCII(payload string, padding int) ([]byte, error) {
	bits := make([]byte, 0, len(payload)*6)
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if c < 0x30 || c > 0x77 {
			return nil, fmt.Errorf("payload char %q out of AIS 6-bit ASCII range", c)
		}
		v := int(c) - 48
		if v > 40 {
			v -= 8
		}
		if v < 0 || v > 63 {
			return nil, fmt.Errorf("payload char %q resolves to %d (out of 0..63)", c, v)
		}
		for j := 5; j >= 0; j-- {
			bits = append(bits, byte((v>>j)&1))
		}
	}
	if padding > len(bits) {
		return nil, fmt.Errorf("padding %d exceeds bit count %d", padding, len(bits))
	}
	return bits[:len(bits)-padding], nil
}

func readUint(bits []byte, off, width int) int {
	if off+width > len(bits) {
		return 0
	}
	v := 0
	for i := 0; i < width; i++ {
		v = (v << 1) | int(bits[off+i])
	}
	return v
}

// readInt reads a two's-complement signed integer of the given
// width. AIS lat/lon/ROT use this encoding.
func readInt(bits []byte, off, width int) int {
	if off+width > len(bits) {
		return 0
	}
	v := readUint(bits, off, width)
	if v&(1<<(width-1)) != 0 {
		v -= 1 << width
	}
	return v
}

// read6BitString pulls width/6 chars out of the bit string and
// renders them per the AIS 6-bit character table. Trailing
// '@' (value 0, used as padding) is trimmed.
func read6BitString(bits []byte, off, width int) string {
	chars := make([]byte, 0, width/6)
	for i := 0; i+6 <= width; i += 6 {
		v := readUint(bits, off+i, 6)
		var c byte
		if v < 32 {
			c = byte(v + 64)
		} else {
			c = byte(v)
		}
		chars = append(chars, c)
	}
	s := string(chars)
	return strings.TrimRight(s, "@ ")
}

func decodePositionClassA(bits []byte) *PositionReportClassA {
	p := &PositionReportClassA{
		NavStatus:         readUint(bits, 38, 4),
		PositionAccuracy:  bits[60] == 1,
		Timestamp:         readUint(bits, 137, 6),
		ManeuverIndicator: readUint(bits, 143, 2),
		RAIM:              bits[148] == 1,
	}
	p.NavStatusName = navStatusName(p.NavStatus)
	rot := int(int8(readUint(bits, 42, 8)))
	if rot != -128 {
		p.RateOfTurnDegPerMin = &rot
	}
	sog := readUint(bits, 50, 10)
	if sog != 1023 {
		s := float64(sog) / 10.0
		p.SpeedOverGroundKts = &s
	}
	lon := readInt(bits, 61, 28)
	if lon != 0x6791AC0 { // sentinel 181° = 0x6791AC0 / 10000
		l := float64(lon) / 600000.0
		p.LongitudeDeg = &l
	}
	lat := readInt(bits, 89, 27)
	if lat != 0x3412140 { // sentinel 91°
		l := float64(lat) / 600000.0
		p.LatitudeDeg = &l
	}
	cog := readUint(bits, 116, 12)
	if cog != 3600 {
		c := float64(cog) / 10.0
		p.CourseOverGroundDeg = &c
	}
	th := readUint(bits, 128, 9)
	if th != 511 {
		p.TrueHeadingDeg = &th
	}
	return p
}

func decodeBaseStation(bits []byte) *BaseStationReport {
	b := &BaseStationReport{
		Year:             readUint(bits, 38, 14),
		Month:            readUint(bits, 52, 4),
		Day:              readUint(bits, 56, 5),
		Hour:             readUint(bits, 61, 5),
		Minute:           readUint(bits, 66, 6),
		Second:           readUint(bits, 72, 6),
		PositionAccuracy: bits[78] == 1,
		EPFDType:         readUint(bits, 134, 4),
	}
	b.EPFDName = epfdName(b.EPFDType)
	lon := readInt(bits, 79, 28)
	if lon != 0x6791AC0 {
		l := float64(lon) / 600000.0
		b.LongitudeDeg = &l
	}
	lat := readInt(bits, 107, 27)
	if lat != 0x3412140 {
		l := float64(lat) / 600000.0
		b.LatitudeDeg = &l
	}
	if len(bits) > 148 {
		b.RAIM = bits[148] == 1
	}
	return b
}

func decodeStaticAndVoyage(bits []byte) *StaticAndVoyageData {
	s := &StaticAndVoyageData{
		AISVersion:     readUint(bits, 38, 2),
		IMONumber:      readUint(bits, 40, 30),
		CallSign:       read6BitString(bits, 70, 42),
		VesselName:     read6BitString(bits, 112, 120),
		ShipType:       readUint(bits, 232, 8),
		DimensionBow:   readUint(bits, 240, 9),
		DimensionStern: readUint(bits, 249, 9),
		DimensionPort:  readUint(bits, 258, 6),
		DimensionStbd:  readUint(bits, 264, 6),
		EPFDType:       readUint(bits, 270, 4),
		ETAMonth:       readUint(bits, 274, 4),
		ETADay:         readUint(bits, 278, 5),
		ETAHour:        readUint(bits, 283, 5),
		ETAMinute:      readUint(bits, 288, 6),
		DraughtM:       float64(readUint(bits, 294, 8)) / 10.0,
		Destination:    read6BitString(bits, 302, 120),
		DTE:            readUint(bits, 422, 1),
	}
	s.ShipTypeName = shipTypeName(s.ShipType)
	s.EPFDName = epfdName(s.EPFDType)
	return s
}

func decodePositionClassB(bits []byte) *PositionReportClassB {
	p := &PositionReportClassB{
		PositionAccuracy: bits[56] == 1,
		Timestamp:        readUint(bits, 133, 6),
	}
	sog := readUint(bits, 46, 10)
	if sog != 1023 {
		s := float64(sog) / 10.0
		p.SpeedOverGroundKts = &s
	}
	lon := readInt(bits, 57, 28)
	if lon != 0x6791AC0 {
		l := float64(lon) / 600000.0
		p.LongitudeDeg = &l
	}
	lat := readInt(bits, 85, 27)
	if lat != 0x3412140 {
		l := float64(lat) / 600000.0
		p.LatitudeDeg = &l
	}
	cog := readUint(bits, 112, 12)
	if cog != 3600 {
		c := float64(cog) / 10.0
		p.CourseOverGroundDeg = &c
	}
	th := readUint(bits, 124, 9)
	if th != 511 {
		p.TrueHeadingDeg = &th
	}
	if len(bits) > 141 {
		p.CSUnit = bits[141] == 1
		p.DisplayFlag = bits[142] == 1
		p.DSCFlag = bits[143] == 1
		p.BandFlag = bits[144] == 1
		p.Msg22Flag = bits[145] == 1
		p.Assigned = bits[146] == 1
		p.RAIM = bits[147] == 1
	}
	return p
}

func decodeExtendedClassB(bits []byte) *ExtendedPositionClassB {
	p := &ExtendedPositionClassB{
		PositionAccuracy: bits[56] == 1,
		Timestamp:        readUint(bits, 133, 6),
		VesselName:       read6BitString(bits, 143, 120),
		ShipType:         readUint(bits, 263, 8),
		DimensionBow:     readUint(bits, 271, 9),
		DimensionStern:   readUint(bits, 280, 9),
		DimensionPort:    readUint(bits, 289, 6),
		DimensionStbd:    readUint(bits, 295, 6),
		EPFDType:         readUint(bits, 301, 4),
		RAIM:             bits[305] == 1,
		DTE:              readUint(bits, 306, 1),
		Assigned:         bits[307] == 1,
	}
	p.ShipTypeName = shipTypeName(p.ShipType)
	p.EPFDName = epfdName(p.EPFDType)
	sog := readUint(bits, 46, 10)
	if sog != 1023 {
		s := float64(sog) / 10.0
		p.SpeedOverGroundKts = &s
	}
	lon := readInt(bits, 57, 28)
	if lon != 0x6791AC0 {
		l := float64(lon) / 600000.0
		p.LongitudeDeg = &l
	}
	lat := readInt(bits, 85, 27)
	if lat != 0x3412140 {
		l := float64(lat) / 600000.0
		p.LatitudeDeg = &l
	}
	cog := readUint(bits, 112, 12)
	if cog != 3600 {
		c := float64(cog) / 10.0
		p.CourseOverGroundDeg = &c
	}
	th := readUint(bits, 124, 9)
	if th != 511 {
		p.TrueHeadingDeg = &th
	}
	return p
}

func decodeAidToNavigation(bits []byte) *AidToNavigationReport {
	a := &AidToNavigationReport{
		AidType:          readUint(bits, 38, 5),
		Name:             read6BitString(bits, 43, 120),
		PositionAccuracy: bits[163] == 1,
		DimensionBow:     readUint(bits, 219, 9),
		DimensionStern:   readUint(bits, 228, 9),
		DimensionPort:    readUint(bits, 237, 6),
		DimensionStbd:    readUint(bits, 243, 6),
		EPFDType:         readUint(bits, 249, 4),
		Timestamp:        readUint(bits, 253, 6),
		OffPosition:      bits[259] == 1,
		RAIM:             bits[268] == 1,
		VirtualAid:       bits[269] == 1,
		Assigned:         bits[270] == 1,
	}
	a.AidTypeName = aidTypeName(a.AidType)
	a.EPFDName = epfdName(a.EPFDType)
	lon := readInt(bits, 164, 28)
	if lon != 0x6791AC0 {
		l := float64(lon) / 600000.0
		a.LongitudeDeg = &l
	}
	lat := readInt(bits, 192, 27)
	if lat != 0x3412140 {
		l := float64(lat) / 600000.0
		a.LatitudeDeg = &l
	}
	// The name may overflow into a variable extension field
	// (bits 272 onward, up to 88 bits / 14 chars), present only
	// when the sender padded the message out past the 272-bit core.
	if extWidth := ((len(bits) - 272) / 6) * 6; extWidth > 0 {
		a.NameExtension = read6BitString(bits, 272, extWidth)
	}
	return a
}

func decodeStaticClassB(bits []byte, parentMMSI int) *StaticDataReportClassB {
	part := readUint(bits, 38, 2)
	s := &StaticDataReportClassB{PartNumber: part}
	switch part {
	case 0:
		s.VesselName = read6BitString(bits, 40, 120)
	case 1:
		s.ShipType = readUint(bits, 40, 8)
		s.ShipTypeName = shipTypeName(s.ShipType)
		s.VendorID = read6BitString(bits, 48, 42)
		s.CallSign = read6BitString(bits, 90, 42)
		// Auxiliary craft (MMSI starting 98) carry their
		// mothership MMSI in the bit range where regular Class B
		// transponders carry the dimensions. Per ITU-R M.1371-5
		// §3.3.8.2.5 Table 26.
		if parentMMSI >= 980000000 && parentMMSI < 990000000 {
			s.MothershipMMSI = readUint(bits, 132, 30)
		} else {
			s.DimensionBow = readUint(bits, 132, 9)
			s.DimensionStern = readUint(bits, 141, 9)
			s.DimensionPort = readUint(bits, 150, 6)
			s.DimensionStbd = readUint(bits, 156, 6)
		}
	}
	return s
}

// splitSentences breaks the input on newlines and trims blank
// lines.
func splitSentences(in string) []string {
	in = strings.ReplaceAll(in, "\r\n", "\n")
	in = strings.ReplaceAll(in, "\r", "\n")
	var out []string
	for _, l := range strings.Split(in, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func messageTypeName(t int) string {
	switch t {
	case 1:
		return "Position Report Class A (scheduled)"
	case 2:
		return "Position Report Class A (assigned)"
	case 3:
		return "Position Report Class A (response to interrogation)"
	case 4:
		return "Base Station Report"
	case 5:
		return "Static and Voyage Related Data"
	case 6:
		return "Binary Addressed Message"
	case 7:
		return "Binary Acknowledge"
	case 8:
		return "Binary Broadcast Message"
	case 9:
		return "Standard SAR Aircraft Position Report"
	case 10:
		return "UTC and Date Inquiry"
	case 11:
		return "UTC and Date Response"
	case 12:
		return "Addressed Safety Related Message"
	case 13:
		return "Safety Related Acknowledge"
	case 14:
		return "Safety Related Broadcast Message"
	case 15:
		return "Interrogation"
	case 16:
		return "Assigned Mode Command"
	case 17:
		return "DGNSS Broadcast Binary Message"
	case 18:
		return "Standard Class B CS Position Report"
	case 19:
		return "Extended Class B Position Report"
	case 20:
		return "Data Link Management Message"
	case 21:
		return "Aid-to-Navigation Report"
	case 22:
		return "Channel Management"
	case 23:
		return "Group Assignment Command"
	case 24:
		return "Static Data Report (Class B)"
	case 25:
		return "Single Slot Binary Message"
	case 26:
		return "Multiple Slot Binary Message With Communications State"
	case 27:
		return "Position Report For Long-Range Applications"
	}
	return fmt.Sprintf("Reserved (type %d)", t)
}

// aidTypeName maps the Type-21 aid-type code to its label per
// ITU-R M.1371-5 Table 76.
func aidTypeName(t int) string {
	switch t {
	case 0:
		return "Default, type of AtoN not specified"
	case 1:
		return "Reference point"
	case 2:
		return "RACON (radar transponder)"
	case 3:
		return "Fixed structure off shore"
	case 4:
		return "Spare (reserved)"
	case 5:
		return "Light, without sectors"
	case 6:
		return "Light, with sectors"
	case 7:
		return "Leading Light Front"
	case 8:
		return "Leading Light Rear"
	case 9:
		return "Beacon, Cardinal N"
	case 10:
		return "Beacon, Cardinal E"
	case 11:
		return "Beacon, Cardinal S"
	case 12:
		return "Beacon, Cardinal W"
	case 13:
		return "Beacon, Port hand"
	case 14:
		return "Beacon, Starboard hand"
	case 15:
		return "Beacon, Preferred Channel port hand"
	case 16:
		return "Beacon, Preferred Channel starboard hand"
	case 17:
		return "Beacon, Isolated danger"
	case 18:
		return "Beacon, Safe water"
	case 19:
		return "Beacon, Special mark"
	case 20:
		return "Cardinal Mark N"
	case 21:
		return "Cardinal Mark E"
	case 22:
		return "Cardinal Mark S"
	case 23:
		return "Cardinal Mark W"
	case 24:
		return "Port hand Mark"
	case 25:
		return "Starboard hand Mark"
	case 26:
		return "Preferred Channel Port hand"
	case 27:
		return "Preferred Channel Starboard hand"
	case 28:
		return "Isolated danger"
	case 29:
		return "Safe Water"
	case 30:
		return "Special Mark"
	case 31:
		return "Light Vessel / LANBY / Rig"
	}
	return fmt.Sprintf("Unknown aid type %d", t)
}

func navStatusName(s int) string {
	switch s {
	case 0:
		return "Under way using engine"
	case 1:
		return "At anchor"
	case 2:
		return "Not under command"
	case 3:
		return "Restricted manoeuvrability"
	case 4:
		return "Constrained by her draught"
	case 5:
		return "Moored"
	case 6:
		return "Aground"
	case 7:
		return "Engaged in fishing"
	case 8:
		return "Under way sailing"
	case 9:
		return "Reserved (HSC)"
	case 10:
		return "Reserved (WIG)"
	case 11:
		return "Power-driven vessel towing astern"
	case 12:
		return "Power-driven vessel pushing ahead / towing alongside"
	case 13:
		return "Reserved for future amendment"
	case 14:
		return "AIS-SART (active) / MOB-AIS / EPIRB-AIS"
	case 15:
		return "Undefined (default)"
	}
	return fmt.Sprintf("Reserved (status %d)", s)
}

// shipTypeName maps the 8-bit Ship and Cargo Type field per
// ITU-R M.1371-5 Table 53. The table is grouped by tens-digit
// (Reserved / WIG / Fishing / Tug / Dredger / Diving / Military
// / Sailing / Pleasure / High-speed craft / Pilot / SAR / Tug /
// Port tender / Anti-pollution / Law enforcement / Spare /
// Medical / Noncombatant / Passenger / Cargo / Tanker / Other).
func shipTypeName(t int) string {
	switch {
	case t == 0:
		return "Not available"
	case t >= 20 && t <= 29:
		return "Wing in ground (WIG)"
	case t == 30:
		return "Fishing"
	case t == 31, t == 32:
		return "Towing"
	case t == 33:
		return "Dredging or underwater operations"
	case t == 34:
		return "Diving operations"
	case t == 35:
		return "Military operations"
	case t == 36:
		return "Sailing"
	case t == 37:
		return "Pleasure craft"
	case t >= 40 && t <= 49:
		return "High-speed craft"
	case t == 50:
		return "Pilot vessel"
	case t == 51:
		return "Search and Rescue vessel"
	case t == 52:
		return "Tug"
	case t == 53:
		return "Port tender"
	case t == 54:
		return "Anti-pollution equipment"
	case t == 55:
		return "Law enforcement"
	case t == 58:
		return "Medical transport"
	case t == 59:
		return "Noncombatant ship per Resolution 18"
	case t >= 60 && t <= 69:
		return "Passenger"
	case t >= 70 && t <= 79:
		return "Cargo"
	case t >= 80 && t <= 89:
		return "Tanker"
	case t >= 90 && t <= 99:
		return "Other"
	}
	return fmt.Sprintf("Reserved (type %d)", t)
}

// epfdName labels the Electronic Position-Fixing Device type.
func epfdName(t int) string {
	switch t {
	case 0:
		return "Undefined (default)"
	case 1:
		return "GPS"
	case 2:
		return "GLONASS"
	case 3:
		return "Combined GPS/GLONASS"
	case 4:
		return "Loran-C"
	case 5:
		return "Chayka"
	case 6:
		return "Integrated navigation system"
	case 7:
		return "Surveyed"
	case 8:
		return "Galileo"
	case 15:
		return "Internal GNSS"
	}
	return fmt.Sprintf("Reserved (EPFD %d)", t)
}
