// SPDX-License-Identifier: AGPL-3.0-or-later

// Package droneid decodes ASTM F3411-22 (a.k.a. FAA / EU drone
// Remote ID) payload messages captured over BLE 4 Legacy / BLE
// 5 Long Range / WiFi NAN / WiFi Beacon broadcasts.
//
// # Wrap-vs-native judgement
//
// Native. The Remote ID payload format is fully published in
// ASTM F3411-22 ("Standard Specification for Remote ID and
// Tracking") + the FAA Remote ID Final Rule (14 CFR Part 89).
// Every message is a fixed 25-byte frame with a 4-bit type
// nibble + 4-bit protocol version + dispatch on type. No
// vendor SDK, no cryptography, no handshake — pasting a hex
// blob captured by a BLE / WiFi sniffer is enough.
//
// # What this package covers
//
//   - Message envelope: 1-byte header = (MessageType << 4) |
//     ProtocolVersion. Six message types recognised plus the
//     Message Pack container (type 0xF).
//   - Type 0x0 Basic ID — 20-character UAS ID + ID Type
//     (None / Serial Number per ANSI CTA-2063-A / CAA
//     registration / UTM-assigned UUID / Session ID) + UA
//     Type (Aeroplane / Helicopter-Multirotor / Glider /
//     etc., full 16-entry table).
//   - Type 0x1 Location/Vector — operational status,
//     altitude reference, lat / lon (10^-7 deg signed
//     i32), pressure + geodetic + AGL altitude (0.5 m,
//     -1000 m offset), ground track and speed with
//     multiplier-encoded high-speed range, vertical speed
//     (signed 0.5 m/s), per-field accuracy nibbles, and
//     1/10-second timestamp within the current hour.
//   - Type 0x3 Self-ID — 23-character free-text description
//     and a Description Type code (0 = text, 200 = emergency,
//     etc.).
//   - Type 0x4 System — operator location (lat / lon),
//     operator altitude, classification region (EU / FAA),
//     EU class (C0..C5), area count / radius / ceiling /
//     floor for swarm-flight extents, and System Timestamp
//     (seconds since 2019-01-01 00:00:00 UTC).
//   - Type 0x5 Operator ID — 20-character operator ID +
//     Operator ID Type.
//   - Type 0xF Message Pack — header + message size (must
//     be 25) + message count (1-9) + N × 25-byte child
//     messages, dispatched individually.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Type 0x2 Authentication — variable-length signature
//     pages, rarely transmitted in practice; the spec allows
//     up to 17 pages of 23 bytes each (393 byte signature).
//     A future Spec can land if real-world captures surface.
//   - The BLE / WiFi transport framing — operators are
//     expected to extract the 25-byte payload from the
//     advertising packet's manufacturer-specific data field
//     (Apple uses BLE 4 Legacy, ASTM standard uses BLE 5
//     extended advertisements + WiFi NAN). The wrapper IDs
//     (0xFA 0xFF "DRI" + ASTM OUI 0x6A:0x5C:0x35 etc.) are
//     out of scope here.
//   - Geographic Remote ID Limitations / no-fly zones (Part
//     107 broadcasts) — that's a separate FAA system.
package droneid

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Message is one decoded ASTM F3411 frame. Exactly one of the
// sub-pointers is set per call — the one that matches Type.
type Message struct {
	HexInput        string      `json:"hex_input"`
	Type            int         `json:"type"`
	TypeName        string      `json:"type_name"`
	ProtocolVersion int         `json:"protocol_version"`
	BasicID         *BasicID    `json:"basic_id,omitempty"`
	Location        *Location   `json:"location,omitempty"`
	SelfID          *SelfID     `json:"self_id,omitempty"`
	System          *System     `json:"system,omitempty"`
	OperatorID      *OperatorID `json:"operator_id,omitempty"`
	Pack            *Pack       `json:"pack,omitempty"`
}

// BasicID is the decoded type-0x0 message: UAS identity +
// aircraft type categorisation.
type BasicID struct {
	IDType int    `json:"id_type"`
	IDName string `json:"id_name"`
	UAType int    `json:"ua_type"`
	UAName string `json:"ua_name"`
	UASID  string `json:"uas_id"`
}

// Location is the decoded type-0x1 message: operational state
// + position + motion + accuracies + timestamp.
type Location struct {
	Status                  int     `json:"status"`
	StatusName              string  `json:"status_name"`
	HeightType              string  `json:"height_type"`
	TrackDirectionDeg       int     `json:"track_direction_deg"`
	SpeedMS                 float64 `json:"speed_m_s"`
	VerticalSpeedMS         float64 `json:"vertical_speed_m_s"`
	LatitudeDeg             float64 `json:"latitude_deg"`
	LongitudeDeg            float64 `json:"longitude_deg"`
	PressureAltitudeM       float64 `json:"pressure_altitude_m"`
	GeodeticAltitudeM       float64 `json:"geodetic_altitude_m"`
	HeightAGLM              float64 `json:"height_agl_m"`
	HorizontalAccuracy      int     `json:"horizontal_accuracy_code"`
	VerticalAccuracy        int     `json:"vertical_accuracy_code"`
	BaroAltitudeAccuracy    int     `json:"baro_altitude_accuracy_code"`
	SpeedAccuracy           int     `json:"speed_accuracy_code"`
	Timestamp1_10Sec        int     `json:"timestamp_1_10_sec"`
	TimestampAccuracyTenths int     `json:"timestamp_accuracy_tenths"`
}

// SelfID is the decoded type-0x3 message: short free-text
// description of the flight purpose or operator-side
// situation.
type SelfID struct {
	DescriptionType int    `json:"description_type"`
	DescriptionName string `json:"description_name"`
	Description     string `json:"description"`
}

// System is the decoded type-0x4 message: operator-side
// position, regulatory classification, swarm-flight extents,
// system-level timestamp.
type System struct {
	OperatorLocationSource int     `json:"operator_location_source"`
	OperatorLocationName   string  `json:"operator_location_name"`
	ClassificationRegion   int     `json:"classification_region"`
	ClassificationName     string  `json:"classification_name"`
	OperatorLatDeg         float64 `json:"operator_latitude_deg"`
	OperatorLonDeg         float64 `json:"operator_longitude_deg"`
	AreaCount              int     `json:"area_count"`
	AreaRadiusM            int     `json:"area_radius_m"`
	AreaCeilingM           float64 `json:"area_ceiling_m"`
	AreaFloorM             float64 `json:"area_floor_m"`
	UACategory             int     `json:"ua_category"`
	UAClass                int     `json:"ua_class"`
	UAClassName            string  `json:"ua_class_name"`
	OperatorAltitudeM      float64 `json:"operator_altitude_m"`
	SystemTimestampUnix    uint32  `json:"system_timestamp_unix"`
}

// OperatorID is the decoded type-0x5 message: regulatory
// operator identifier.
type OperatorID struct {
	IDType int    `json:"id_type"`
	IDName string `json:"id_name"`
	ID     string `json:"id"`
}

// Pack is the decoded type-0xF Message Pack container —
// up to 9 × 25-byte child messages dispatched in sequence.
type Pack struct {
	MessageSize  int        `json:"message_size"`
	MessageCount int        `json:"message_count"`
	Messages     []*Message `json:"messages"`
}

// Decode parses a hex-encoded Remote ID frame into a Message
// view. Accepts ':', '-', '_', whitespace as separators and a
// leading '0x' prefix.
func Decode(hexBlob string) (*Message, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes dispatches on the frame's type nibble after a
// length-and-shape sanity check.
func DecodeBytes(b []byte) (*Message, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("droneid: empty payload")
	}
	hdr := b[0]
	typ := int(hdr >> 4)
	pv := int(hdr & 0x0F)
	// Single message frames must be exactly 25 bytes. Pack
	// (type 0xF) is the only variable-length form.
	if typ != 0xF && len(b) != 25 {
		return nil, fmt.Errorf(
			"droneid: single message frame (type 0x%X) must be exactly 25 bytes; got %d",
			typ, len(b))
	}
	m := &Message{
		HexInput:        strings.ToUpper(hex.EncodeToString(b)),
		Type:            typ,
		TypeName:        messageTypeName(typ),
		ProtocolVersion: pv,
	}
	switch typ {
	case 0x0:
		m.BasicID = decodeBasicID(b)
	case 0x1:
		m.Location = decodeLocation(b)
	case 0x3:
		m.SelfID = decodeSelfID(b)
	case 0x4:
		m.System = decodeSystem(b)
	case 0x5:
		m.OperatorID = decodeOperatorID(b)
	case 0xF:
		p, err := decodePack(b)
		if err != nil {
			return nil, err
		}
		m.Pack = p
	case 0x2:
		// Authentication is variable-length and out of scope
		// for this iteration — we still surface the type
		// label so operators see "Authentication" rather than
		// silently dropping it.
	}
	return m, nil
}

func decodeBasicID(b []byte) *BasicID {
	idType := int(b[1] >> 4)
	uaType := int(b[1] & 0x0F)
	return &BasicID{
		IDType: idType,
		IDName: idTypeName(idType),
		UAType: uaType,
		UAName: uaTypeName(uaType),
		UASID:  trimASCII(b[2:22]),
	}
}

func decodeLocation(b []byte) *Location {
	status := int(b[1] >> 4)
	heightTypeBit := (b[1] >> 2) & 0x01
	ewDirSeg := (b[1] >> 1) & 0x01
	speedMult := b[1] & 0x01

	track := int(b[2])
	if ewDirSeg == 1 {
		track += 180
	}

	var speedMS float64
	if speedMult == 0 {
		speedMS = float64(b[3]) * 0.25
	} else {
		// High-speed encoding: (raw × 0.75) + (255 × 0.25)
		speedMS = float64(b[3])*0.75 + (255.0 * 0.25)
	}

	vsRaw := int8(b[4])
	vSpeedMS := float64(vsRaw) * 0.5

	lat := decodeI32(b[5:9])
	lon := decodeI32(b[9:13])

	pressureAlt := float64(decodeU16(b[13:15]))*0.5 - 1000.0
	geodeticAlt := float64(decodeU16(b[15:17]))*0.5 - 1000.0
	heightAGL := float64(decodeU16(b[17:19]))*0.5 - 1000.0

	vertAcc := int(b[19] >> 4)
	horizAcc := int(b[19] & 0x0F)
	baroAcc := int(b[20] >> 4)
	speedAcc := int(b[20] & 0x0F)

	ts := int(decodeU16(b[21:23]))
	tsAcc := int(b[23] & 0x0F)

	heightType := "AGL / takeoff"
	if heightTypeBit == 1 {
		heightType = "geodetic"
	}

	return &Location{
		Status:                  status,
		StatusName:              statusName(status),
		HeightType:              heightType,
		TrackDirectionDeg:       track,
		SpeedMS:                 speedMS,
		VerticalSpeedMS:         vSpeedMS,
		LatitudeDeg:             float64(lat) / 1e7,
		LongitudeDeg:            float64(lon) / 1e7,
		PressureAltitudeM:       pressureAlt,
		GeodeticAltitudeM:       geodeticAlt,
		HeightAGLM:              heightAGL,
		HorizontalAccuracy:      horizAcc,
		VerticalAccuracy:        vertAcc,
		BaroAltitudeAccuracy:    baroAcc,
		SpeedAccuracy:           speedAcc,
		Timestamp1_10Sec:        ts,
		TimestampAccuracyTenths: tsAcc,
	}
}

func decodeSelfID(b []byte) *SelfID {
	dt := int(b[1])
	return &SelfID{
		DescriptionType: dt,
		DescriptionName: descriptionTypeName(dt),
		Description:     trimASCII(b[2:25]),
	}
}

func decodeSystem(b []byte) *System {
	// Per ASTM F3411-22 §6.4.6 + OpenDroneID layout:
	//   bits 0-1 : OperatorLocationType (2 bits)
	//   bits 2-4 : ClassificationType (3 bits)
	//   bits 5-7 : Reserved
	opLocSrc := int(b[1] & 0x03)
	classRegion := int((b[1] >> 2) & 0x07)
	lat := decodeI32(b[2:6])
	lon := decodeI32(b[6:10])
	areaCount := int(decodeU16(b[10:12]))
	areaRadius := int(b[12]) * 10
	areaCeiling := float64(decodeU16(b[13:15]))*0.5 - 1000.0
	areaFloor := float64(decodeU16(b[15:17]))*0.5 - 1000.0
	uaCat := int(b[17] >> 4)
	uaClass := int(b[17] & 0x0F)
	opAlt := float64(decodeU16(b[18:20]))*0.5 - 1000.0
	ts := decodeU32(b[20:24])
	return &System{
		OperatorLocationSource: opLocSrc,
		OperatorLocationName:   operatorLocationName(opLocSrc),
		ClassificationRegion:   classRegion,
		ClassificationName:     classificationName(classRegion),
		OperatorLatDeg:         float64(lat) / 1e7,
		OperatorLonDeg:         float64(lon) / 1e7,
		AreaCount:              areaCount,
		AreaRadiusM:            areaRadius,
		AreaCeilingM:           areaCeiling,
		AreaFloorM:             areaFloor,
		UACategory:             uaCat,
		UAClass:                uaClass,
		UAClassName:            uaClassName(uaCat, uaClass),
		OperatorAltitudeM:      opAlt,
		SystemTimestampUnix:    ts + epochOffset2019,
	}
}

func decodeOperatorID(b []byte) *OperatorID {
	idType := int(b[1])
	return &OperatorID{
		IDType: idType,
		IDName: operatorIDTypeName(idType),
		ID:     trimASCII(b[2:22]),
	}
}

func decodePack(b []byte) (*Pack, error) {
	if len(b) < 3 {
		return nil, fmt.Errorf("droneid: message pack truncated (need at least 3 header bytes)")
	}
	msgSize := int(b[1])
	msgCount := int(b[2])
	if msgSize != 25 {
		return nil, fmt.Errorf("droneid: message pack must declare message_size=25; got %d", msgSize)
	}
	if msgCount < 1 || msgCount > 9 {
		return nil, fmt.Errorf("droneid: message pack count must be 1..9; got %d", msgCount)
	}
	expected := 3 + msgCount*25
	if len(b) != expected {
		return nil, fmt.Errorf(
			"droneid: message pack length mismatch — header says %d messages × 25 = %d bytes (plus 3 header), got %d",
			msgCount, msgCount*25, len(b))
	}
	p := &Pack{
		MessageSize:  msgSize,
		MessageCount: msgCount,
		Messages:     make([]*Message, 0, msgCount),
	}
	for i := 0; i < msgCount; i++ {
		off := 3 + i*25
		child, err := DecodeBytes(b[off : off+25])
		if err != nil {
			return nil, fmt.Errorf("droneid: pack message[%d]: %w", i, err)
		}
		p.Messages = append(p.Messages, child)
	}
	return p, nil
}

// epochOffset2019 is the Unix-time offset of 2019-01-01
// 00:00:00 UTC, used by the System message's Timestamp field
// per ASTM F3411-22 §6.4.4.
const epochOffset2019 = uint32(1546300800)

func decodeI32(b []byte) int32 {
	return int32(b[0]) | int32(b[1])<<8 | int32(b[2])<<16 | int32(b[3])<<24
}

func decodeU16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func decodeU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func trimASCII(b []byte) string {
	end := len(b)
	for end > 0 && (b[end-1] == 0x00 || b[end-1] == ' ') {
		end--
	}
	return string(b[:end])
}

func messageTypeName(t int) string {
	switch t {
	case 0x0:
		return "Basic ID"
	case 0x1:
		return "Location / Vector"
	case 0x2:
		return "Authentication"
	case 0x3:
		return "Self ID"
	case 0x4:
		return "System"
	case 0x5:
		return "Operator ID"
	case 0xF:
		return "Message Pack"
	}
	return fmt.Sprintf("Reserved (type 0x%X)", t)
}

func idTypeName(t int) string {
	switch t {
	case 0:
		return "None"
	case 1:
		return "Serial Number (ANSI/CTA-2063-A)"
	case 2:
		return "CAA-assigned registration ID"
	case 3:
		return "UTM (UUID) assigned ID"
	case 4:
		return "Specific Session ID"
	}
	return fmt.Sprintf("Reserved (id_type %d)", t)
}

func uaTypeName(t int) string {
	switch t {
	case 0:
		return "None / not declared"
	case 1:
		return "Aeroplane (fixed-wing)"
	case 2:
		return "Helicopter / multirotor"
	case 3:
		return "Gyroplane"
	case 4:
		return "Hybrid Lift (fixed-wing + VTOL)"
	case 5:
		return "Ornithopter"
	case 6:
		return "Glider"
	case 7:
		return "Kite"
	case 8:
		return "Free Balloon"
	case 9:
		return "Captive Balloon"
	case 10:
		return "Airship (e.g. blimp)"
	case 11:
		return "Free Fall / Parachute"
	case 12:
		return "Rocket"
	case 13:
		return "Tethered Powered Aircraft"
	case 14:
		return "Ground Obstacle"
	case 15:
		return "Other"
	}
	return fmt.Sprintf("Reserved (ua_type %d)", t)
}

func statusName(s int) string {
	switch s {
	case 0:
		return "Undeclared"
	case 1:
		return "Ground"
	case 2:
		return "Airborne"
	case 3:
		return "Emergency"
	case 4:
		return "Remote ID System Failure"
	}
	return fmt.Sprintf("Reserved (status %d)", s)
}

func descriptionTypeName(t int) string {
	switch t {
	case 0:
		return "Free text"
	case 1:
		return "Emergency"
	case 2:
		return "Extended Status"
	}
	if t >= 200 {
		return "Private / reserved-range"
	}
	return fmt.Sprintf("Reserved (description_type %d)", t)
}

func operatorLocationName(s int) string {
	switch s {
	case 0:
		return "Takeoff (one-shot at flight start)"
	case 1:
		return "Dynamic (live GNSS fix on controller)"
	case 2:
		return "Fixed (pre-configured operator location)"
	}
	return fmt.Sprintf("Reserved (operator_location_source %d)", s)
}

func classificationName(c int) string {
	switch c {
	case 0:
		return "Undeclared"
	case 1:
		return "EU (EASA classification)"
	}
	return fmt.Sprintf("Reserved (classification_region %d)", c)
}

func uaClassName(category, class int) string {
	if category != 1 {
		// Only EU classification (region=1) defines a class
		// table per ASTM F3411-22 §6.4.13; everything else is
		// undeclared.
		if class == 0 {
			return "Undeclared"
		}
		return fmt.Sprintf("Class %d (non-EU; reserved)", class)
	}
	switch class {
	case 0:
		return "EU undeclared"
	case 1:
		return "EU Class 0 (≤250 g, ≤19 m/s)"
	case 2:
		return "EU Class 1 (<900 g, ≤19 m/s)"
	case 3:
		return "EU Class 2 (<4 kg)"
	case 4:
		return "EU Class 3 (<25 kg)"
	case 5:
		return "EU Class 4 (<25 kg, model aircraft)"
	case 6:
		return "EU Class 5 (Specific category)"
	case 7:
		return "EU Class 6 (Certified category)"
	}
	return fmt.Sprintf("EU reserved class %d", class)
}

func operatorIDTypeName(t int) string {
	switch t {
	case 0:
		return "CAA-assigned operator registration ID"
	}
	if t >= 200 {
		return "Private / reserved-range"
	}
	return fmt.Sprintf("Reserved (operator_id_type %d)", t)
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("droneid: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("droneid: invalid hex: %w", err)
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
