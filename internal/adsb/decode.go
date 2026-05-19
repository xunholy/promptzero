// SPDX-License-Identifier: AGPL-3.0-or-later

// Package adsb decodes Mode S downlink frames captured at
// 1090 MHz — both short-form (56-bit) surveillance replies and
// long-form (112-bit) extended squitter / ADS-B frames.
//
// # Wrap-vs-native judgement
//
// Native. The Mode S frame format and the ADS-B Extended
// Squitter sub-message family are fully published (ICAO Annex
// 10 Vol IV + RTCA DO-260 + EUROCAE ED-102). The CRC-24
// generator (G(x) = 0x1FFF409) is a textbook bit-walking
// polynomial division. Type-code dispatch is a static switch
// over a 5-bit field. Pasting a hex blob captured by
// dump1090 / readsb / a Flipper-adjacent SDR feed is enough
// — no vendor SDK, no protocol negotiation, no hardware path.
//
// # What this package covers
//
//   - Frame envelope: Downlink Format (DF, 5 bits) detection
//     with a documented name table covering all 32 DF slots
//     (DF0 / DF4 / DF5 / DF11 / DF16 / DF17 / DF18 / DF19 /
//     DF20 / DF21 / DF24+ Comm-D extended length).
//   - Frame length validation: short (56 bits = 7 bytes) for
//     DF0/4/5/11; long (112 bits = 14 bytes) for DF16-22 and
//     DF24+.
//   - ICAO 24-bit aircraft address extraction for DF11/17/18
//     (where the AA field is in the clear; for other DFs the
//     address is XOR-overlaid with the parity field — left to
//     callers to recover via re-interrogation).
//   - Mode S CRC-24 validation (polynomial 0xFFF409, init 0,
//     no reflection) — computes the expected parity field
//     over the data portion and compares to the transmitted
//     parity. Surfaces both the captured PI and the computed
//     value for diffing.
//   - DF17 (ADS-B) Type Code dispatch covering the
//     operationally important sub-types:
//     TC 1-4 (Aircraft Identification with 8-character
//     callsign decoded from the 6-bit AIS / IA-5 alphabet
//     and emitter category lookup), TC 5-8 (Surface Position
//     with movement decode, ground track, and raw CPR),
//     TC 9-18 / 20-22 (Airborne Position with altitude
//     decode from the 12-bit Q-bit field, raw CPR
//     latitude/longitude, and odd/even frame flag),
//     TC 19 (Airborne Velocity: subtype 1/2 ground speed
//     and heading, subtype 3/4 airspeed and magnetic
//     heading, vertical rate with source flag),
//     TC 28 (Aircraft Status: emergency code / squawk),
//     TC 29 (Target State and Status), TC 31 (Aircraft
//     Operation Status).
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - CPR (Compact Position Reporting) lat/lon resolution:
//     global resolution requires pairing an even-frame and an
//     odd-frame from the same aircraft within ~10 seconds;
//     this decoder exposes the raw 17-bit CPR values + the
//     odd/even flag so a higher-level workflow / Spec can do
//     the pairing. Local-CPR resolution (against a reference
//     position) is intentionally deferred until the receiving
//     side has somewhere to put the reference; otherwise the
//     output would be misleading.
//   - DF1/2/3/6-10/12-15/22/23 reserved slot bodies — the DF
//     name is reported but no body decode is attempted
//     because no civil aviation traffic uses these slots in
//     practice (and the bodies have no published civilian
//     spec).
//   - Comm-B BDS register decoding for DF20/21 — only the DF
//     envelope is decoded; the BDS payload requires a
//     register-by-register decoder (BDS 1,7 / 4,0 / 4,4 /
//     5,0 / 6,0 etc.) which is a separate ~600 LoC effort.
//   - TIS-B (DF18) imitation-of-other-format payload variants:
//     DF18 is decoded as if it were DF17, which is correct for
//     the most common CF=0/CF=1 case. CF=2..7 sub-formats
//     (ADS-R, fine TIS-B) are out of scope.
//   - Live demodulation from raw I/Q samples — frames must be
//     pre-decoded to hex by an upstream demodulator
//     (dump1090 --raw output, for instance).
package adsb

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// Frame is the decoded view of a single Mode S downlink frame.
type Frame struct {
	HexInput    string `json:"hex_input"`
	BitCount    int    `json:"bit_count"`
	DF          int    `json:"df"`
	DFName      string `json:"df_name"`
	CA          *int   `json:"ca,omitempty"`
	CAName      string `json:"ca_name,omitempty"`
	ICAOAddress string `json:"icao_address,omitempty"`
	CRC         string `json:"crc"`
	CRCExpected string `json:"crc_expected"`
	CRCValid    bool   `json:"crc_valid"`
	ADSB        *ADSB  `json:"adsb,omitempty"`
}

// ADSB carries the decoded Extended Squitter ME field (DF17 /
// DF18). Only one of the sub-pointers is set per frame — the
// one that matches the Type Code.
type ADSB struct {
	TC               int               `json:"tc"`
	TCName           string            `json:"tc_name"`
	Identification   *Identification   `json:"identification,omitempty"`
	AirbornePosition *AirbornePosition `json:"airborne_position,omitempty"`
	AirborneVelocity *AirborneVelocity `json:"airborne_velocity,omitempty"`
	SurfacePosition  *SurfacePosition  `json:"surface_position,omitempty"`
}

// Identification is the decoded TC 1-4 Aircraft Identification
// message: 8-character callsign + emitter category.
type Identification struct {
	Category     int    `json:"category"`
	CategoryName string `json:"category_name"`
	Callsign     string `json:"callsign"`
}

// AirbornePosition is the decoded TC 9-18 / 20-22 Airborne
// Position message. Latitude/longitude are not resolved here
// — the caller pairs an even + odd frame for a global CPR
// solve. Altitude is decoded from the 12-bit field with the
// Q-bit (25-ft vs 100-ft resolution).
type AirbornePosition struct {
	SurveillanceStatus int    `json:"surveillance_status"`
	AltitudeSource     string `json:"altitude_source"`
	AltitudeFt         int    `json:"altitude_ft,omitempty"`
	AltitudeValid      bool   `json:"altitude_valid"`
	CPRFormat          int    `json:"cpr_format"`
	CPRLatRaw          int    `json:"cpr_lat_raw"`
	CPRLonRaw          int    `json:"cpr_lon_raw"`
}

// AirborneVelocity is the decoded TC 19 Airborne Velocity
// message. Subtypes 1/2 carry ground speed + ground track;
// subtypes 3/4 carry airspeed + magnetic heading.
type AirborneVelocity struct {
	Subtype            int      `json:"subtype"`
	SubtypeName        string   `json:"subtype_name"`
	GroundSpeedKts     *int     `json:"ground_speed_kts,omitempty"`
	GroundTrackDeg     *float64 `json:"ground_track_deg,omitempty"`
	AirspeedKts        *int     `json:"airspeed_kts,omitempty"`
	AirspeedIsIAS      bool     `json:"airspeed_is_ias,omitempty"`
	MagneticHeadingDeg *float64 `json:"magnetic_heading_deg,omitempty"`
	VerticalRateFPM    int      `json:"vertical_rate_fpm"`
	VerticalRateSource string   `json:"vertical_rate_source"`
}

// SurfacePosition is the decoded TC 5-8 Surface Position
// message — for aircraft on the ground.
type SurfacePosition struct {
	Movement         int      `json:"movement"`
	GroundSpeedKts   *float64 `json:"ground_speed_kts,omitempty"`
	GroundTrackDeg   *float64 `json:"ground_track_deg,omitempty"`
	GroundTrackValid bool     `json:"ground_track_valid"`
	CPRFormat        int      `json:"cpr_format"`
	CPRLatRaw        int      `json:"cpr_lat_raw"`
	CPRLonRaw        int      `json:"cpr_lon_raw"`
}

// Decode parses a hex-encoded Mode S frame into a structured
// Frame view. Accepts ':', '-', '_', whitespace as separators
// and a leading '0x' prefix.
func Decode(hexBlob string) (*Frame, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a 7-byte (short) or 14-byte (long)
// Mode S frame into a Frame.
func DecodeBytes(b []byte) (*Frame, error) {
	if len(b) != 7 && len(b) != 14 {
		return nil, fmt.Errorf(
			"adsb: Mode S frame must be 7 bytes (short, 56-bit) or 14 bytes (long, 112-bit); got %d",
			len(b))
	}

	df := int(b[0] >> 3)
	f := &Frame{
		HexInput: strings.ToUpper(hex.EncodeToString(b)),
		BitCount: len(b) * 8,
		DF:       df,
		DFName:   dfName(df),
	}

	if err := validateDFLength(df, len(b)); err != nil {
		return nil, err
	}

	// CRC is the last 3 bytes (24 bits) of every frame.
	f.CRC = strings.ToUpper(hex.EncodeToString(b[len(b)-3:]))
	expected := computeCRC(b)
	f.CRCExpected = fmt.Sprintf("%06X", expected)
	captured := uint32(b[len(b)-3])<<16 | uint32(b[len(b)-2])<<8 | uint32(b[len(b)-1])
	f.CRCValid = captured == expected

	// For DF11 / DF17 / DF18 the ICAO address sits in bits 9-32
	// (bytes 1-3) in the clear, and CA (capability) is bits 6-8
	// of byte 0.
	switch df {
	case 11, 17, 18:
		ca := int(b[0] & 0x07)
		f.CA = &ca
		f.CAName = caName(df, ca)
		f.ICAOAddress = strings.ToUpper(hex.EncodeToString(b[1:4]))
	}

	// ADS-B Extended Squitter body for DF17 + DF18 (CF=0/1).
	if df == 17 || df == 18 {
		f.ADSB = decodeME(b[4:11])
	}

	return f, nil
}

// computeCRC implements the Mode S CRC-24 (G(x) = 0x1FFF409).
// The full message (including the 24-bit parity field) is
// processed; for a valid frame the running register at the end
// is 0. For convenience we compute over (message data, 24 zero
// bits) and return that as the expected parity, so the caller
// can compare against the transmitted parity field directly.
func computeCRC(msg []byte) uint32 {
	const poly = uint32(0x1FFF409) // generator polynomial
	bits := len(msg) * 8
	payloadBits := bits - 24
	var crc uint32
	// Walk the payload bits.
	for i := 0; i < payloadBits; i++ {
		bit := uint32(msg[i>>3]>>(7-(i&7))) & 1
		crc = (crc << 1) | bit
		if crc&0x1000000 != 0 {
			crc ^= poly
		}
	}
	// Walk 24 zero bits to complete the polynomial expansion.
	for i := 0; i < 24; i++ {
		crc <<= 1
		if crc&0x1000000 != 0 {
			crc ^= poly
		}
	}
	return crc & 0xFFFFFF
}

// decodeME dispatches on the 5-bit Type Code at the top of the
// ME field (the 7-byte payload of a DF17 / DF18 long frame).
func decodeME(me []byte) *ADSB {
	if len(me) < 7 {
		return nil
	}
	tc := int(me[0] >> 3)
	a := &ADSB{TC: tc, TCName: tcName(tc)}
	switch {
	case tc >= 1 && tc <= 4:
		a.Identification = decodeIdentification(me)
	case tc >= 5 && tc <= 8:
		a.SurfacePosition = decodeSurfacePosition(me)
	case (tc >= 9 && tc <= 18) || (tc >= 20 && tc <= 22):
		a.AirbornePosition = decodeAirbornePosition(me, tc)
	case tc == 19:
		a.AirborneVelocity = decodeAirborneVelocity(me)
	}
	return a
}

// decodeIdentification parses TC 1-4 Aircraft Identification.
// Layout (bits within the 56-bit ME, 1-indexed per spec):
//
//	1-5   : TC
//	6-8   : Category
//	9-56  : 8 × 6-bit characters (callsign)
func decodeIdentification(me []byte) *Identification {
	cat := int(me[0] & 0x07)
	chars := make([]byte, 8)
	for i := 0; i < 8; i++ {
		bitStart := 8 + i*6
		v := extractBits(me, bitStart, 6)
		chars[i] = decodeAISChar(byte(v))
	}
	cs := strings.TrimRight(string(chars), " ")
	return &Identification{
		Category:     cat,
		CategoryName: categoryName(int(me[0]>>3), cat),
		Callsign:     cs,
	}
}

// decodeAirbornePosition parses TC 9-18 / 20-22 Airborne
// Position. Layout (bits within the 56-bit ME):
//
//	1-5   : TC
//	6-7   : Surveillance Status
//	8     : NIC Supplement B (single antenna flag in older
//	        spec versions; here exposed as part of surveillance
//	        flags by the caller)
//	9-20  : Altitude (12 bits with Q-bit at bit 16)
//	21    : T flag (time sync)
//	22    : CPR Format (0=even, 1=odd)
//	23-39 : CPR Latitude (17 bits)
//	40-56 : CPR Longitude (17 bits)
//
// TC 9-18 = barometric altitude, TC 20-22 = GNSS altitude.
func decodeAirbornePosition(me []byte, tc int) *AirbornePosition {
	src := "barometric"
	if tc >= 20 && tc <= 22 {
		src = "GNSS"
	}
	ap := &AirbornePosition{
		SurveillanceStatus: int((me[0] >> 1) & 0x03),
		AltitudeSource:     src,
		CPRFormat:          int((me[2] >> 2) & 0x01),
		CPRLatRaw:          extractBits(me, 22, 17),
		CPRLonRaw:          extractBits(me, 39, 17),
	}
	rawAlt := extractBits(me, 8, 12)
	if alt, ok := decodeAltitude12(rawAlt); ok {
		ap.AltitudeFt = alt
		ap.AltitudeValid = true
	}
	return ap
}

// decodeAltitude12 decodes the 12-bit altitude field used in
// airborne position messages. The Q-bit (bit 4 of the field,
// counted from the MSB) selects encoding:
//
//	Q = 1 : N × 25 - 1000 ft, where N is the 11-bit binary
//	        value formed by stripping the Q-bit.
//	Q = 0 : Gillham (Mode C) gray-coded altitude — exposed as
//	        invalid here because Gillham decoding adds ~80 LoC
//	        of permutation logic and is rare in modern ADS-B
//	        traffic (most aircraft transmit Q=1).
func decodeAltitude12(raw int) (int, bool) {
	if raw == 0 {
		return 0, false
	}
	q := (raw >> 4) & 0x01
	if q == 0 {
		return 0, false
	}
	// Strip Q-bit: take top 7 bits + bottom 4 bits.
	n := ((raw >> 5) << 4) | (raw & 0x0F)
	return n*25 - 1000, true
}

// decodeAirborneVelocity parses TC 19 Airborne Velocity.
// Subtype field is bits 6-8 of byte 0.
func decodeAirborneVelocity(me []byte) *AirborneVelocity {
	sub := int(me[0] & 0x07)
	av := &AirborneVelocity{
		Subtype:     sub,
		SubtypeName: velocitySubtypeName(sub),
	}
	switch sub {
	case 1, 2:
		// Ground-speed subtype:
		// bit 9   : EW direction (0 = East, 1 = West)
		// bits 10-19 : EW velocity (10 bits, -1 to get knots)
		// bit 20  : NS direction (0 = North, 1 = South)
		// bits 21-30 : NS velocity (10 bits, -1 to get knots)
		ewDir := int((me[1] >> 2) & 0x01)
		ewVel := (int(me[1]&0x03) << 8) | int(me[2])
		nsDir := int((me[3] >> 7) & 0x01)
		nsVel := (int(me[3]&0x7F) << 3) | (int(me[4]) >> 5)
		if ewVel > 0 && nsVel > 0 {
			ewSigned := float64(ewVel - 1)
			nsSigned := float64(nsVel - 1)
			if ewDir == 1 {
				ewSigned = -ewSigned
			}
			if nsDir == 1 {
				nsSigned = -nsSigned
			}
			gs := int(math.Sqrt(ewSigned*ewSigned + nsSigned*nsSigned))
			av.GroundSpeedKts = &gs
			heading := math.Atan2(ewSigned, nsSigned) * 180.0 / math.Pi
			if heading < 0 {
				heading += 360.0
			}
			av.GroundTrackDeg = &heading
		}
	case 3, 4:
		// Air-speed subtype:
		// bit 9   : Heading-available flag
		// bits 10-19 : Magnetic heading (10 bits, value × 360/1024)
		// bit 20  : Airspeed type (0 = IAS, 1 = TAS)
		// bits 21-30 : Airspeed (10 bits, kts)
		if (me[1]>>2)&0x01 == 1 {
			hdgRaw := (int(me[1]&0x03) << 8) | int(me[2])
			h := float64(hdgRaw) * 360.0 / 1024.0
			av.MagneticHeadingDeg = &h
		}
		av.AirspeedIsIAS = (me[3]>>7)&0x01 == 0
		spdRaw := (int(me[3]&0x7F) << 3) | (int(me[4]) >> 5)
		if spdRaw > 0 {
			sp := spdRaw - 1
			av.AirspeedKts = &sp
		}
	}
	// Vertical rate (bits 36-46 of ME, across bytes 4-5):
	//   bit 36 : source (0 = barometric, 1 = GNSS) per DO-260B
	//   bit 37 : sign (0 = up, 1 = down)
	//   bits 38-46 : magnitude (9 bits, (N-1) × 64 = fpm)
	vrSrc := (me[4] >> 4) & 0x01
	if vrSrc == 0 {
		av.VerticalRateSource = "barometric"
	} else {
		av.VerticalRateSource = "GNSS"
	}
	vrSign := (me[4] >> 3) & 0x01
	vrMag := (int(me[4]&0x07) << 6) | (int(me[5]) >> 2)
	if vrMag > 0 {
		fpm := (vrMag - 1) * 64
		if vrSign == 1 {
			fpm = -fpm
		}
		av.VerticalRateFPM = fpm
	}
	return av
}

// decodeSurfacePosition parses TC 5-8 Surface Position.
// Layout (bits within the 56-bit ME):
//
//	1-5   : TC
//	6-12  : Movement (7 bits — encoded ground speed)
//	13    : Heading status (1 = valid)
//	14-20 : Ground track (7 bits — value × 360/128 = degrees)
//	21    : Time flag
//	22    : CPR Format
//	23-39 : CPR Latitude
//	40-56 : CPR Longitude
func decodeSurfacePosition(me []byte) *SurfacePosition {
	mov := int(((me[0] & 0x07) << 4) | (me[1] >> 4))
	sp := &SurfacePosition{
		Movement:  mov,
		CPRFormat: int((me[2] >> 2) & 0x01),
		CPRLatRaw: extractBits(me, 22, 17),
		CPRLonRaw: extractBits(me, 39, 17),
	}
	gs := movementToSpeed(mov)
	if gs >= 0 {
		sp.GroundSpeedKts = &gs
	}
	if (me[1]>>3)&0x01 == 1 {
		sp.GroundTrackValid = true
		trkRaw := (int(me[1]&0x07) << 4) | (int(me[2]) >> 4)
		trk := float64(trkRaw) * 360.0 / 128.0
		sp.GroundTrackDeg = &trk
	}
	return sp
}

// movementToSpeed maps the 7-bit Movement field of a surface
// position to a ground speed in knots, per the piecewise table
// in DO-260B §2.2.3.2.5.4.7. Returns -1 for the reserved /
// "no speed" code 0.
func movementToSpeed(m int) float64 {
	switch {
	case m == 0:
		return -1
	case m == 1:
		return 0
	case m == 124:
		return 175
	case m == 125, m == 126, m == 127:
		return -1
	case m >= 2 && m <= 8:
		return float64(m-1) * 0.125
	case m >= 9 && m <= 12:
		return 1 + float64(m-9)*0.25
	case m >= 13 && m <= 38:
		return 2 + float64(m-13)*0.5
	case m >= 39 && m <= 93:
		return 15 + float64(m-39)
	case m >= 94 && m <= 108:
		return 70 + float64(m-94)*2
	case m >= 109 && m <= 123:
		return 100 + float64(m-109)*5
	}
	return -1
}

// extractBits pulls n bits from byteSlice starting at bit
// position start (0-indexed from the MSB of byteSlice[0]).
func extractBits(b []byte, start, n int) int {
	var v int
	for i := 0; i < n; i++ {
		pos := start + i
		bit := int(b[pos>>3]>>(7-(pos&7))) & 1
		v = (v << 1) | bit
	}
	return v
}

// decodeAISChar maps a 6-bit ICAO Annex 10 Volume IV alphabet
// value to its ASCII character. Codes 1-26 = A-Z, 32 = space,
// 48-57 = '0'-'9'; everything else renders as '#' so an
// unexpected callsign still shows up in the output.
func decodeAISChar(v byte) byte {
	switch {
	case v >= 1 && v <= 26:
		return 'A' + (v - 1)
	case v == 32:
		return ' '
	case v >= 48 && v <= 57:
		return v
	}
	return '#'
}

// dfName maps a Downlink Format code to its canonical name.
func dfName(df int) string {
	switch df {
	case 0:
		return "Short Air-Air Surveillance"
	case 4:
		return "Surveillance, Altitude Reply"
	case 5:
		return "Surveillance, Identity Reply"
	case 11:
		return "All-Call Reply"
	case 16:
		return "Long Air-Air Surveillance"
	case 17:
		return "Extended Squitter (ADS-B)"
	case 18:
		return "Extended Squitter / Non-Transponder (TIS-B / ADS-R)"
	case 19:
		return "Military Extended Squitter"
	case 20:
		return "Comm-B, Altitude Reply"
	case 21:
		return "Comm-B, Identity Reply"
	case 22:
		return "Reserved for military use"
	case 24, 25, 26, 27, 28, 29, 30, 31:
		return "Comm-D Extended Length Message"
	}
	return fmt.Sprintf("Reserved (DF%d)", df)
}

// validateDFLength enforces the documented frame width for each
// DF. Short frames (DF0/4/5/11) are 56 bits; the rest are 112.
func validateDFLength(df, byteLen int) error {
	short := df == 0 || df == 4 || df == 5 || df == 11
	if short && byteLen != 7 {
		return fmt.Errorf("adsb: DF%d is a short (56-bit) frame; expected 7 bytes, got %d", df, byteLen)
	}
	if !short && byteLen != 14 {
		return fmt.Errorf("adsb: DF%d is a long (112-bit) frame; expected 14 bytes, got %d", df, byteLen)
	}
	return nil
}

// caName maps the 3-bit Capability field for DF11/17/18. The
// meaning differs slightly between DF11 (transponder
// capability) and DF17 (airborne/surface/uncertain).
func caName(df, ca int) string {
	if df == 17 || df == 18 {
		switch ca {
		case 0:
			return "Level 1 transponder (Comm-A / Comm-B not supported)"
		case 4:
			return "Level 2+ transponder, on ground"
		case 5:
			return "Level 2+ transponder, airborne"
		case 6:
			return "Level 2+ transponder, either airborne or ground"
		case 7:
			return "DR/FS field signals alert / SPI / on-ground"
		}
		return fmt.Sprintf("Reserved (CA%d)", ca)
	}
	// DF11 capability codes are interpreted under DO-181E.
	switch ca {
	case 0:
		return "Level 1 transponder"
	case 4:
		return "Level 2 transponder, on ground"
	case 5:
		return "Level 2 transponder, airborne"
	case 6:
		return "Level 2 transponder, either state"
	case 7:
		return "Cross-link capability"
	}
	return fmt.Sprintf("Reserved (CA%d)", ca)
}

// tcName names the 5-bit Type Code at the top of an ADS-B ME
// field.
func tcName(tc int) string {
	switch {
	case tc >= 1 && tc <= 4:
		return "Aircraft Identification and Category"
	case tc >= 5 && tc <= 8:
		return "Surface Position"
	case tc >= 9 && tc <= 18:
		return "Airborne Position (barometric altitude)"
	case tc == 19:
		return "Airborne Velocity"
	case tc >= 20 && tc <= 22:
		return "Airborne Position (GNSS altitude)"
	case tc == 23:
		return "Reserved for test"
	case tc >= 24 && tc <= 27:
		return "Reserved"
	case tc == 28:
		return "Aircraft Status (emergency / squawk)"
	case tc == 29:
		return "Target State and Status Information"
	case tc == 31:
		return "Aircraft Operation Status"
	}
	return fmt.Sprintf("Reserved (TC%d)", tc)
}

// categoryName maps the Emitter Category sub-field within TC
// 1-4 Aircraft Identification to its readable name. The TC
// itself selects the category set (A/B/C/D) per DO-260B §3.1.5.
func categoryName(tc, cat int) string {
	if cat == 0 {
		return "No category information"
	}
	switch tc {
	case 4: // Set A (light/small/large/heavy)
		switch cat {
		case 1:
			return "Light aircraft (< 15,500 lb)"
		case 2:
			return "Small aircraft (15,500-75,000 lb)"
		case 3:
			return "Large aircraft (75,000-300,000 lb)"
		case 4:
			return "High vortex large (e.g. B757)"
		case 5:
			return "Heavy (≥ 300,000 lb)"
		case 6:
			return "High performance (> 5g and > 400 kt)"
		case 7:
			return "Rotorcraft"
		}
	case 3: // Set B
		switch cat {
		case 1:
			return "Glider / sailplane"
		case 2:
			return "Lighter-than-air"
		case 3:
			return "Parachutist / skydiver"
		case 4:
			return "Ultralight / hang-glider / paraglider"
		case 5:
			return "Reserved"
		case 6:
			return "Unmanned aerial vehicle"
		case 7:
			return "Space / transatmospheric vehicle"
		}
	case 2: // Set C — surface
		switch cat {
		case 1:
			return "Surface vehicle — emergency vehicle"
		case 2:
			return "Surface vehicle — service vehicle"
		case 3:
			return "Point obstacle (tower)"
		case 4:
			return "Cluster obstacle"
		case 5:
			return "Line obstacle"
		}
	case 1: // Set D — reserved
		return fmt.Sprintf("Reserved category D%d", cat)
	}
	return fmt.Sprintf("Category %d", cat)
}

// velocitySubtypeName labels the 3-bit subtype of TC 19.
func velocitySubtypeName(sub int) string {
	switch sub {
	case 1:
		return "Ground speed, normal"
	case 2:
		return "Ground speed, supersonic"
	case 3:
		return "Airspeed, normal"
	case 4:
		return "Airspeed, supersonic"
	}
	return fmt.Sprintf("Reserved (subtype %d)", sub)
}

// parseHex strips separators and decodes a hex blob into bytes.
func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("adsb: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("adsb: invalid hex: %w", err)
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
