// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import (
	"encoding/hex"
	"strings"
)

// Mode S Comm-B (DF20/21) BDS register decoding (ICAO Doc 9871).
//
// A Comm-B reply carries a 56-bit Message-B (MB) field whose meaning
// is NOT self-describing: the same bits could be any BDS register, and
// the frame says nothing about which one. The receiver must INFER the
// register from the content — a register only "fits" if its status
// bits are internally consistent and its decoded values fall in the
// physically valid range. This decoder reproduces the pyModeS
// inference gates (is10/is17/is20/is40/is50/is60): a register is only
// reported when its validity gate passes, and when more than one gate
// passes the result is flagged ambiguous rather than guessed — no
// confidently-wrong output.
//
// Registers decoded:
//
//   - BDS 2,0 Aircraft identification (callsign)
//   - BDS 4,0 Selected vertical intention (MCP/FCU + FMS selected
//     altitude, barometric pressure setting)
//   - BDS 5,0 Track and turn report (roll, true track, ground speed,
//     track-angle rate, true airspeed)
//   - BDS 6,0 Heading and speed report (magnetic heading, IAS, Mach,
//     barometric + inertial vertical rate)
//   - BDS 1,7 Common-usage GICB capability report (list of supported
//     registers)
//
// BDS 1,0 (data-link capability) participates in inference but its
// field decode is deferred. Every register and field is anchored
// byte-for-byte to the pyModeS reference test vectors (commb_test.go).

// CommB is the decoded Comm-B (DF20/21) MB field.
type CommB struct {
	MBHex string `json:"mb_hex"`
	// InferredRegisters lists every BDS code whose validity gate passes.
	// Exactly one is the normal case; an empty list means no known
	// register fit (the MB may be a register this decoder does not cover);
	// more than one is surfaced with an ambiguity note.
	InferredRegisters []string                `json:"inferred_registers"`
	BDS20             *BDS20Identification    `json:"bds20_identification,omitempty"`
	BDS40             *BDS40VerticalIntention `json:"bds40_selected_vertical_intention,omitempty"`
	BDS50             *BDS50TrackTurn         `json:"bds50_track_turn_report,omitempty"`
	BDS60             *BDS60HeadingSpeed      `json:"bds60_heading_speed_report,omitempty"`
	BDS17             *BDS17Capability        `json:"bds17_gicb_capability,omitempty"`
	Notes             []string                `json:"notes,omitempty"`
}

// BDS20Identification is the BDS 2,0 callsign.
type BDS20Identification struct {
	Callsign string `json:"callsign"`
}

// BDS40VerticalIntention is the BDS 4,0 selected-vertical-intention report.
type BDS40VerticalIntention struct {
	MCPSelectedAltitudeFt *int     `json:"mcp_selected_altitude_ft,omitempty"`
	FMSSelectedAltitudeFt *int     `json:"fms_selected_altitude_ft,omitempty"`
	BarometricPressureMB  *float64 `json:"barometric_pressure_mb,omitempty"`
}

// BDS50TrackTurn is the BDS 5,0 track-and-turn report.
type BDS50TrackTurn struct {
	RollAngleDeg    *float64 `json:"roll_angle_deg,omitempty"`
	TrueTrackDeg    *float64 `json:"true_track_angle_deg,omitempty"`
	GroundSpeedKts  *int     `json:"ground_speed_kts,omitempty"`
	TrackAngleRate  *float64 `json:"track_angle_rate_deg_s,omitempty"`
	TrueAirspeedKts *int     `json:"true_airspeed_kts,omitempty"`
}

// BDS60HeadingSpeed is the BDS 6,0 heading-and-speed report.
type BDS60HeadingSpeed struct {
	MagneticHeadingDeg  *float64 `json:"magnetic_heading_deg,omitempty"`
	IndicatedAirspeed   *int     `json:"indicated_airspeed_kts,omitempty"`
	Mach                *float64 `json:"mach,omitempty"`
	VerticalRateBaroFPM *int     `json:"vertical_rate_barometric_fpm,omitempty"`
	VerticalRateInsFPM  *int     `json:"vertical_rate_inertial_fpm,omitempty"`
}

// BDS17Capability is the BDS 1,7 GICB capability report.
type BDS17Capability struct {
	SupportedRegisters []string `json:"supported_registers"`
}

// decodeCommB decodes the 56-bit MB field (mb = the 7 bytes at offset
// 4..10 of a DF20/21 frame) into whatever BDS register(s) structurally
// validate. df is the downlink format (20 or 21), used by the BDS 6,0
// gate's optional cross-check.
func decodeCommB(mb []byte) *CommB {
	if len(mb) < 7 {
		return nil
	}
	cb := &CommB{MBHex: strings.ToUpper(hex.EncodeToString(mb[:7]))}

	if commbAllZero(mb) {
		cb.Notes = append(cb.Notes, "MB field is all zeros (no Comm-B data)")
		cb.InferredRegisters = []string{}
		return cb
	}

	var inferred []string
	bds10 := false
	if is10(mb) {
		inferred = append(inferred, "BDS10")
		bds10 = true
	}
	if is17(mb) {
		inferred = append(inferred, "BDS17")
		cb.BDS17 = decodeBDS17(mb)
	}
	if is20(mb) {
		inferred = append(inferred, "BDS20")
		cb.BDS20 = &BDS20Identification{Callsign: cs20(mb)}
	}
	if is40(mb) {
		inferred = append(inferred, "BDS40")
		cb.BDS40 = decodeBDS40(mb)
	}
	if is50(mb) {
		inferred = append(inferred, "BDS50")
		cb.BDS50 = decodeBDS50(mb)
	}
	if is60(mb) {
		inferred = append(inferred, "BDS60")
		cb.BDS60 = decodeBDS60(mb)
	}
	if inferred == nil {
		inferred = []string{}
		cb.Notes = append(cb.Notes,
			"no known BDS register matched — the MB field may carry a register this decoder does not cover")
	} else if len(inferred) > 1 {
		cb.Notes = append(cb.Notes,
			"more than one BDS register validates — Comm-B identity is ambiguous; treat decodes as candidates")
	}
	cb.InferredRegisters = inferred
	if bds10 {
		cb.Notes = append(cb.Notes, "BDS10 (data-link capability) inferred; field decode deferred")
	}
	return cb
}

// ---- validity gates (pyModeS is10/is17/is20/is40/is50/is60) ----

// wrongStatus mirrors pyModeS common.wrongstatus: status bit sb (1-indexed)
// gates the field spanning bits msb..lsb (1-indexed, inclusive). Returns
// true (invalid) when the status bit is 0 but the gated field is non-zero.
func wrongStatus(mb []byte, sb, msb, lsb int) bool {
	if extractBits(mb, sb-1, 1) == 1 {
		return false
	}
	return extractBits(mb, msb-1, lsb-msb+1) != 0
}

func commbAllZero(mb []byte) bool {
	for _, b := range mb[:7] {
		if b != 0 {
			return false
		}
	}
	return true
}

func is10(mb []byte) bool {
	if commbAllZero(mb) {
		return false
	}
	if extractBits(mb, 0, 8) != 0x10 { // first 8 bits must be 0x10
		return false
	}
	if extractBits(mb, 9, 5) != 0 { // bits 10-14 reserved (d[9:14])
		return false
	}
	ovc := extractBits(mb, 14, 1)
	subnet := extractBits(mb, 16, 7) // d[16:23]
	if ovc == 1 && subnet < 5 {
		return false
	}
	if ovc == 0 && subnet > 4 {
		return false
	}
	return true
}

func is17(mb []byte) bool {
	if commbAllZero(mb) {
		return false
	}
	if extractBits(mb, 24, 32) != 0 { // d[24:56] must be zero
		return false
	}
	for _, r := range bds17Registers(mb) {
		if r == "BDS20" {
			return true
		}
	}
	return false
}

func is20(mb []byte) bool {
	if commbAllZero(mb) {
		return false
	}
	if extractBits(mb, 0, 8) != 0x20 { // BDS code 2,0 in the first byte
		return false
	}
	// Empty callsign is allowed.
	if extractBits(mb, 8, 24) == 0 && extractBits(mb, 32, 24) == 0 {
		return true
	}
	for _, c := range cs20(mb) {
		if c == '#' {
			return false
		}
	}
	return true
}

func is40(mb []byte) bool {
	if commbAllZero(mb) {
		return false
	}
	if wrongStatus(mb, 1, 2, 13) || wrongStatus(mb, 14, 15, 26) ||
		wrongStatus(mb, 27, 28, 39) || wrongStatus(mb, 48, 49, 51) ||
		wrongStatus(mb, 54, 55, 56) {
		return false
	}
	if extractBits(mb, 39, 8) != 0 { // d[39:47] shall be zero
		return false
	}
	if extractBits(mb, 51, 2) != 0 { // d[51:53] shall be zero
		return false
	}
	return true
}

func is50(mb []byte) bool {
	if commbAllZero(mb) {
		return false
	}
	if wrongStatus(mb, 1, 3, 11) || wrongStatus(mb, 12, 13, 23) ||
		wrongStatus(mb, 24, 25, 34) || wrongStatus(mb, 35, 36, 45) ||
		wrongStatus(mb, 46, 47, 56) {
		return false
	}
	roll := roll50(mb)
	if roll != nil && absF(*roll) > 50 {
		return false
	}
	gs := gs50(mb)
	if gs != nil && *gs > 600 {
		return false
	}
	tas := tas50(mb)
	if tas != nil && *tas > 500 {
		return false
	}
	if gs != nil && tas != nil && absInt(*tas-*gs) > 200 {
		return false
	}
	return true
}

func is60(mb []byte) bool {
	if commbAllZero(mb) {
		return false
	}
	if wrongStatus(mb, 1, 2, 12) || wrongStatus(mb, 13, 14, 23) ||
		wrongStatus(mb, 24, 25, 34) || wrongStatus(mb, 35, 36, 45) ||
		wrongStatus(mb, 46, 47, 56) {
		return false
	}
	ias := ias60(mb)
	if ias != nil && *ias > 500 {
		return false
	}
	mach := mach60(mb)
	if mach != nil && *mach > 1 {
		return false
	}
	vrb := vr60baro(mb)
	if vrb != nil && absInt(*vrb) > 6000 {
		return false
	}
	vri := vr60ins(mb)
	if vri != nil && absInt(*vri) > 6000 {
		return false
	}
	return true
}

// ---- field decoders (pyModeS bds20/40/50/60) ----

// bds20Chars is the BDS 2,0 / IA-5 6-bit callsign alphabet (note: index
// 32 maps to '_', distinct from the ADS-B identification table's space).
const bds20Chars = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ#####_###############0123456789######"

func cs20(mb []byte) string {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = bds20Chars[extractBits(mb, 8+i*6, 6)]
	}
	return string(out)
}

func decodeBDS40(mb []byte) *BDS40VerticalIntention {
	r := &BDS40VerticalIntention{}
	if extractBits(mb, 0, 1) == 1 {
		v := extractBits(mb, 1, 12) * 16
		r.MCPSelectedAltitudeFt = &v
	}
	if extractBits(mb, 13, 1) == 1 {
		v := extractBits(mb, 14, 12) * 16
		r.FMSSelectedAltitudeFt = &v
	}
	if extractBits(mb, 26, 1) == 1 {
		p := float64(extractBits(mb, 27, 12))*0.1 + 800
		r.BarometricPressureMB = &p
	}
	return r
}

func decodeBDS50(mb []byte) *BDS50TrackTurn {
	return &BDS50TrackTurn{
		RollAngleDeg:    roll50(mb),
		TrueTrackDeg:    trk50(mb),
		GroundSpeedKts:  gs50(mb),
		TrackAngleRate:  rtrk50(mb),
		TrueAirspeedKts: tas50(mb),
	}
}

func roll50(mb []byte) *float64 {
	if extractBits(mb, 0, 1) == 0 {
		return nil
	}
	value := extractBits(mb, 2, 9)
	if extractBits(mb, 1, 1) == 1 { // sign
		value -= 512
	}
	a := float64(value) * 45 / 256
	return &a
}

func trk50(mb []byte) *float64 {
	if extractBits(mb, 11, 1) == 0 {
		return nil
	}
	value := extractBits(mb, 13, 10)
	if extractBits(mb, 12, 1) == 1 { // sign -> west
		value -= 1024
	}
	trk := float64(value) * 90 / 512
	if trk < 0 {
		trk += 360
	}
	return &trk
}

func gs50(mb []byte) *int {
	if extractBits(mb, 23, 1) == 0 {
		return nil
	}
	v := extractBits(mb, 24, 10) * 2
	return &v
}

func rtrk50(mb []byte) *float64 {
	if extractBits(mb, 34, 1) == 0 {
		return nil
	}
	if extractBits(mb, 36, 9) == 0x1FF { // all ones -> invalid
		return nil
	}
	value := extractBits(mb, 36, 9)
	if extractBits(mb, 35, 1) == 1 { // sign
		value -= 512
	}
	a := float64(value) * 8 / 256
	return &a
}

func tas50(mb []byte) *int {
	if extractBits(mb, 45, 1) == 0 {
		return nil
	}
	v := extractBits(mb, 46, 10) * 2
	return &v
}

func decodeBDS60(mb []byte) *BDS60HeadingSpeed {
	return &BDS60HeadingSpeed{
		MagneticHeadingDeg:  hdg60(mb),
		IndicatedAirspeed:   ias60(mb),
		Mach:                mach60(mb),
		VerticalRateBaroFPM: vr60baro(mb),
		VerticalRateInsFPM:  vr60ins(mb),
	}
}

func hdg60(mb []byte) *float64 {
	if extractBits(mb, 0, 1) == 0 {
		return nil
	}
	value := extractBits(mb, 2, 10)
	if extractBits(mb, 1, 1) == 1 { // sign -> west
		value -= 1024
	}
	hdg := float64(value) * 90 / 512
	if hdg < 0 {
		hdg += 360
	}
	return &hdg
}

func ias60(mb []byte) *int {
	if extractBits(mb, 12, 1) == 0 {
		return nil
	}
	v := extractBits(mb, 13, 10)
	return &v
}

func mach60(mb []byte) *float64 {
	if extractBits(mb, 23, 1) == 0 {
		return nil
	}
	m := float64(extractBits(mb, 24, 10)) * 2.048 / 512
	return &m
}

func vr60baro(mb []byte) *int {
	if extractBits(mb, 34, 1) == 0 {
		return nil
	}
	return verticalRate(mb, 35, 36)
}

func vr60ins(mb []byte) *int {
	if extractBits(mb, 45, 1) == 0 {
		return nil
	}
	return verticalRate(mb, 46, 47)
}

// verticalRate decodes a 9-bit two's-complement vertical-rate value with a
// separate sign bit, scaled by 32 ft/min (BDS 6,0 baro/inertial fields).
func verticalRate(mb []byte, signBit, valueBit int) *int {
	value := extractBits(mb, valueBit, 9)
	if value == 0 || value == 511 { // all zeros or all ones -> 0
		z := 0
		return &z
	}
	if extractBits(mb, signBit, 1) == 1 {
		value -= 512
	}
	roc := value * 32
	return &roc
}

func decodeBDS17(mb []byte) *BDS17Capability {
	return &BDS17Capability{SupportedRegisters: bds17Registers(mb)}
}

// bds17AllBDS is the ordered BDS-code list addressed by bits 0..23 of a
// BDS 1,7 capability report (pyModeS bds17.cap17).
var bds17AllBDS = []string{
	"05", "06", "07", "08", "09", "0A", "20", "21",
	"40", "41", "42", "43", "44", "45", "48", "50",
	"51", "52", "53", "54", "55", "56", "5F", "60",
}

func bds17Registers(mb []byte) []string {
	var caps []string
	for i := 0; i < 24; i++ {
		if extractBits(mb, i, 1) == 1 {
			caps = append(caps, "BDS"+bds17AllBDS[i])
		}
	}
	return caps
}

// ---- small helpers ----

func absF(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
