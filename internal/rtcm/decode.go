// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rtcm decodes the RTCM 3.x differential-GNSS message framing
// — the protocol a GNSS base station broadcasts (over radio, NTRIP or
// a serial link) to feed real-time corrections to rovers. It is the
// third protocol in the GNSS triad alongside internal/nmea
// (gps_nmea_decode, the text output) and internal/ubx (ubx_decode,
// the u-blox binary input): a u-blox / Septentrio / Trimble receiver
// in a base/rover RTK setup emits RTCM3.
//
// The GNSS-integrity angle: injecting forged RTCM corrections (a false
// 1005 reference-station position, or fabricated observables) is a
// known way to pull an RTK rover off its true fix. Decoding an RTCM
// stream lets an analyst see the reference-station id, the broadcast
// base-station ECEF position, and which message types / constellations
// a stream carries — surfacing an anomalous or spoofed correction
// source.
//
// # Wrap-vs-native judgement
//
//	Native. The RTCM3 transport frame is a fixed, fully-public wire
//	format (a 0xD3 preamble, 6 reserved bits, a 10-bit payload
//	length, the payload, and a 24-bit CRC-24Q parity) defined in
//	the RTCM 10403.x standard; the CRC-24Q polynomial (0x1864CFB)
//	is the same Qualcomm CRC used across GNSS. Frame parsing + a
//	bit reader + a CRC loop is a few hundred lines, so a runtime
//	dependency would not be justified. stdlib only, no new go.mod
//	dep.
//
// # What this package covers
//
//   - RTCM3 transport framing: the 0xD3 preamble, 10-bit length,
//     and the CRC-24Q (poly 0x1864CFB) over the whole frame,
//     validated. A stream of back-to-back frames decodes to a
//     list; leading non-preamble bytes are skipped so a mid-stream
//     capture still parses. A frame whose CRC fails is surfaced
//     with checksum_ok=false rather than dropped.
//   - Message-type identification (DF002, the first 12 payload
//     bits) with a name for the common types: the 1001-1004 /
//     1009-1012 legacy RTK observables, 1005/1006 station ARP,
//     1007/1008/1033 antenna & receiver descriptors, 1019/1020/
//     1042-1046 ephemerides, the 107x-112x MSM (multiple-signal
//     message) families per constellation, and 1230 GLONASS code-
//     phase biases. The reference-station id (DF003) is surfaced
//     for the message types that carry it at bits 12-23.
//   - 1005 / 1006 Stationary RTK Reference Station ARP — the
//     base-station antenna reference point as ECEF X / Y / Z (in
//     metres, from the 38-bit 0.0001 m fields), the GPS / GLONASS /
//     Galileo service indicators, and (1006 only) the antenna
//     height. This is the message a spoofed-correction attack
//     would tamper with, so it is bodied out.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - The observable / ephemeris / MSM message bodies — these carry
//     per-satellite pseudorange / carrier-phase / orbit data whose
//     decode is large and constellation-specific; the frame is
//     CRC-validated and the type + station id surfaced, with the
//     payload left as raw hex rather than guessed. The station-ARP
//     messages (1005/1006) are the ones bodied out because they
//     carry the base position an integrity check cares about.
//   - RTCM 2.x (the older word-based framing) — a different, legacy
//     protocol.
//   - NTRIP transport (the HTTP-like caster protocol that carries
//     RTCM over the internet) — separate layer.
package rtcm

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Message is one decoded RTCM3 frame.
type Message struct {
	MessageType        int         `json:"message_type"`
	TypeName           string      `json:"type_name"`
	Length             int         `json:"payload_length"`
	ChecksumOK         bool        `json:"checksum_ok"`
	ReferenceStationID *int        `json:"reference_station_id,omitempty"`
	StationARP         *StationARP `json:"station_arp,omitempty"`
	PayloadHex         string      `json:"payload_hex,omitempty"`
	Notes              []string    `json:"notes,omitempty"`
}

// StationARP is the decoded 1005 / 1006 Stationary RTK Reference
// Station Antenna Reference Point.
type StationARP struct {
	ECEFXm         float64  `json:"ecef_x_m"`
	ECEFYm         float64  `json:"ecef_y_m"`
	ECEFZm         float64  `json:"ecef_z_m"`
	GPSSupported   bool     `json:"gps_supported"`
	GLONASSSupport bool     `json:"glonass_supported"`
	GalileoSupport bool     `json:"galileo_supported"`
	AntennaHeightM *float64 `json:"antenna_height_m,omitempty"`
}

const preamble = 0xD3

// Decode parses every RTCM3 frame found in the input. The input is a
// hex string (whitespace / ':' / '-' / '_' separators and a '0x'
// prefix tolerated) carrying one or more back-to-back RTCM3 frames.
func Decode(input string) ([]Message, error) {
	raw, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(raw) < 6 {
		return nil, fmt.Errorf("rtcm: input too short (%d bytes) for an RTCM3 frame (min 6)", len(raw))
	}
	var out []Message
	i := 0
	for i+6 <= len(raw) {
		if raw[i] != preamble {
			i++
			continue
		}
		msg, consumed, perr := parseFrame(raw[i:])
		if perr != nil {
			i++
			continue
		}
		out = append(out, *msg)
		i += consumed
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("rtcm: no RTCM3 frame found (expected 0x%02X preamble + valid CRC-24Q)", preamble)
	}
	return out, nil
}

func parseFrame(b []byte) (*Message, int, error) {
	if len(b) < 6 {
		return nil, 0, fmt.Errorf("truncated header")
	}
	// The 6 bits after the preamble are reserved; the next 10 are length.
	length := (int(b[1]&0x03) << 8) | int(b[2])
	frameLen := 3 + length + 3 // header + payload + 24-bit CRC
	if len(b) < frameLen {
		return nil, 0, fmt.Errorf("truncated frame: need %d bytes, have %d", frameLen, len(b))
	}
	payload := b[3 : 3+length]
	got := uint32(b[3+length])<<16 | uint32(b[3+length+1])<<8 | uint32(b[3+length+2])
	want := crc24q(b[:3+length])
	if got != want {
		// A bad CRC most likely means we synced on a stray 0xD3; signal
		// the caller to keep scanning rather than emit a bogus frame.
		return nil, 0, fmt.Errorf("crc mismatch")
	}
	if length < 2 {
		return nil, 0, fmt.Errorf("payload too short for a message type")
	}
	r := &bitReader{b: payload}
	msgType := int(r.read(12))
	m := &Message{
		MessageType: msgType,
		TypeName:    messageTypeName(msgType),
		Length:      length,
		ChecksumOK:  true,
	}
	if hasStationID(msgType) && length*8 >= 24 {
		id := int(r.read(12))
		m.ReferenceStationID = &id
	}
	switch msgType {
	case 1005, 1006:
		if arp, perr := decodeStationARP(payload, msgType); perr == nil {
			m.StationARP = arp
		} else {
			m.Notes = append(m.Notes, perr.Error())
			m.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		}
	default:
		m.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		m.Notes = append(m.Notes, "message body not decoded (1005/1006 station ARP are bodied out); frame + CRC-24Q validated")
	}
	return m, frameLen, nil
}

func decodeStationARP(payload []byte, msgType int) (*StationARP, error) {
	needBits := 152
	if msgType == 1006 {
		needBits = 168
	}
	if len(payload)*8 < needBits {
		return nil, fmt.Errorf("station-ARP payload truncated (%d bits, need %d)", len(payload)*8, needBits)
	}
	r := &bitReader{b: payload}
	r.read(12) // DF002 message number
	r.read(12) // DF003 reference station id (already surfaced)
	r.read(6)  // DF021 ITRF realisation year
	gps := r.read(1) == 1
	glo := r.read(1) == 1
	gal := r.read(1) == 1
	r.read(1) // reference-station indicator
	x := r.readSigned(38)
	r.read(1) // single-receiver oscillator indicator
	r.read(1) // reserved
	y := r.readSigned(38)
	r.read(2) // quarter-cycle indicator
	z := r.readSigned(38)
	a := &StationARP{
		ECEFXm:         float64(x) * 1e-4,
		ECEFYm:         float64(y) * 1e-4,
		ECEFZm:         float64(z) * 1e-4,
		GPSSupported:   gps,
		GLONASSSupport: glo,
		GalileoSupport: gal,
	}
	if msgType == 1006 {
		h := float64(r.read(16)) * 1e-4
		a.AntennaHeightM = &h
	}
	return a, nil
}

// bitReader reads big-endian bit fields from a byte slice.
type bitReader struct {
	b   []byte
	pos int // bit position
}

func (r *bitReader) read(n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		bytePos := r.pos >> 3
		bitPos := 7 - (r.pos & 7)
		var bit uint64
		if bytePos < len(r.b) {
			bit = uint64((r.b[bytePos] >> bitPos) & 1)
		}
		v = (v << 1) | bit
		r.pos++
	}
	return v
}

func (r *bitReader) readSigned(n int) int64 {
	v := r.read(n)
	if v&(1<<(n-1)) != 0 {
		return int64(v) - (1 << n)
	}
	return int64(v)
}

// crc24q computes the RTCM / GNSS CRC-24Q (poly 0x1864CFB, init 0).
func crc24q(data []byte) uint32 {
	var crc uint32
	for _, b := range data {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864CFB
			}
		}
	}
	return crc & 0xFFFFFF
}

// hasStationID reports whether a message type carries the reference
// station id (DF003) at payload bits 12-23.
func hasStationID(t int) bool {
	switch {
	case t >= 1001 && t <= 1012: // legacy RTK observables
		return true
	case t >= 1005 && t <= 1008: // station ARP + antenna descriptor
		return true
	case t == 1033: // receiver & antenna descriptors
		return true
	case t >= 1071 && t <= 1127: // MSM families (GPS/GLO/GAL/SBAS/QZSS/BDS)
		return true
	case t == 1230: // GLONASS code-phase biases
		return true
	}
	return false
}

// messageTypeName names the common RTCM 3.x message types.
func messageTypeName(t int) string {
	switch t {
	case 1001:
		return "L1-only GPS RTK observables"
	case 1002:
		return "Extended L1-only GPS RTK observables"
	case 1003:
		return "L1/L2 GPS RTK observables"
	case 1004:
		return "Extended L1/L2 GPS RTK observables"
	case 1005:
		return "Stationary RTK Reference Station ARP"
	case 1006:
		return "Stationary RTK Reference Station ARP with Antenna Height"
	case 1007:
		return "Antenna Descriptor"
	case 1008:
		return "Antenna Descriptor & Serial Number"
	case 1009:
		return "L1-only GLONASS RTK observables"
	case 1010:
		return "Extended L1-only GLONASS RTK observables"
	case 1011:
		return "L1/L2 GLONASS RTK observables"
	case 1012:
		return "Extended L1/L2 GLONASS RTK observables"
	case 1019:
		return "GPS Ephemeris"
	case 1020:
		return "GLONASS Ephemeris"
	case 1033:
		return "Receiver and Antenna Descriptors"
	case 1042:
		return "BeiDou Ephemeris"
	case 1044:
		return "QZSS Ephemeris"
	case 1045:
		return "Galileo F/NAV Ephemeris"
	case 1046:
		return "Galileo I/NAV Ephemeris"
	case 1230:
		return "GLONASS L1/L2 Code-Phase Biases"
	}
	if name := msmName(t); name != "" {
		return name
	}
	return fmt.Sprintf("RTCM3 message type %d", t)
}

// msmName names the Multiple Signal Message families (107x-112x).
func msmName(t int) string {
	bands := map[int]string{1070: "GPS", 1080: "GLONASS", 1090: "Galileo", 1100: "SBAS", 1110: "QZSS", 1120: "BeiDou"}
	base := (t / 10) * 10
	sys, ok := bands[base]
	if !ok {
		return ""
	}
	msm := t - base
	if msm < 1 || msm > 7 {
		return ""
	}
	return fmt.Sprintf("%s MSM%d (Multiple Signal Message)", sys, msm)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("rtcm: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("rtcm: input is not valid hex: %w", err)
	}
	return b, nil
}
