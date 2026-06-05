// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

// Mode S surveillance altitude (AC13) and identity/squawk (ID13)
// header decoding — the 13-bit field at message bits 20-32 carried by
// the surveillance downlink formats:
//
//   - DF0  (short air-air surveillance)        -> AC13 altitude
//   - DF4  (surveillance altitude reply)       -> AC13 altitude
//   - DF16 (long air-air surveillance)         -> AC13 altitude
//   - DF20 (Comm-B altitude reply)             -> AC13 altitude
//   - DF5  (surveillance identity reply)       -> ID13 squawk
//   - DF21 (Comm-B identity reply)             -> ID13 squawk
//
// AC13 (ICAO Annex 10 / Doc 9871) carries pressure altitude in one of
// three encodings selected by the M (metric) and Q (resolution) bits:
// M=0,Q=1 -> 25-ft increments; M=0,Q=0 -> Gillham (Mode C) gray-coded
// 100-ft increments; M=1 -> metric. ID13 carries the 4-digit octal
// Mode-A squawk, with 7500 / 7600 / 7700 flagged as the special
// emergency codes (hijack / radio-failure / general-emergency).
//
// The logic reproduces the pyModeS reference (altitude / gray2alt /
// gray2int / squawk) byte-for-byte; see altid_test.go for the
// oracle-anchored vectors.

// AltID is the decoded AC13 altitude or ID13 squawk header of a
// surveillance frame.
type AltID struct {
	AltitudeFt       *int   `json:"altitude_ft,omitempty"`
	AltitudeEncoding string `json:"altitude_encoding,omitempty"` // 25ft / Gillham 100ft / metric
	AltitudeNote     string `json:"altitude_note,omitempty"`
	Squawk           string `json:"squawk,omitempty"`
	SquawkEmergency  string `json:"squawk_emergency,omitempty"`
}

// decodeAltitudeFrame decodes the AC13 altitude field (frame bits 20-32)
// for DF0/4/16/20. b is the full frame.
func decodeAltitudeFrame(b []byte) *AltID {
	bits := bitsAt(b, 19, 13)
	a := &AltID{}
	alt, enc, note := altitude13(bits)
	a.AltitudeFt = alt
	a.AltitudeEncoding = enc
	a.AltitudeNote = note
	return a
}

// decodeIdentityFrame decodes the ID13 squawk field (frame bits 20-32)
// for DF5/21. b is the full frame.
func decodeIdentityFrame(b []byte) *AltID {
	bits := bitsAt(b, 19, 13)
	sq := squawk13(bits)
	a := &AltID{Squawk: sq, SquawkEmergency: emergencyCode(sq)}
	return a
}

// bitsAt returns n bits starting at 0-indexed bit offset start of b, as a
// slice of 0/1 ints (MSB first) — mirroring pyModeS's binary-string slices.
func bitsAt(b []byte, start, n int) []int {
	out := make([]int, n)
	for i := 0; i < n; i++ {
		pos := start + i
		out[i] = int(b[pos>>3]>>(7-(pos&7))) & 1
	}
	return out
}

func bitsToInt(bits []int) int {
	v := 0
	for _, x := range bits {
		v = v<<1 | x
	}
	return v
}

// altitude13 decodes a 13-bit AC altitude field (pyModeS common.altitude).
// Returns altitude in feet (nil if unknown/all-zero), the encoding label,
// and an optional note.
func altitude13(d []int) (*int, string, string) {
	if bitsToInt(d) == 0 {
		return nil, "", "altitude unknown or invalid (all-zero AC field)"
	}
	mbit := d[6]
	qbit := d[8]

	if mbit == 0 && qbit == 1 { // 25-ft increments
		vbin := []int{d[0], d[1], d[2], d[3], d[4], d[5], d[7], d[9], d[10], d[11], d[12]}
		alt := bitsToInt(vbin)*25 - 1000
		return &alt, "25ft", ""
	}
	if mbit == 0 && qbit == 0 { // Gillham (Mode C) gray code, 100-ft
		c1, a1, c2, a2, c4, a4 := d[0], d[1], d[2], d[3], d[4], d[5]
		b1, b2, d2, b4, d4 := d[7], d[9], d[10], d[11], d[12]
		gray := []int{d2, d4, a1, a2, a4, b1, b2, b4, c1, c2, c4}
		alt := gray2alt(gray)
		if alt == nil {
			return nil, "Gillham 100ft", "Gillham (Mode C) altitude not representable"
		}
		return alt, "Gillham 100ft", ""
	}
	// mbit == 1: metric
	vbin := append([]int{d[0], d[1], d[2], d[3], d[4], d[5]}, d[7:]...)
	alt := int(float64(bitsToInt(vbin)) * 3.28084)
	return &alt, "metric", "metric altitude (M-bit set), converted to feet"
}

// gray2alt decodes an 11-bit Gillham (Mode C) gray-coded altitude
// (pyModeS common.gray2alt). Returns nil for the unrepresentable codes.
func gray2alt(g []int) *int {
	n500 := gray2int(g[:8])
	n100 := gray2int(g[8:])
	if n100 == 0 || n100 == 5 || n100 == 6 {
		return nil
	}
	if n100 == 7 {
		n100 = 5
	}
	if n500%2 == 1 {
		n100 = 6 - n100
	}
	alt := (n500*500 + n100*100) - 1300
	return &alt
}

// gray2int converts a gray-coded bit slice to its integer value
// (pyModeS common.gray2int).
func gray2int(bits []int) int {
	num := bitsToInt(bits)
	num ^= num >> 8
	num ^= num >> 4
	num ^= num >> 2
	num ^= num >> 1
	return num
}

// squawk13 decodes a 13-bit ID field into the 4-digit octal Mode-A
// squawk (pyModeS common.squawk).
func squawk13(d []int) string {
	c1, a1, c2, a2, c4, a4 := d[0], d[1], d[2], d[3], d[4], d[5]
	b1, d1, b2, d2, b4, d4 := d[7], d[8], d[9], d[10], d[11], d[12]
	o1 := a4<<2 | a2<<1 | a1
	o2 := b4<<2 | b2<<1 | b1
	o3 := c4<<2 | c2<<1 | c1
	o4 := d4<<2 | d2<<1 | d1
	return string([]byte{'0' + byte(o1), '0' + byte(o2), '0' + byte(o3), '0' + byte(o4)})
}

// emergencyCode labels the three reserved emergency squawks.
func emergencyCode(squawk string) string {
	switch squawk {
	case "7500":
		return "7500 — unlawful interference (hijack)"
	case "7600":
		return "7600 — radio failure (lost communications)"
	case "7700":
		return "7700 — general emergency"
	}
	return ""
}
