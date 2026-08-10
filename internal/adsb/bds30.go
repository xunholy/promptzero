// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import "fmt"

// BDS 3,0 — ACAS Active Resolution Advisory. Per ICAO Annex 10 Vol IV
// §4.3.8.4.2.4, this Comm-B register carries the live TCAS/ACAS II
// Resolution Advisory state: the ARA bits (which manoeuvre the RA is
// commanding — climb/descend, corrective vs preventive, sense reversal,
// etc.), the RAC bits (which manoeuvres are prohibited because another
// aircraft has claimed them), whether the RA has terminated, and the
// identity of the threat aircraft. A genuinely safety-relevant surveillance
// artifact: it says an aircraft was in a collision-avoidance manoeuvre.
//
// Unlike the meteorological registers, BDS 3,0 is self-identifying (its
// first byte is a fixed 0x30), but it is decoded on explicit request via
// DecodeBDS30 / the adsb_bds30_decode tool for consistency with the other
// explicit Comm-B registers and to keep decodeCommB's inference untouched.
// It also appears in DF16 (long ACAS) and is embedded in ADS-B BDS 6,1
// subtype-2 broadcasts.
//
// Field layout and semantics are ported from pyModeS v3
// (decoder/bds/bds30.py); the TTI=2 threat altitude reuses this package's
// AC13 decoder (altitude13). Bit numbers in comments are 0-indexed from the
// MB MSB, matching pyModeS.

// ResolutionAdvisory is the ARA field: which manoeuvre the RA commands.
type ResolutionAdvisory struct {
	Issued           bool `json:"issued"`            // ARA[0]: an RA is active
	Corrective       bool `json:"corrective"`        // ARA[1]: corrective (vs preventive)
	DownwardSense    bool `json:"downward_sense"`    // ARA[2]: downward sense
	IncreasedRate    bool `json:"increased_rate"`    // ARA[3]: increased rate
	SenseReversal    bool `json:"sense_reversal"`    // ARA[4]: sense reversal
	AltitudeCrossing bool `json:"altitude_crossing"` // ARA[5]: altitude crossing
	Positive         bool `json:"positive"`          // ARA[6]: positive
}

// ResolutionAdvisoryComplement is the RAC field: manoeuvres prohibited
// because another aircraft is resolving into them.
type ResolutionAdvisoryComplement struct {
	NoBelow bool `json:"no_below"`
	NoAbove bool `json:"no_above"`
	NoLeft  bool `json:"no_left"`
	NoRight bool `json:"no_right"`
}

// BDS30 is the decoded ACAS Active Resolution Advisory report.
type BDS30 struct {
	ResolutionAdvisory           ResolutionAdvisory           `json:"resolution_advisory"`
	ResolutionAdvisoryComplement ResolutionAdvisoryComplement `json:"resolution_advisory_complement"`
	RATerminated                 bool                         `json:"ra_terminated"`
	MultipleThreat               bool                         `json:"multiple_threat"`
	// ThreatTypeIndicator: 0=no identity, 1=ICAO address, 2=altitude+range+bearing.
	ThreatTypeIndicator int    `json:"threat_type_indicator"`
	ThreatTypeName      string `json:"threat_type_name"`
	// Threat identity — set according to ThreatTypeIndicator.
	ThreatICAO       string   `json:"threat_icao,omitempty"`        // TTI=1
	ThreatAltitudeFt *int     `json:"threat_altitude_ft,omitempty"` // TTI=2
	ThreatRangeNM    *float64 `json:"threat_range_nm,omitempty"`    // TTI=2
	ThreatBearingDeg *int     `json:"threat_bearing_deg,omitempty"` // TTI=2
	// IsBDS30 is pyModeS's is_bds30 heuristic: the fixed 0x30 identifier,
	// the ACAS-III-reserved ARA bits below 48, and a non-reserved threat
	// type. False means the field is unlikely to be a genuine BDS 3,0.
	IsBDS30 bool `json:"is_bds30"`
}

var threatTypeNames = [...]string{"none", "ICAO address", "altitude/range/bearing", "reserved"} //nolint:gochecknoglobals

// DecodeBDS30 decodes a 7-byte (56-bit) Comm-B MB field as BDS 3,0. It
// always returns a decode (the caller has asserted the register); consult
// IsBDS30 for whether the field passes the ACAS-RA plausibility checks.
func DecodeBDS30(mb []byte) *BDS30 {
	if len(mb) < 7 {
		return nil
	}
	bit := func(k int) bool { return extractBits(mb, k, 1) == 1 }
	b := &BDS30{
		ResolutionAdvisory: ResolutionAdvisory{
			Issued:           bit(8),
			Corrective:       bit(9),
			DownwardSense:    bit(10),
			IncreasedRate:    bit(11),
			SenseReversal:    bit(12),
			AltitudeCrossing: bit(13),
			Positive:         bit(14),
		},
		ResolutionAdvisoryComplement: ResolutionAdvisoryComplement{
			NoBelow: bit(22),
			NoAbove: bit(23),
			NoLeft:  bit(24),
			NoRight: bit(25),
		},
		RATerminated:        bit(26),
		MultipleThreat:      bit(27),
		ThreatTypeIndicator: extractBits(mb, 28, 2),
	}
	b.ThreatTypeName = threatTypeNames[b.ThreatTypeIndicator]

	switch b.ThreatTypeIndicator {
	case 1:
		// 24-bit ICAO address at bits 30-53.
		b.ThreatICAO = fmt.Sprintf("%06X", extractBits(mb, 30, 24))
	case 2:
		// Altitude: 13-bit AC13 at bits 30-42.
		ac13 := extractBits(mb, 30, 13)
		if alt, _, _ := altitude13(bitsOf13(ac13)); alt != nil {
			b.ThreatAltitudeFt = alt
		}
		// Range: 7-bit at bits 43-49; NM = (n-1)/10, n=0 means not available.
		if n := extractBits(mb, 43, 7); n > 0 {
			r := float64(n-1) / 10.0
			b.ThreatRangeNM = &r
		}
		// Bearing: 6-bit at bits 50-55; deg = 6*(n-1)+3, n=0 means not available.
		if n := extractBits(mb, 50, 6); n > 0 {
			deg := 6*(n-1) + 3
			b.ThreatBearingDeg = &deg
		}
	}

	b.IsBDS30 = is30(mb)
	return b
}

// bitsOf13 expands a 13-bit AC13 value to the MSB-first []int altitude13
// expects.
func bitsOf13(v int) []int {
	d := make([]int, 13)
	for i := 0; i < 13; i++ {
		d[i] = (v >> (12 - i)) & 1
	}
	return d
}

// is30 mirrors pyModeS v3 is_bds30.
func is30(mb []byte) bool {
	if commbAllZero(mb) {
		return false
	}
	// The first byte is a fixed BDS 3,0 identifier.
	if extractBits(mb, 0, 8) != 0x30 {
		return false
	}
	// The 7 ARA bits reserved for ACAS III (bits 15-21) must be < 48.
	if extractBits(mb, 15, 7) >= 48 {
		return false
	}
	// Threat type 3 is reserved.
	if extractBits(mb, 28, 2) == 3 {
		return false
	}
	return true
}
