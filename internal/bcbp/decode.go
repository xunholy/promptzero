// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bcbp decodes an IATA Bar Coded Boarding Pass (Resolution 792)
// — the text string encoded in the PDF417 / Aztec / QR barcode on a
// boarding pass. Boarding passes are routinely photographed, posted to
// social media and discarded intact; the barcode leaks the passenger
// name, the booking reference (PNR — which on many airline sites is
// enough, with the surname, to open the full reservation), the
// itinerary, seat, check-in sequence and frequent-flyer number. Decoding
// it is a core travel-OSINT / privacy-exposure check (companion to the
// MRZ decoder).
//
// # Wrap-vs-native judgement
//
//	Native. The BCBP format is a fixed, fully-public layout (IATA
//	Resolution 792): a small header, then per flight leg a block of
//	fixed-width mandatory fields terminated by a hex field-size marker
//	that delimits the variable "conditional" (airline-use) section.
//	The structure is self-describing via those length markers, so
//	parsing is substring slicing driven by the declared sizes — no
//	dependency is justified. stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The mandatory fields are fixed-width and were verified against the
//	canonical IATA Resolution 792 example boarding pass. Because every
//	leg's conditional section is length-prefixed, the leg boundaries
//	are found from the declared sizes rather than guessed, so a
//	multi-leg pass cannot be mis-sliced. The variable / conditional
//	(airline-use) section is surfaced as a RAW string rather than
//	decoded field-by-field — its sub-field layout is version-dependent
//	and airline-extensible, so guessing it would risk confidently-wrong
//	output; the high-value mandatory fields (name, PNR, route, flight,
//	seat) are the ones bodied out. The flight date is a day-of-year
//	(Julian) number with NO year, so it is surfaced as the raw day
//	count (1-366) and not resolved to a calendar date.
package bcbp

import (
	"fmt"
	"strconv"
	"strings"
)

// BoardingPass is the decoded view of a BCBP string.
type BoardingPass struct {
	FormatCode    string   `json:"format_code"` // M (multi/standard) or S
	NumberOfLegs  int      `json:"number_of_legs"`
	PassengerName string   `json:"passenger_name"`
	ETicket       bool     `json:"electronic_ticket"`
	Legs          []Leg    `json:"legs"`
	Notes         []string `json:"notes,omitempty"`
}

// Leg is one flight segment's mandatory fields.
type Leg struct {
	PNR              string `json:"pnr"` // operating-carrier booking reference
	From             string `json:"from"`
	To               string `json:"to"`
	OperatingCarrier string `json:"operating_carrier"`
	FlightNumber     string `json:"flight_number"`
	FlightDayOfYear  int    `json:"flight_day_of_year"` // Julian day 1-366 (no year encoded)
	Compartment      string `json:"compartment_class"`
	SeatNumber       string `json:"seat_number"`
	CheckInSequence  string `json:"checkin_sequence"`
	PassengerStatus  string `json:"passenger_status"`
	ConditionalRaw   string `json:"conditional_raw,omitempty"` // airline-use variable section, surfaced raw
}

// Decode parses a BCBP barcode string.
func Decode(input string) (*BoardingPass, error) {
	s := strings.TrimRight(input, "\r\n")
	if len(s) < 23 {
		return nil, fmt.Errorf("bcbp: input too short (%d chars) for a BCBP header", len(s))
	}
	bp := &BoardingPass{FormatCode: s[0:1]}
	if bp.FormatCode != "M" && bp.FormatCode != "S" {
		return nil, fmt.Errorf("bcbp: format code %q is not M or S — not a Bar Coded Boarding Pass", bp.FormatCode)
	}
	legs, err := strconv.Atoi(s[1:2])
	if err != nil || legs < 1 || legs > 9 {
		return nil, fmt.Errorf("bcbp: invalid number-of-legs digit %q", s[1:2])
	}
	bp.NumberOfLegs = legs
	bp.PassengerName = strings.TrimSpace(s[2:22])
	bp.ETicket = s[22:23] == "E"

	pos := 23
	for i := 0; i < legs; i++ {
		// Each leg's mandatory block is 37 chars: PNR(7) from(3) to(3)
		// carrier(3) flight(5) date(3) compartment(1) seat(4) sequence(5)
		// status(1) + a 2-hex conditional-field-size that delimits the
		// variable (airline-use) section that follows.
		if pos+37 > len(s) {
			return nil, fmt.Errorf("bcbp: truncated leg %d (need 37 mandatory chars at offset %d, have %d)", i+1, pos, len(s)-pos)
		}
		m := s[pos : pos+37]
		leg := Leg{
			PNR:              strings.TrimSpace(m[0:7]),
			From:             strings.TrimSpace(m[7:10]),
			To:               strings.TrimSpace(m[10:13]),
			OperatingCarrier: strings.TrimSpace(m[13:16]),
			FlightNumber:     strings.TrimSpace(m[16:21]),
			Compartment:      strings.TrimSpace(m[24:25]),
			SeatNumber:       strings.TrimSpace(m[25:29]),
			CheckInSequence:  strings.TrimSpace(m[29:34]),
			PassengerStatus:  strings.TrimSpace(m[34:35]),
		}
		if day, derr := strconv.Atoi(strings.TrimSpace(m[21:24])); derr == nil {
			leg.FlightDayOfYear = day
		}
		condSize := 0
		if n, herr := strconv.ParseInt(strings.TrimSpace(m[35:37]), 16, 32); herr == nil {
			condSize = int(n)
		}
		condStart := pos + 37
		condEnd := condStart + condSize
		if condEnd > len(s) {
			condEnd = len(s)
		}
		if condEnd > condStart {
			leg.ConditionalRaw = s[condStart:condEnd]
		}
		bp.Legs = append(bp.Legs, leg)
		pos = condEnd
	}
	bp.Notes = append(bp.Notes,
		"the flight date is a day-of-year (1-366) with no year encoded, so it is not resolved to a calendar date",
		"the conditional (airline-use) section is surfaced raw — its sub-field layout is version-dependent and airline-extensible, so it is not decoded field-by-field (no confidently-wrong guess)")
	return bp, nil
}
