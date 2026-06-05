// SPDX-License-Identifier: AGPL-3.0-or-later

// Package eas decodes EAS / SAME (Specific Area Message Encoding)
// headers — the AFSK digital header that prefixes every Emergency Alert
// System and NOAA Weather Radio alert (the ZCZC… burst at 520.83 baud on
// 162 MHz / broadcast EAS). Demodulators such as multimon-ng / rtl_fm
// recover the raw header string; this package interprets its fields —
// who issued the alert, what kind, for which areas, and when — which is
// the useful part for RF monitoring / broadcast forensics.
//
// # Wrap-vs-native judgement
//
//	Native. A SAME header is a fixed, fully-public ASCII structure
//	(NWS NWSI 10-1712 / FCC 47 CFR 11.31):
//	ZCZC-ORG-EEE-PSSCCC-PSSCCC…+TTTT-JJJHHMM-LLLLLLLL- . Decoding it
//	is deterministic string parsing plus three documented lookup
//	tables (originator codes, event codes, state FIPS codes). No DSP
//	(the demodulation to the ZCZC string is upstream), no crypto, no
//	new dependency — the field interpretation that multimon-ng leaves
//	to the operator is implemented here directly.
//
// # What this covers
//
//   - Originator (ORG): PEP / CIV / WXR / EAS / EAN with meanings.
//   - Event (EEE): the FCC/NWS event-code table (tests, weather
//     warnings / watches / statements, civil/non-weather events), with
//     the standard suffix fallback for unrecognised codes (…W = Warning,
//     …A = Watch, …E = Emergency, …S = Statement, …T = Test).
//   - Location codes (PSSCCC): the part-of-county digit, the state FIPS
//     code (→ state/territory name) and the county FIPS code.
//   - Purge / valid time (TTTT, hhmm duration) and the issue time
//     (JJJHHMM: ordinal day-of-year + UTC hh:mm).
//   - The 8-character originator callsign.
//
// # Deliberately deferred
//
//	County FIPS → county-name resolution (a ~3200-entry table) is not
//	included — the state name and the raw 5-digit FIPS are surfaced.
//	The calendar date is not derived from the ordinal day because the
//	SAME header carries no year. The message audio / EOM (NNNN) framing
//	is upstream of the header string.
package eas

import (
	"fmt"
	"strconv"
	"strings"
)

// Result is the decoded SAME header.
type Result struct {
	Originator     string     `json:"originator"`
	OriginatorName string     `json:"originator_name"`
	Event          string     `json:"event"`
	EventName      string     `json:"event_name"`
	Locations      []Location `json:"locations"`
	ValidMinutes   int        `json:"valid_minutes"`
	ValidDuration  string     `json:"valid_duration"`
	IssueDayOfYear int        `json:"issue_day_of_year"`
	IssueTimeUTC   string     `json:"issue_time_utc"`
	Callsign       string     `json:"callsign"`
	Notes          []string   `json:"notes,omitempty"`
}

// Location is one decoded PSSCCC location code.
type Location struct {
	Raw        string `json:"raw"`
	PartCode   int    `json:"part_code"`
	PartName   string `json:"part_name"`
	StateFIPS  int    `json:"state_fips"`
	StateName  string `json:"state_name"`
	CountyFIPS int    `json:"county_fips"`
}

// Decode parses a SAME header string (the ZCZC… line a demodulator
// emits). Leading preamble / surrounding text is tolerated — parsing
// starts at the "ZCZC" marker.
func Decode(s string) (*Result, error) {
	s = strings.TrimSpace(s)
	i := strings.Index(s, "ZCZC")
	if i < 0 {
		return nil, fmt.Errorf("no ZCZC start-of-header marker found")
	}
	s = s[i:]
	// Trim anything after the trailing dash of the callsign field if a
	// message body / EOM follows.
	plus := strings.IndexByte(s, '+')
	if plus < 0 {
		return nil, fmt.Errorf("malformed header: no '+' separating locations from the time fields")
	}

	head := s[:plus]   // ZCZC-ORG-EEE-LOC1-...-LOCn
	tail := s[plus+1:] // TTTT-JJJHHMM-LLLLLLLL-...
	hp := strings.Split(head, "-")
	if len(hp) < 4 || hp[0] != "ZCZC" {
		return nil, fmt.Errorf("malformed header: expected ZCZC-ORG-EEE-location… before '+'")
	}
	r := &Result{
		Originator:     hp[1],
		OriginatorName: originatorName(hp[1]),
		Event:          hp[2],
		EventName:      eventName(hp[2]),
	}
	for _, loc := range hp[3:] {
		r.Locations = append(r.Locations, decodeLocation(loc))
	}

	tp := strings.Split(tail, "-")
	if len(tp) < 3 {
		return nil, fmt.Errorf("malformed header: expected TTTT-JJJHHMM-callsign after '+'")
	}
	// TTTT = hhmm valid/purge duration.
	if t := tp[0]; len(t) == 4 {
		hh, e1 := strconv.Atoi(t[:2])
		mm, e2 := strconv.Atoi(t[2:])
		if e1 == nil && e2 == nil {
			r.ValidMinutes = hh*60 + mm
			r.ValidDuration = fmt.Sprintf("%dh%02dm", hh, mm)
		} else {
			r.Notes = append(r.Notes, "unparseable valid-time field "+t)
		}
	} else {
		r.Notes = append(r.Notes, "valid-time field is not 4 digits: "+tp[0])
	}
	// JJJHHMM = ordinal day + UTC time.
	if j := tp[1]; len(j) == 7 {
		day, e1 := strconv.Atoi(j[:3])
		hh, e2 := strconv.Atoi(j[3:5])
		mm, e3 := strconv.Atoi(j[5:])
		if e1 == nil && e2 == nil && e3 == nil {
			r.IssueDayOfYear = day
			r.IssueTimeUTC = fmt.Sprintf("%02d:%02d", hh, mm)
		} else {
			r.Notes = append(r.Notes, "unparseable issue-time field "+j)
		}
	} else {
		r.Notes = append(r.Notes, "issue-time field is not 7 digits: "+tp[1])
	}
	r.Callsign = strings.TrimRight(tp[2], "-")
	return r, nil
}

func decodeLocation(raw string) Location {
	l := Location{Raw: raw}
	if len(raw) != 6 {
		return l
	}
	p, e0 := strconv.Atoi(raw[:1])
	st, e1 := strconv.Atoi(raw[1:3])
	co, e2 := strconv.Atoi(raw[3:])
	if e0 != nil || e1 != nil || e2 != nil {
		return l
	}
	l.PartCode = p
	l.PartName = partName(p)
	l.StateFIPS = st
	l.StateName = stateName(st)
	l.CountyFIPS = co
	return l
}

func partName(p int) string {
	if p == 0 {
		return "entire area"
	}
	return fmt.Sprintf("portion %d of the area", p)
}
