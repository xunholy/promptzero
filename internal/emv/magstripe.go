// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"fmt"
	"strings"
)

// Magstripe is the parsed contents of a raw magnetic-stripe swipe — the ASCII
// track data a card reader / MSR / skimmer emits, as opposed to the EMV chip's
// tag-57 BCD Track-2-Equivalent (see DecodeTrack2). It carries Track 1 and/or
// Track 2 as present in the input.
type Magstripe struct {
	Track1 *Track1  `json:"track1,omitempty"`
	Track2 *Track2  `json:"track2,omitempty"`
	Notes  []string `json:"notes,omitempty"`
}

// Track1 is the decoded ISO 7813 Track 1 (IATA) format — the only track that
// carries the cardholder name and a format code.
type Track1 struct {
	FormatCode         string   `json:"format_code"` // 'B' = financial/bank
	PAN                string   `json:"pan"`
	PANMasked          string   `json:"pan_masked"`
	Name               string   `json:"name,omitempty"`
	Surname            string   `json:"surname,omitempty"`
	GivenName          string   `json:"given_name,omitempty"`
	Expiry             string   `json:"expiry,omitempty"`       // raw YYMM
	ExpiryFormatted    string   `json:"expiry_mm_yy,omitempty"` // MM/YY
	ServiceCode        string   `json:"service_code,omitempty"`
	ServiceCodeMeaning string   `json:"service_code_meaning,omitempty"`
	Discretionary      string   `json:"discretionary_data,omitempty"`
	LuhnValid          bool     `json:"luhn_valid"`
	LRC                string   `json:"lrc,omitempty"` // trailing redundancy char, surfaced raw (not validated)
	Notes              []string `json:"notes,omitempty"`
}

// DecodeMagstripe parses a raw swipe string containing Track 1 (starting '%',
// ending '?') and/or Track 2 (starting ';', ending '?'), in any order. The
// trailing LRC character (after '?') is surfaced raw but not validated — its
// check is on the bit-level 5/7-bit encoding, a layer below the ASCII string a
// reader emits, and a wrong verdict is worse than none.
func DecodeMagstripe(s string) (*Magstripe, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("emv: empty magstripe input")
	}
	out := &Magstripe{}
	if i := strings.IndexByte(s, '%'); i >= 0 {
		if t1, err := decodeTrack1(s[i:]); err == nil {
			out.Track1 = t1
		} else {
			out.Notes = append(out.Notes, "track 1: "+err.Error())
		}
	}
	if i := strings.IndexByte(s, ';'); i >= 0 {
		if t2, err := decodeTrack2ASCII(s[i:]); err == nil {
			out.Track2 = t2
		} else {
			out.Notes = append(out.Notes, "track 2: "+err.Error())
		}
	}
	if out.Track1 == nil && out.Track2 == nil {
		return nil, fmt.Errorf("emv: no track found (Track 1 starts with '%%', Track 2 with ';')")
	}
	return out, nil
}

// fmtExpiry renders a 4-digit YYMM expiry as MM/YY.
func fmtExpiry(yymm string) string {
	if len(yymm) == 4 && allDigits(yymm) {
		return yymm[2:4] + "/" + yymm[0:2]
	}
	return ""
}

// decodeTrack1 parses an ISO 7813 Track 1 field: %FPAN^NAME^YYMMSSS...?LRC
func decodeTrack1(s string) (*Track1, error) {
	if len(s) < 2 || s[0] != '%' {
		return nil, fmt.Errorf("missing '%%' start sentinel")
	}
	body := s[1:]
	end := strings.IndexByte(body, '?')
	var lrc string
	if end >= 0 {
		if end+1 < len(body) {
			lrc = body[end+1 : end+2]
		}
		body = body[:end]
	} else {
		return nil, fmt.Errorf("missing '?' end sentinel")
	}
	if body == "" {
		return nil, fmt.Errorf("empty track")
	}
	t := &Track1{FormatCode: string(body[0]), LRC: lrc}
	fields := strings.SplitN(body[1:], "^", 3)
	if len(fields) < 3 {
		return nil, fmt.Errorf("malformed (need PAN^NAME^DATA separated by '^')")
	}
	t.PAN = fields[0]
	t.PANMasked = maskPAN(t.PAN)
	t.LuhnValid = luhnValid(t.PAN)
	if name := strings.TrimSpace(fields[1]); name != "" {
		t.Name = name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			t.Surname = strings.TrimSpace(name[:i])
			t.GivenName = strings.TrimSpace(name[i+1:])
		}
	}
	// Additional data: YYMM (4) + service code (3) + discretionary, for the
	// financial format code 'B'. Other format codes use a different layout, so
	// the remainder is surfaced raw without forcing the field split.
	data := fields[2]
	if t.FormatCode == "B" && len(data) >= 7 && allDigits(data[:7]) {
		t.Expiry = data[:4]
		t.ExpiryFormatted = fmtExpiry(t.Expiry)
		t.ServiceCode = data[4:7]
		t.ServiceCodeMeaning = serviceCodeMeaning(t.ServiceCode)
		t.Discretionary = data[7:]
	} else {
		t.Discretionary = data
		if t.FormatCode != "B" {
			t.Notes = append(t.Notes, "non-'B' format code: expiry/service-code layout not assumed; additional data surfaced raw")
		}
	}
	if !allDigits(t.PAN) {
		t.Notes = append(t.Notes, "PAN contains non-digit characters")
	}
	return t, nil
}

// decodeTrack2ASCII parses an ISO 7813 Track 2 ASCII swipe: ;PAN=YYMMSSS...?LRC
func decodeTrack2ASCII(s string) (*Track2, error) {
	if len(s) < 2 || s[0] != ';' {
		return nil, fmt.Errorf("missing ';' start sentinel")
	}
	body := s[1:]
	end := strings.IndexByte(body, '?')
	var lrc string
	if end >= 0 {
		if end+1 < len(body) {
			lrc = body[end+1 : end+2]
		}
		body = body[:end]
	} else {
		return nil, fmt.Errorf("missing '?' end sentinel")
	}
	eq := strings.IndexByte(body, '=')
	if eq < 0 {
		return nil, fmt.Errorf("missing '=' field separator")
	}
	t := &Track2{PAN: body[:eq]}
	t.PANMasked = maskPAN(t.PAN)
	t.LuhnValid = luhnValid(t.PAN)
	data := body[eq+1:]
	if len(data) >= 7 && allDigits(data[:7]) {
		t.Expiry = data[:4]
		t.ExpiryFormatted = fmtExpiry(t.Expiry)
		t.ServiceCode = data[4:7]
		t.ServiceCodeMeaning = serviceCodeMeaning(t.ServiceCode)
		t.Discretionary = data[7:]
	} else {
		t.Discretionary = data
		t.Notes = append(t.Notes, "expiry/service-code not present or non-numeric; data surfaced raw")
	}
	if lrc != "" {
		t.Notes = append(t.Notes, "LRC char present (not validated): "+lrc)
	}
	if !allDigits(t.PAN) {
		t.Notes = append(t.Notes, "PAN contains non-digit characters")
	}
	return t, nil
}
