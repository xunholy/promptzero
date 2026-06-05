// SPDX-License-Identifier: AGPL-3.0-or-later

package eas

import "testing"

// TestDecodeWorkedExample anchors against the documented SAME example
// (NWS / Wikipedia): an EAS Participant Required Weekly Test for five
// Florida counties, valid 30 minutes, issued ordinal day 278 at 04:15
// UTC by WTSP/TV.
func TestDecodeWorkedExample(t *testing.T) {
	r, err := Decode("ZCZC-EAS-RWT-012057-012081-012101-012103-012115+0030-2780415-WTSP/TV-")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Originator != "EAS" || r.OriginatorName != "EAS Participant (broadcast station or cable system)" {
		t.Errorf("originator = %s / %q", r.Originator, r.OriginatorName)
	}
	if r.Event != "RWT" || r.EventName != "Required Weekly Test" {
		t.Errorf("event = %s / %q", r.Event, r.EventName)
	}
	if len(r.Locations) != 5 {
		t.Fatalf("locations = %d, want 5", len(r.Locations))
	}
	l0 := r.Locations[0]
	if l0.Raw != "012057" || l0.PartCode != 0 || l0.StateFIPS != 12 ||
		l0.StateName != "Florida" || l0.CountyFIPS != 57 {
		t.Errorf("location[0] = %+v", l0)
	}
	if r.ValidMinutes != 30 || r.ValidDuration != "0h30m" {
		t.Errorf("valid = %d / %q, want 30 / 0h30m", r.ValidMinutes, r.ValidDuration)
	}
	if r.IssueDayOfYear != 278 || r.IssueTimeUTC != "04:15" {
		t.Errorf("issue = day %d %q, want 278 04:15", r.IssueDayOfYear, r.IssueTimeUTC)
	}
	if r.Callsign != "WTSP/TV" {
		t.Errorf("callsign = %q, want WTSP/TV", r.Callsign)
	}
}

// TestDecodeWeatherWarning covers a single-county tornado warning and
// the "entire area" part code, plus a multi-hour valid time.
func TestDecodeTornado(t *testing.T) {
	r, err := Decode("ZCZC-WXR-TOR-048201+0100-1011830-KHGX/NWS-")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OriginatorName != "National Weather Service / Environment Canada" {
		t.Errorf("org = %q", r.OriginatorName)
	}
	if r.EventName != "Tornado Warning" {
		t.Errorf("event = %q", r.EventName)
	}
	if r.Locations[0].StateName != "Texas" || r.Locations[0].CountyFIPS != 201 {
		t.Errorf("loc = %+v", r.Locations[0])
	}
	if r.ValidMinutes != 60 {
		t.Errorf("valid = %d, want 60", r.ValidMinutes)
	}
}

// TestUnknownEventSuffix exercises the third-letter fallback.
func TestUnknownEventSuffix(t *testing.T) {
	cases := map[string]string{
		"ZCZC-WXR-XYW-012057+0030-2780415-TEST----": "unrecognised Warning",
		"ZCZC-WXR-XYA-012057+0030-2780415-TEST----": "unrecognised Watch",
		"ZCZC-WXR-XYS-012057+0030-2780415-TEST----": "unrecognised Statement",
	}
	for in, want := range cases {
		r, err := Decode(in)
		if err != nil {
			t.Fatalf("Decode(%s): %v", in, err)
		}
		if r.EventName != want {
			t.Errorf("%s: event = %q, want %q", in, r.EventName, want)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, in := range []string{
		"", "no marker here", "ZCZC-EAS-RWT-012057", // no '+'
		"ZCZC+0030-2780415-X-", // nothing before '+'
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

// TestDecodeWithPreamble confirms surrounding text before ZCZC is tolerated.
func TestDecodeWithPreamble(t *testing.T) {
	r, err := Decode("\xab\xab\xabZCZC-EAS-RMT-012057+0015-2780415-WTSP/TV-NNNN")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Event != "RMT" || r.EventName != "Required Monthly Test" {
		t.Errorf("event = %s / %q", r.Event, r.EventName)
	}
}

// FuzzDecode asserts the parser never panics.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"ZCZC-EAS-RWT-012057-012081+0030-2780415-WTSP/TV-",
		"ZCZC", "ZCZC-+-", "", "ZCZC---+---",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
