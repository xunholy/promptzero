package workflows

import (
	"strings"
	"testing"
)

// Tests for the pure helpers feeding PhysPentestBadgeWalk: csvField,
// recordIfNew, parseRFIDBadge, parseIButtonBadge. All were at 0%
// statement coverage. The pipeline records every detected badge into
// a CSV-formatted line — quiet drift in any of these would either
// silently skip new badges or produce a corrupt CSV that downstream
// tools (mfkey32 sweeps, hashcat prep) couldn't ingest.

func TestCsvField(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{"", ""},
		{"has space", "has space"},              // spaces don't trigger quoting
		{"with,comma", `"with,comma"`},          // comma → quote
		{`has"quote`, `"has""quote"`},           // quote → quote + escape
		{"new\nline", "\"new\nline\""},          // newline → quote
		{`evil","RX",,,`, `"evil"",""RX"",,,"`}, // mixed escapes — every " doubled, whole field wrapped
	}
	for _, c := range cases {
		if got := csvField(c.in); got != c.want {
			t.Errorf("csvField(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestRecordIfNew_AddsFirstSighting(t *testing.T) {
	seen := map[string]badgeRecord{}
	var csv strings.Builder
	rec := badgeRecord{
		radio:      "rfid",
		protocol:   "EM4100",
		identifier: "1A2B3C4D5E",
		raw:        "EM4100 data: 1A2B3C4D5E",
	}
	recordIfNew(seen, rec, &csv)

	if len(seen) != 1 {
		t.Fatalf("seen len = %d; want 1", len(seen))
	}
	out := csv.String()
	if !strings.Contains(out, "rfid,EM4100,1A2B3C4D5E") {
		t.Errorf("csv missing fields: %q", out)
	}
	if !strings.Contains(out, "EM4100 data: 1A2B3C4D5E") {
		t.Errorf("csv missing raw field: %q", out)
	}
}

func TestRecordIfNew_DedupesSameRadioAndID(t *testing.T) {
	seen := map[string]badgeRecord{}
	var csv strings.Builder
	rec := badgeRecord{radio: "rfid", identifier: "AABBCC"}

	recordIfNew(seen, rec, &csv)
	first := csv.String()
	recordIfNew(seen, rec, &csv)
	if csv.String() != first {
		t.Errorf("duplicate record appended to CSV; before=%q after=%q", first, csv.String())
	}
	if len(seen) != 1 {
		t.Errorf("seen grew on duplicate: %d", len(seen))
	}
}

func TestRecordIfNew_DifferentRadiosNotDeduped(t *testing.T) {
	seen := map[string]badgeRecord{}
	var csv strings.Builder
	// Same identifier on different radios must be kept separate —
	// an EM4100 RFID card and a Dallas iButton can theoretically
	// produce the same hex by chance.
	recordIfNew(seen, badgeRecord{radio: "rfid", identifier: "01020304"}, &csv)
	recordIfNew(seen, badgeRecord{radio: "ibutton", identifier: "01020304"}, &csv)
	if len(seen) != 2 {
		t.Errorf("expected 2 entries for same id different radios; got %d", len(seen))
	}
}

func TestParseRFIDBadge_HappyPath(t *testing.T) {
	// rfidProtocolPattern is anchored with ^ — the protocol token has
	// to start the line. The Flipper firmware emits one line per
	// protocol-attempt with the protocol name as the leading token,
	// e.g. "EM4100  data: 1234567890" (mirrors the form pinned in
	// commands_internal_test.go).
	out := "EM4100\n" +
		"Card ID: 1A 2B 3C 4D 5E\n"
	got := parseRFIDBadge(out)
	if got.radio != "rfid" {
		t.Errorf("radio = %q; want rfid", got.radio)
	}
	if got.protocol != "EM4100" {
		t.Errorf("protocol = %q; want EM4100", got.protocol)
	}
	if got.identifier != "1A 2B 3C 4D 5E" {
		t.Errorf("identifier = %q; want '1A 2B 3C 4D 5E'", got.identifier)
	}
}

func TestParseRFIDBadge_HIDProx(t *testing.T) {
	// HID Prox common output form — protocol name has a space.
	// The pattern accepts "HID Prox" or "HIDProx" via "HID ?Prox".
	out := "HIDProx card\nData: DE AD BE EF 00"
	got := parseRFIDBadge(out)
	if !strings.Contains(strings.ToLower(got.protocol), "hid") {
		t.Errorf("protocol = %q; want HID-something", got.protocol)
	}
	if got.identifier != "DE AD BE EF 00" {
		t.Errorf("identifier = %q", got.identifier)
	}
}

func TestParseRFIDBadge_NoMatch(t *testing.T) {
	got := parseRFIDBadge("nothing here\nempty output")
	if got.protocol != "" || got.identifier != "" {
		t.Errorf("expected zero record, got %+v", got)
	}
	if got.radio != "rfid" {
		t.Errorf("radio field should still be set even with no decode")
	}
}

func TestParseIButtonBadge_Dallas(t *testing.T) {
	out := "Dallas\nKey: 01 02 03 04 05 06 07 08"
	got := parseIButtonBadge(out)
	if got.radio != "ibutton" {
		t.Errorf("radio = %q", got.radio)
	}
	if got.protocol != "Dallas" {
		t.Errorf("protocol = %q; want Dallas", got.protocol)
	}
	if got.identifier != "01 02 03 04 05 06 07 08" {
		t.Errorf("identifier = %q", got.identifier)
	}
}

func TestParseIButtonBadge_Cyfral(t *testing.T) {
	out := "Cyfral\nKey: AA BB CC DD"
	got := parseIButtonBadge(out)
	if got.protocol != "Cyfral" {
		t.Errorf("protocol = %q; want Cyfral", got.protocol)
	}
}

func TestParseIButtonBadge_Metakom(t *testing.T) {
	out := "Metakom\nKey: 11 22 33 44"
	got := parseIButtonBadge(out)
	if got.protocol != "Metakom" {
		t.Errorf("protocol = %q; want Metakom", got.protocol)
	}
}

func TestParseIButtonBadge_NoKeyLine(t *testing.T) {
	out := "Dallas\nNo key detected"
	got := parseIButtonBadge(out)
	if got.protocol != "Dallas" {
		t.Errorf("protocol should still parse: got %q", got.protocol)
	}
	if got.identifier != "" {
		t.Errorf("identifier should be empty when no key: %q", got.identifier)
	}
}
