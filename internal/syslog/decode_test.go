package syslog

import (
	"strings"
	"testing"
)

// TestDecode_RFC5424_Canonical pins the canonical RFC 5424
// example message — including structured data with two
// elements + escaped quote in a parameter value + a MSG body.
func TestDecode_RFC5424_Canonical(t *testing.T) {
	// PRI 165 = facility 20 (local4), severity 5 (Notice)
	line := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 ` +
		`[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]` +
		`[examplePriority@32473 class="high"]` +
		` BOMAn application event log entry...`
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Format != "RFC 5424 (IETF)" {
		t.Errorf("Format = %q", got.Format)
	}
	if got.Priority != 165 {
		t.Errorf("Priority = %d", got.Priority)
	}
	if got.Facility != 20 {
		t.Errorf("Facility = %d; want 20 (local4)", got.Facility)
	}
	if !strings.HasPrefix(got.FacilityName, "local4") {
		t.Errorf("FacilityName = %q", got.FacilityName)
	}
	if got.Severity != 5 {
		t.Errorf("Severity = %d; want 5", got.Severity)
	}
	if !strings.HasPrefix(got.SeverityName, "Notice") {
		t.Errorf("SeverityName = %q", got.SeverityName)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d", got.Version)
	}
	if got.Timestamp != "2003-10-11T22:14:15.003Z" {
		t.Errorf("Timestamp = %q", got.Timestamp)
	}
	if got.Hostname != "mymachine.example.com" {
		t.Errorf("Hostname = %q", got.Hostname)
	}
	if got.AppName != "evntslog" {
		t.Errorf("AppName = %q", got.AppName)
	}
	if got.ProcID != "" {
		t.Errorf("ProcID = %q; want empty (was '-')", got.ProcID)
	}
	if got.MsgID != "ID47" {
		t.Errorf("MsgID = %q", got.MsgID)
	}
	if len(got.StructuredData) != 2 {
		t.Fatalf("StructuredData count = %d", len(got.StructuredData))
	}
	sd1 := got.StructuredData[0]
	if sd1.ID != "exampleSDID@32473" {
		t.Errorf("SD[0].ID = %q", sd1.ID)
	}
	if sd1.Parameters["iut"] != "3" {
		t.Errorf("SD[0].iut = %q", sd1.Parameters["iut"])
	}
	if sd1.Parameters["eventSource"] != "Application" {
		t.Errorf("SD[0].eventSource = %q", sd1.Parameters["eventSource"])
	}
	if sd1.Parameters["eventID"] != "1011" {
		t.Errorf("SD[0].eventID = %q", sd1.Parameters["eventID"])
	}
	sd2 := got.StructuredData[1]
	if sd2.ID != "examplePriority@32473" {
		t.Errorf("SD[1].ID = %q", sd2.ID)
	}
	if sd2.Parameters["class"] != "high" {
		t.Errorf("SD[1].class = %q", sd2.Parameters["class"])
	}
	if got.Message != "BOMAn application event log entry..." {
		t.Errorf("Message = %q", got.Message)
	}
}

// TestDecode_RFC5424_NoStructuredData pins the variant where
// structured data is the nil marker `-`.
func TestDecode_RFC5424_NoStructuredData(t *testing.T) {
	line := `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed`
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Facility != 4 {
		t.Errorf("Facility = %d; want 4 (auth)", got.Facility)
	}
	if got.Severity != 2 {
		t.Errorf("Severity = %d; want 2 (Critical)", got.Severity)
	}
	if got.AppName != "su" {
		t.Errorf("AppName = %q", got.AppName)
	}
	if len(got.StructuredData) != 0 {
		t.Errorf("StructuredData should be empty for '-'")
	}
	if got.Message != "'su root' failed" {
		t.Errorf("Message = %q", got.Message)
	}
}

// TestDecode_RFC5424_EscapedQuote pins the backslash-escape
// handling inside an SD parameter value.
func TestDecode_RFC5424_EscapedQuote(t *testing.T) {
	line := `<14>1 - - - - - [meta tag="hello \"world\""] body text`
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.StructuredData[0].Parameters["tag"] != `hello "world"` {
		t.Errorf("tag = %q", got.StructuredData[0].Parameters["tag"])
	}
}

// TestDecode_RFC3164_BSD pins a classic BSD-format message.
func TestDecode_RFC3164_BSD(t *testing.T) {
	line := `<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Format != "RFC 3164 (BSD)" {
		t.Errorf("Format = %q", got.Format)
	}
	if got.Priority != 34 {
		t.Errorf("Priority = %d", got.Priority)
	}
	if got.Facility != 4 {
		t.Errorf("Facility = %d", got.Facility)
	}
	if got.SeverityName != "Critical (critical conditions)" {
		t.Errorf("SeverityName = %q", got.SeverityName)
	}
	if got.Timestamp != "Oct 11 22:14:15" {
		t.Errorf("Timestamp = %q", got.Timestamp)
	}
	if got.Hostname != "mymachine" {
		t.Errorf("Hostname = %q", got.Hostname)
	}
	if got.Tag != "su" {
		t.Errorf("Tag = %q", got.Tag)
	}
	if got.Message != "'su root' failed for lonvick on /dev/pts/8" {
		t.Errorf("Message = %q", got.Message)
	}
}

// TestDecode_RFC3164_PID pins a TAG[PID] split.
func TestDecode_RFC3164_PID(t *testing.T) {
	line := `<13>Sep 29 06:55:01 server cron[1234]: (root) CMD (run-parts /etc/cron.hourly)`
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Tag != "cron" {
		t.Errorf("Tag = %q", got.Tag)
	}
	if got.ProcID != "1234" {
		t.Errorf("ProcID = %q", got.ProcID)
	}
}

// TestDecode_RFC3164_DayPadding pins the single-digit-day
// "Jan  2" form (note two spaces between Mmm and day).
func TestDecode_RFC3164_DayPadding(t *testing.T) {
	line := `<14>Jan  2 03:04:05 host1 daemon: started`
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Timestamp != "Jan  2 03:04:05" {
		t.Errorf("Timestamp = %q", got.Timestamp)
	}
	if got.Hostname != "host1" {
		t.Errorf("Hostname = %q", got.Hostname)
	}
}

// TestDecode_AllFacilities spot-checks every standard facility
// + the 8 local facilities.
func TestDecode_AllFacilities(t *testing.T) {
	cases := map[int]string{
		0:  "kern",
		1:  "user",
		2:  "mail",
		3:  "daemon",
		4:  "auth",
		5:  "syslog",
		10: "authpriv",
		11: "ftp",
		16: "local0",
		17: "local1",
		23: "local7",
	}
	for code, prefix := range cases {
		got := facilityName(code)
		if !strings.HasPrefix(got, prefix) {
			t.Errorf("facilityName(%d) = %q; want prefix %q", code, got, prefix)
		}
	}
}

// TestDecode_AllSeverities spot-checks all 8 severities.
func TestDecode_AllSeverities(t *testing.T) {
	cases := map[int]string{
		0: "Emergency",
		1: "Alert",
		2: "Critical",
		3: "Error",
		4: "Warning",
		5: "Notice",
		6: "Informational",
		7: "Debug",
	}
	for code, prefix := range cases {
		got := severityName(code)
		if !strings.HasPrefix(got, prefix) {
			t.Errorf("severityName(%d) = %q; want prefix %q", code, got, prefix)
		}
	}
}

// TestDecode_PriorityBounds rejects out-of-range PRI.
func TestDecode_PriorityBounds(t *testing.T) {
	if _, err := Decode("<999>1 - - - - - - test"); err == nil {
		t.Error("PRI 999: want error")
	}
}

// TestDecode_MissingPRI rejects messages that don't start
// with '<'.
func TestDecode_MissingPRI(t *testing.T) {
	if _, err := Decode("no pri here"); err == nil {
		t.Error("no PRI: want error")
	}
}

// TestDecode_MalformedPRI rejects '<>' / '<abc>' / unclosed.
func TestDecode_MalformedPRI(t *testing.T) {
	if _, err := Decode("<abc>1 ..."); err == nil {
		t.Error("non-numeric PRI: want error")
	}
	if _, err := Decode("<165 noclose"); err == nil {
		t.Error("missing '>': want error")
	}
}

// TestDecode_Empty rejects empty input.
func TestDecode_Empty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestDecode_RFC5424_UnterminatedSD surfaces an error rather
// than silently truncating.
func TestDecode_RFC5424_UnterminatedSD(t *testing.T) {
	line := `<14>1 - - - - - [oops missing close`
	if _, err := Decode(line); err == nil {
		t.Error("unterminated SD: want error")
	}
}
