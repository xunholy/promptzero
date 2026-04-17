package fileformat

import (
	"reflect"
	"strings"
	"testing"
)

const irFixture = `Filetype: IR signals file
Version: 1
#
name: Power
type: parsed
protocol: NEC
address: 04 00 00 00
command: 08 00 00 00
#
name: Volume_Up
type: raw
frequency: 38000
duty_cycle: 0.330000
data: 9000 4500 560 560 560 1690 560 560
`

func TestParseIR(t *testing.T) {
	f, err := ParseIR([]byte(irFixture))
	if err != nil {
		t.Fatalf("ParseIR: %v", err)
	}
	if len(f.Signals) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(f.Signals))
	}
	if f.Signals[0].Protocol != "NEC" || f.Signals[0].Command != "08 00 00 00" {
		t.Fatalf("signal 0: %+v", f.Signals[0])
	}
	raw := f.Signals[1]
	if raw.Type != "raw" || raw.Frequency != 38000 || len(raw.Data) != 8 {
		t.Fatalf("signal 1: %+v", raw)
	}
	if raw.Data[2] != 560 {
		t.Fatalf("signal 1 data[2]: %d", raw.Data[2])
	}
}

func TestIR_RoundTrip(t *testing.T) {
	assertIRRoundTrip(t, irFixture)
}

func TestIR_CRLFAndComments(t *testing.T) {
	crlf := strings.ReplaceAll(irFixture, "\n", "\r\n")
	assertIRRoundTrip(t, crlf)
}

func TestIR_MissingFinalNewline(t *testing.T) {
	assertIRRoundTrip(t, strings.TrimRight(irFixture, "\n"))
}

func TestIR_EditSignalFields(t *testing.T) {
	f, err := ParseIR([]byte(irFixture))
	if err != nil {
		t.Fatal(err)
	}
	edits := map[string]interface{}{
		"signal_0_name":    "TV_Power",
		"signal_0_command": "FF 00 00 00",
	}
	if err := applyIREdits(f, edits); err != nil {
		t.Fatalf("applyIREdits: %v", err)
	}
	if f.Signals[0].Name != "TV_Power" || f.Signals[0].Command != "FF 00 00 00" {
		t.Fatalf("edits not applied: %+v", f.Signals[0])
	}
}

func TestIR_RejectUnknownEdit(t *testing.T) {
	f, _ := ParseIR([]byte(irFixture))
	if err := applyIREdits(f, map[string]interface{}{"random": "x"}); err == nil {
		t.Fatalf("expected error for unknown key")
	}
	if err := applyIREdits(f, map[string]interface{}{"signal_9_name": "x"}); err == nil {
		t.Fatalf("expected error for out-of-range signal index")
	}
	if err := applyIREdits(f, map[string]interface{}{"signal_0_badfield": "x"}); err == nil {
		t.Fatalf("expected error for unknown signal field")
	}
}

func assertIRRoundTrip(t *testing.T, fixture string) {
	t.Helper()
	a, err := ParseIR([]byte(fixture))
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	b, err := ParseIR(a.Marshal())
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("round-trip mismatch\nA: %+v\nB: %+v", a, b)
	}
}
