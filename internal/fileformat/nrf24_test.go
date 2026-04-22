package fileformat

import (
	"bytes"
	"strings"
	"testing"
)

// ----- ParseNRF24Addresses -----

func TestParseNRF24Addresses_HappyPath(t *testing.T) {
	src := `# captured 2026-04-22
A1:B2:C3:D4:E5,1
11:22:33:44:55,2
DE:AD:BE:EF:00,250
`
	targets, warnings, err := ParseNRF24Addresses(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(targets) != 3 {
		t.Fatalf("want 3 targets, got %d", len(targets))
	}
	if targets[0].Address != "A1:B2:C3:D4:E5" || targets[0].Rate != 1 {
		t.Errorf("targets[0] = %+v", targets[0])
	}
	if targets[2].Rate != 250 {
		t.Errorf("250 kbps rate dropped: %+v", targets[2])
	}
}

func TestParseNRF24Addresses_UppercasesLowerInput(t *testing.T) {
	targets, _, err := ParseNRF24Addresses("a1:b2:c3:d4:e5,2\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if targets[0].Address != "A1:B2:C3:D4:E5" {
		t.Errorf("expected uppercase, got %q", targets[0].Address)
	}
}

func TestParseNRF24Addresses_SkipsBadLinesWithWarnings(t *testing.T) {
	src := `A1:B2:C3:D4:E5,1
not_an_address
AA:BB:CC:DD:EE,abc
11:22:33:44:55,2
`
	targets, warnings, err := ParseNRF24Addresses(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(targets) != 2 {
		t.Errorf("want 2 good targets, got %d", len(targets))
	}
	if len(warnings) != 2 {
		t.Errorf("want 2 warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestParseNRF24Addresses_AllMalformedErrors(t *testing.T) {
	_, _, err := ParseNRF24Addresses("garbage\nmore garbage\n")
	if err == nil {
		t.Error("all-bad input should error out")
	}
}

func TestParseNRF24Addresses_EmptyErrors(t *testing.T) {
	if _, _, err := ParseNRF24Addresses(""); err == nil {
		t.Error("empty input should error")
	}
	if _, _, err := ParseNRF24Addresses("\n\n   "); err == nil {
		t.Error("whitespace-only should error")
	}
}

func TestParseNRF24Addresses_SuspiciousRateWarnsButAccepts(t *testing.T) {
	targets, warnings, err := ParseNRF24Addresses("A1:B2:C3:D4:E5,99\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(targets) != 1 {
		t.Errorf("suspicious rate should still emit target: %d", len(targets))
	}
	if len(warnings) == 0 {
		t.Error("suspicious rate should produce a warning")
	}
}

// ----- BuildMousejackPayload -----

func TestBuildMousejackPayload_HappyPath(t *testing.T) {
	raw, err := BuildMousejackPayload(MousejackPayloadParams{
		Script:   "REM opens a terminal\nGUI r\nDELAY 500\nSTRING cmd\nENTER\n",
		TargetOS: "windows",
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !bytes.Contains(raw, []byte("STRING cmd")) {
		t.Errorf("payload dropped expected keystroke")
	}
	if !bytes.Contains(raw, []byte("REM opens a terminal")) {
		t.Errorf("payload dropped REM comment")
	}
}

func TestBuildMousejackPayload_DelayCapEnforced(t *testing.T) {
	_, err := BuildMousejackPayload(MousejackPayloadParams{
		Script: "DELAY 20000\n",
	})
	if err == nil {
		t.Error("20s DELAY must exceed mousejack cap")
	}
	if !strings.Contains(err.Error(), "loses sync") {
		t.Errorf("error should explain the why: %v", err)
	}
}

func TestBuildMousejackPayload_DelayCapOverridable(t *testing.T) {
	// Operators who know what they're doing can raise the ceiling.
	raw, err := BuildMousejackPayload(MousejackPayloadParams{
		Script:     "DELAY 20000\nSTRING ok\n",
		MaxDelayMS: 30000,
	})
	if err != nil {
		t.Fatalf("override failed: %v", err)
	}
	if !bytes.Contains(raw, []byte("DELAY 20000")) {
		t.Errorf("override should still emit the delay")
	}
}

func TestBuildMousejackPayload_RejectsEmpty(t *testing.T) {
	if _, err := BuildMousejackPayload(MousejackPayloadParams{}); err == nil {
		t.Error("empty script should error")
	}
	if _, err := BuildMousejackPayload(MousejackPayloadParams{Script: "   \n\n"}); err == nil {
		t.Error("whitespace-only script should error")
	}
}

func TestBuildMousejackPayload_RejectsRemOnly(t *testing.T) {
	_, err := BuildMousejackPayload(MousejackPayloadParams{
		Script: "REM just a comment\nREM another one\n",
	})
	if err == nil {
		t.Error("REM-only script should error — nothing to inject")
	}
}

func TestBuildMousejackPayload_RejectsBadTargetOS(t *testing.T) {
	_, err := BuildMousejackPayload(MousejackPayloadParams{
		Script:   "STRING x\n",
		TargetOS: "bsd",
	})
	if err == nil {
		t.Error("bogus target_os should error")
	}
}

func TestBuildMousejackPayload_RejectsNegativeDelay(t *testing.T) {
	_, err := BuildMousejackPayload(MousejackPayloadParams{
		Script: "DELAY -100\n",
	})
	if err == nil {
		t.Error("negative DELAY should error")
	}
}

func TestBuildMousejackPayload_RejectsBadDelayArg(t *testing.T) {
	_, err := BuildMousejackPayload(MousejackPayloadParams{
		Script: "DELAY forever\n",
	})
	if err == nil {
		t.Error("non-integer DELAY should error")
	}
}
