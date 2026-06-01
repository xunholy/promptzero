// SPDX-License-Identifier: AGPL-3.0-or-later

package obd2

import (
	"math"
	"testing"
)

func approx(got, want float64) bool { return math.Abs(got-want) < 1e-6 }

// TestDecodeResponse_HandVectors checks the canonical J1979 formulas against
// hand-computed values.
func TestDecodeResponse_HandVectors(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		val  float64
		unit string
	}{
		{"RPM", "410C1AF8", 1726, "rpm"},                    // ((26*256)+248)/4
		{"speed", "410D50", 80, "km/h"},                     // 0x50
		{"coolant", "41057B", 83, "°C"},                     // 123-40
		{"throttle 100%", "4111FF", 100, "%"},               // 255*100/255
		{"MAF", "411001F4", 5.0, "g/s"},                     // (256+244)/100
		{"load", "41047F", 127.0 * 100 / 255, "%"},          // ~49.8
		{"timing advance 0", "410E80", 0, "° before TDC"},   // 128/2-64
		{"intake temp", "410F32", 10, "°C"},                 // 50-40
		{"control module voltage", "4142385C", 14.428, "V"}, // (0x385C=14428)/1000
	}
	for _, c := range cases {
		r, err := DecodeResponse(c.hex)
		if err != nil {
			t.Fatalf("%s: DecodeResponse: %v", c.name, err)
		}
		if r.Value == nil {
			t.Fatalf("%s: nil value", c.name)
		}
		if !approx(*r.Value, c.val) {
			t.Errorf("%s: value = %v, want %v", c.name, *r.Value, c.val)
		}
		if r.Unit != c.unit {
			t.Errorf("%s: unit = %q, want %q", c.name, r.Unit, c.unit)
		}
	}
}

func TestDecodeResponse_NamesPID(t *testing.T) {
	r, err := DecodeResponse("41 0C 1A F8")
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if r.Name != "Engine RPM" || r.PIDHex != "0x0C" {
		t.Errorf("name/pid = %q/%s, want Engine RPM/0x0C", r.Name, r.PIDHex)
	}
	if r.Formula != "((A*256)+B)/4" {
		t.Errorf("formula = %q", r.Formula)
	}
}

func TestDecodeResponse_UnknownPIDRaw(t *testing.T) {
	// PID 0x00 (supported-PIDs bitmask) has no formula -> raw, no value.
	r, err := DecodeResponse("410012345678")
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if r.Value != nil {
		t.Errorf("unknown PID got a value: %v", *r.Value)
	}
	if r.RawHex != "12345678" {
		t.Errorf("raw_hex = %q, want 12345678", r.RawHex)
	}
	if r.Note == "" {
		t.Error("expected a note for an unsupported PID")
	}
}

func TestDecodeResponse_TruncatedData(t *testing.T) {
	// RPM needs 2 data bytes; supply 1.
	r, err := DecodeResponse("410C1A")
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if r.Value != nil {
		t.Errorf("truncated RPM got a value: %v", *r.Value)
	}
	if r.Note == "" {
		t.Error("expected a note for too-few data bytes")
	}
}

func TestDecodeResponse_Request(t *testing.T) {
	r, err := DecodeResponse("010C")
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if r.Value != nil {
		t.Errorf("request got a value")
	}
	if r.Name != "Engine RPM" {
		t.Errorf("request PID name = %q, want Engine RPM", r.Name)
	}
}

func TestDecodeResponse_Errors(t *testing.T) {
	for _, in := range []string{"", "41", "zz", "030C"} { // empty, too short, non-hex, wrong mode
		if _, err := DecodeResponse(in); err == nil {
			t.Errorf("DecodeResponse(%q): expected error", in)
		}
	}
}
