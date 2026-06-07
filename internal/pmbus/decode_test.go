// SPDX-License-Identifier: AGPL-3.0-or-later

package pmbus

import "testing"

func TestReadVinLinear11(t *testing.T) {
	// READ_VIN (0x88), LINEAR11 0xF030 (exp -2, mantissa 48) = 12.0 V; LE 30 F0.
	r, err := Decode("8830f0")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "READ_VIN" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
	if r.Value != "12 V" {
		t.Errorf("Value = %q, want '12 V'", r.Value)
	}
}

func TestReadTemperatureLinear11(t *testing.T) {
	// READ_TEMPERATURE_1 (0x8D), 25.0 °C. exp 0, mantissa 25 → 0x0019; LE 19 00.
	r, err := Decode("8d1900")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Value != "25 °C" {
		t.Errorf("Value = %q, want '25 °C'", r.Value)
	}
}

func TestVOUTCommandSecurityFlag(t *testing.T) {
	r, err := Decode("21cd0c")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "VOUT_COMMAND" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
	if r.SecurityRelevance == "" {
		t.Error("VOUT_COMMAND should carry a security note (PMFault overvolt vector)")
	}
	// VOUT is ULINEAR16/VOUT_MODE-scaled — surfaced raw with a note.
	if r.Value != "" {
		t.Errorf("VOUT value should not be LINEAR11-decoded, got %q", r.Value)
	}
}

func TestOperationSecurityFlag(t *testing.T) {
	r, err := Decode("0180")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "OPERATION" || r.SecurityRelevance == "" {
		t.Errorf("OPERATION = %q / sec %q", r.CommandName, r.SecurityRelevance)
	}
}

func TestStatusByteFlags(t *testing.T) {
	// STATUS_BYTE (0x78) = 0x24 → VOUT_OV_FAULT (0x20) + TEMPERATURE (0x04).
	r, err := Decode("7824")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.StatusFlags) != 2 || r.StatusFlags[0] != "VOUT_OV_FAULT" || r.StatusFlags[1] != "TEMPERATURE" {
		t.Errorf("StatusFlags = %v, want [VOUT_OV_FAULT TEMPERATURE]", r.StatusFlags)
	}
}

func TestStatusWordHighByte(t *testing.T) {
	// STATUS_WORD (0x79): low 0x00, high 0x80 (VOUT).
	r, err := Decode("790080")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, f := range r.StatusFlags {
		if f == "VOUT" {
			found = true
		}
	}
	if !found {
		t.Errorf("StatusFlags = %v, want VOUT (high byte)", r.StatusFlags)
	}
}

func TestNegativeLinear11(t *testing.T) {
	// READ_IOUT (0x8C): mantissa -16, exp 0 → -16 A. mantissa -16 = 0x7F0
	// (11-bit two's complement), exp 0 → 0x07F0; LE F0 07.
	r, err := Decode("8cf007")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Value != "-16 A" {
		t.Errorf("Value = %q, want '-16 A'", r.Value)
	}
}

func TestUnknownCommand(t *testing.T) {
	r, err := Decode("c5")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "unknown / manufacturer-specific command 0xC5" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
