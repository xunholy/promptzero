// SPDX-License-Identifier: AGPL-3.0-or-later

package t55xx

import "testing"

// Vector 1 (Proxmark3 T5577_Guide): 0x00148040 — EM4100 emulation config.
func TestDecode_EM4100(t *testing.T) {
	c, err := DecodeHex("00148040")
	if err != nil {
		t.Fatal(err)
	}
	if c.DataBitRateRaw != 5 || c.DataBitRate != "RF/64" {
		t.Errorf("bit rate = %d (%s), want 5 (RF/64)", c.DataBitRateRaw, c.DataBitRate)
	}
	if c.ModulationRaw != 8 || c.Modulation != "ASK / Manchester" {
		t.Errorf("modulation = %d (%s), want 8 (ASK / Manchester)", c.ModulationRaw, c.Modulation)
	}
	if c.MaxBlock != 2 {
		t.Errorf("max block = %d, want 2", c.MaxBlock)
	}
	if c.AnswerOnRequest || c.PasswordEnabled || c.SequenceTerminator {
		t.Errorf("AOR/PWD/ST should be unset: %+v", c)
	}
	if c.MasterKey != 0 {
		t.Errorf("master key = %d, want 0", c.MasterKey)
	}
}

// Vector 2 (HID Prox T5577 config): 0x00107060 — FSK2a, RF/50, 3 blocks.
func TestDecode_HIDProx(t *testing.T) {
	c, err := DecodeHex("0x00107060")
	if err != nil {
		t.Fatal(err)
	}
	if c.DataBitRateRaw != 4 || c.DataBitRate != "RF/50" {
		t.Errorf("bit rate = %d (%s), want 4 (RF/50)", c.DataBitRateRaw, c.DataBitRate)
	}
	if c.ModulationRaw != 7 || c.Modulation != "FSK2a (RF/10, RF/8)" {
		t.Errorf("modulation = %d (%s), want 7 (FSK2a)", c.ModulationRaw, c.Modulation)
	}
	if c.MaxBlock != 3 {
		t.Errorf("max block = %d, want 3", c.MaxBlock)
	}
}

func TestDecode_FlagsAndPSK(t *testing.T) {
	// Construct a config: modulation PSK1 (1), PSK clock RF/4 (1), bit rate
	// RF/32 (2), AOR set, PWD set, ST set, max block 4.
	var b uint32
	b |= 2 << 18 // data bit rate = 2 (RF/32)
	b |= 1 << 12 // modulation = 1 (PSK1)
	b |= 1 << 10 // PSK clock = 1 (RF/4)
	b |= 1 << 9  // AOR
	b |= 4 << 5  // max block = 4
	b |= 1 << 4  // PWD
	b |= 1 << 3  // ST
	c := Decode(b)
	if c.Modulation != "PSK1" {
		t.Errorf("modulation = %s, want PSK1", c.Modulation)
	}
	if c.PSKClockFreq != "RF/4" {
		t.Errorf("psk clock = %q, want RF/4", c.PSKClockFreq)
	}
	if c.DataBitRate != "RF/32" {
		t.Errorf("bit rate = %s", c.DataBitRate)
	}
	if !c.AnswerOnRequest || !c.PasswordEnabled || !c.SequenceTerminator {
		t.Errorf("AOR/PWD/ST should all be set: %+v", c)
	}
	if c.MaxBlock != 4 {
		t.Errorf("max block = %d, want 4", c.MaxBlock)
	}
}

func TestDecode_NonPSKHasNoClock(t *testing.T) {
	// Manchester (8) -> PSK clock field not surfaced.
	c, _ := DecodeHex("00148040")
	if c.PSKClockFreq != "" {
		t.Errorf("non-PSK modulation should not surface PSK clock, got %q", c.PSKClockFreq)
	}
}

func TestDecode_ExtendedModeNoted(t *testing.T) {
	// Master key nibble 0x6 -> extended-mode note.
	c := Decode(0x60000000)
	if c.MasterKey != 6 || len(c.Notes) == 0 {
		t.Errorf("extended-mode master key should be noted: %+v", c)
	}
}

func TestDecode_Errors(t *testing.T) {
	if _, err := DecodeHex(""); err == nil {
		t.Error("empty should error")
	}
	if _, err := DecodeHex("zzzz"); err == nil {
		t.Error("non-hex should error")
	}
	if _, err := DecodeHex("0011"); err == nil {
		t.Error("non-4-byte word should error")
	}
}
