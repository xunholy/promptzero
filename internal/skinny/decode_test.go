// SPDX-License-Identifier: AGPL-3.0-or-later

package skinny

import (
	"strings"
	"testing"
)

// Vectors built with scapy.contrib.skinny.

func TestDecodeKeypad(t *testing.T) {
	// KeypadButton, key 5 (the digit dialed), instance 1.
	r, err := Decode("100000000000000003000000050000000100000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Messages) != 1 {
		t.Fatalf("messages = %d; want 1", len(r.Messages))
	}
	m := r.Messages[0]
	if m.Length != 16 || m.MessageID != "0x0003" || m.MessageName != "KeypadButton" {
		t.Errorf("msg = %+v", m)
	}
	if m.DialedDigit != "5" {
		t.Errorf("DialedDigit = %q; want 5", m.DialedDigit)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "dialed") {
		t.Error("expected the dialed-digit recon note")
	}
}

func TestDecodeKeypadHash(t *testing.T) {
	// KeypadButton key 15 -> '#'.
	r, err := Decode("1000000000000000030000000f0000000100000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Messages[0].DialedDigit != "#" {
		t.Errorf("DialedDigit = %q; want #", r.Messages[0].DialedDigit)
	}
}

func TestDecodeOffHook(t *testing.T) {
	r, err := Decode("0c00000000000000060000000000000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := r.Messages[0]
	if m.Length != 12 || m.MessageID != "0x0006" || m.MessageName != "OffHook" {
		t.Errorf("msg = %+v", m)
	}
	if m.DialedDigit != "" {
		t.Errorf("OffHook should have no dialed digit")
	}
}

func TestDecodeStream(t *testing.T) {
	// OffHook + KeypadButton(5) concatenated — the self-delimiting framing
	// must yield both messages.
	r, err := Decode("0c00000000000000060000000000000000000000" +
		"100000000000000003000000050000000100000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Messages) != 2 {
		t.Fatalf("messages = %d; want 2", len(r.Messages))
	}
	if r.Messages[0].MessageName != "OffHook" || r.Messages[1].MessageName != "KeypadButton" {
		t.Errorf("stream = %q, %q", r.Messages[0].MessageName, r.Messages[1].MessageName)
	}
	if r.Messages[1].DialedDigit != "5" {
		t.Errorf("second msg dialed = %q; want 5", r.Messages[1].DialedDigit)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "zz", "100000", "ffffffff0000000003000000"} { // empty / non-hex / short / length overruns
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestMessageNames(t *testing.T) {
	if messageName(0x0001) != "Register" || messageName(0x008F) != "CallInfo" {
		t.Errorf("names: 0x0001=%q 0x008F=%q", messageName(0x0001), messageName(0x008F))
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("100000000000000003000000050000000100000000000000")
	f.Add("0c00000000000000060000000000000000000000")
	f.Add("")
	f.Add("10000000")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
