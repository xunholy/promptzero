// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

func TestPrincetonPT2262RoundTrip(t *testing.T) {
	// addr=0xAAA (101010101010), data=0x5 (0101)
	const te = 350
	addr := uint32(0xAAA)
	data := uint32(0x5)
	bits := uint16ToBits(uint16((addr<<4)|data), 16)

	pulses := encodePWMFrame(bits, te, 1, 31, 3, 1, 1, 3, 3)

	p := protocols.PrincetonPT2262{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if res.Confidence < 0.8 {
		t.Errorf("confidence = %.2f, want ≥ 0.80", res.Confidence)
	}
	gotAddr := res.Payload["address"].(uint32)
	gotData := res.Payload["data"].(uint32)
	if gotAddr != addr {
		t.Errorf("address = %X, want %X", gotAddr, addr)
	}
	if gotData != data {
		t.Errorf("data = %X, want %X", gotData, data)
	}
}

func TestPrincetonPT2262NoSync(t *testing.T) {
	// All short marks — no long sync gap
	pulses := make([]int, 40)
	for i := range pulses {
		if i%2 == 0 {
			pulses[i] = 350
		} else {
			pulses[i] = -350
		}
	}
	p := protocols.PrincetonPT2262{}
	_, err := p.Decode(pulses)
	if err == nil {
		t.Error("expected error when sync absent, got nil")
	}
}

func TestPrincetonPT2262Name(t *testing.T) {
	p := protocols.PrincetonPT2262{}
	if p.Name() != "Princeton PT2262" {
		t.Errorf("Name() = %q", p.Name())
	}
	if p.BitRate() <= 0 {
		t.Errorf("BitRate() = %.1f, want > 0", p.BitRate())
	}
}
