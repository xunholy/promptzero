// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

func TestCAMERoundTrip(t *testing.T) {
	const te = 320
	const wantCode = uint32(0xA5B)
	bits := uint16ToBits(uint16(wantCode), 12)

	// CAME: sync = 1×TE mark + 36×TE space
	// "1" = 1×TE mark + 1×TE space; "0" = 1×TE mark + 2×TE space
	pulses := encodeCMEFrame(bits, te, 1, 36, 1, 1, 1, 2, 3)

	p := protocols.CAME{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if res.Confidence < 0.8 {
		t.Errorf("confidence = %.2f, want ≥ 0.80", res.Confidence)
	}
	gotCode := res.Payload["code"].(uint32)
	if gotCode != wantCode {
		t.Errorf("code = %X, want %X", gotCode, wantCode)
	}
}

func TestCAMEName(t *testing.T) {
	p := protocols.CAME{}
	if p.Name() != "CAME" {
		t.Errorf("Name() = %q", p.Name())
	}
}

func TestCAMENoSync(t *testing.T) {
	pulses := make([]int, 30)
	for i := range pulses {
		if i%2 == 0 {
			pulses[i] = 320
		} else {
			pulses[i] = -320
		}
	}
	_, err := protocols.CAME{}.Decode(pulses)
	if err == nil {
		t.Error("expected error when no sync")
	}
}

// encodeCMEFrame is a CAME-specific encoder: mark(syncHigh×te) + space(syncLow×te)
// then bits encoded as mark(te) + space(1×te or 2×te).
func encodeCMEFrame(bits []byte, te, syncHigh, syncLow, oneHigh, oneLow, zeroHigh, zeroLow, repeat int) []int {
	if repeat < 1 {
		repeat = 1
	}
	var frame []int
	frame = append(frame, syncHigh*te, -(syncLow * te))
	for _, b := range bits {
		if b != 0 {
			frame = append(frame, oneHigh*te, -(oneLow * te))
		} else {
			frame = append(frame, zeroHigh*te, -(zeroLow * te))
		}
	}
	out := make([]int, 0, len(frame)*repeat)
	for i := 0; i < repeat; i++ {
		out = append(out, frame...)
	}
	return out
}
