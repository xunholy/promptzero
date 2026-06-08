// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

const magTE = 200

// buildMagellanPulses renders a 32-bit Magellan frame to a PWM pulse train: the
// te_short preamble, a te_long×3 start mark + te_long space, 32 MSB-first bits
// (bit 1 = short mark + long space, bit 0 = long mark + short space), then the
// long terminating space.
func buildMagellanPulses(data uint32) []int {
	te := magTE
	teLong := te * 2
	p := []int{te * 4, -te} // header lead-in
	for k := 0; k < 12; k++ {
		p = append(p, te, -te) // preamble short pulses
	}
	p = append(p, te, -teLong)       // preamble -> start transition
	p = append(p, teLong*3, -teLong) // start bit
	for k := 31; k >= 0; k-- {
		if (data>>uint(k))&1 == 1 {
			p = append(p, te, -teLong) // bit 1
		} else {
			p = append(p, teLong, -te) // bit 0
		}
	}
	p = append(p, te, -teLong*100) // stop bit
	return p
}

// magellanCRC8 mirrors the production CRC for test-side frame construction
// (CRC-8 poly 0x31, init 0x00). Kept local to avoid exporting the internal one.
func magellanTestCRC8(b []byte) byte {
	var crc byte
	for _, x := range b {
		crc ^= x
		for j := 0; j < 8; j++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x31
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// reverse24 reverses the low 24 bits of v (test-side, mirrors reverseBits).
func reverse24(v uint32) uint32 {
	var r uint32
	for i := 0; i < 24; i++ {
		r = r<<1 | (v>>uint(i))&1
	}
	return r
}

// frameFor builds a valid 32-bit Magellan frame (24-bit reversed payload that
// yields the given event+serial, plus the CRC byte).
func frameFor(event, serial uint32) uint32 {
	payload24 := reverse24((event&0xFF)<<16 | (serial & 0xFFFF))
	crc := magellanTestCRC8([]byte{byte(payload24 >> 16), byte(payload24 >> 8), byte(payload24)})
	return payload24<<8 | uint32(crc)
}

// TestMagellanCRC8 pins the CRC against the firmware's own worked example:
// crc8(0x37,0xAE,0x48) == 0x28. If this passes, the CRC port is correct.
func TestMagellanCRC8(t *testing.T) {
	if got := magellanTestCRC8([]byte{0x37, 0xAE, 0x48}); got != 0x28 {
		t.Fatalf("crc8(0x37AE48) = 0x%02X, want 0x28", got)
	}
}

// TestMagellanFirmwareExample decodes the firmware's documented frame
// 0x37AE4828 -> event 0x12, serial 0x75EC (printed 117236).
func TestMagellanFirmwareExample(t *testing.T) {
	const data = 0x37AE4828
	res, err := protocols.Magellan{}.Decode(buildMagellanPulses(data))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.Payload["code"].(uint32) != data {
		t.Errorf("code = 0x%08X, want 0x%08X", res.Payload["code"], uint32(data))
	}
	if res.Payload["event"].(uint32) != 0x12 {
		t.Errorf("event = 0x%X, want 0x12", res.Payload["event"])
	}
	if res.Payload["serial"].(uint32) != 0x75EC {
		t.Errorf("serial = 0x%X, want 0x75EC", res.Payload["serial"])
	}
	if res.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0", res.Confidence)
	}
}

// TestMagellanRoundTrip builds valid frames across a spread of event/serial
// values and confirms the decoder recovers them (CRC-gated).
func TestMagellanRoundTrip(t *testing.T) {
	for event := uint32(0); event < 256; event += 37 {
		for serial := uint32(0); serial < 0x10000; serial += 2731 {
			data := frameFor(event, serial)
			res, err := protocols.Magellan{}.Decode(buildMagellanPulses(data))
			if err != nil {
				t.Fatalf("Decode(event=0x%X serial=0x%X data=0x%08X): %v", event, serial, data, err)
			}
			if res.Payload["serial"].(uint32) != serial {
				t.Fatalf("serial = 0x%X, want 0x%X", res.Payload["serial"], serial)
			}
			if res.Payload["event"].(uint32) != event {
				t.Fatalf("event = 0x%X, want 0x%X", res.Payload["event"], event)
			}
		}
	}
}

func TestMagellanRejects(t *testing.T) {
	good := buildMagellanPulses(frameFor(0x12, 0x75EC))

	// Corrupt the CRC: flip the lowest data bit so the trailing CRC no longer matches.
	bad := buildMagellanPulses(frameFor(0x12, 0x75EC) ^ 0x100)

	cases := map[string][]int{
		"empty":        {},
		"no start bit": {200, -400, 200, -400, 200},
		"truncated":    good[:20],
		"crc mismatch": bad,
	}
	for name, pulses := range cases {
		if _, err := (protocols.Magellan{}).Decode(pulses); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
