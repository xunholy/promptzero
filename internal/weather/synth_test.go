// SPDX-License-Identifier: AGPL-3.0-or-later

package weather

import "testing"

// TestSynth_RoundTrip is the primary check: a frame built by Synth must
// decode back to the same reading via the independent DecodeBytes path,
// for both covered families and across the temperature sign + range.
func TestSynth_RoundTrip(t *testing.T) {
	cases := []SynthInput{
		{Protocol: "Acurite-609TXC", SensorID: 0xA3, TemperatureC: 21.5, Humidity: 48, BatteryLow: false},
		{Protocol: "Acurite-609TXC", SensorID: 0x10, TemperatureC: -5.0, Humidity: 90, BatteryLow: true},
		{Protocol: "Acurite-609TXC", SensorID: 0xFF, TemperatureC: 0.0, Humidity: 0},
		{Protocol: "LaCrosse-TX141TH-Bv2", SensorID: 0x7C, TemperatureC: 23.4, Humidity: 55, Channel: 1, TestButton: false},
		{Protocol: "LaCrosse-TX141TH-Bv2", SensorID: 0x01, TemperatureC: -12.7, Humidity: 100, Channel: 3, TestButton: true, BatteryLow: true},
		{Protocol: "lacrosse", SensorID: 0x42, TemperatureC: 35.0, Humidity: 20, Channel: 0},
	}
	for _, in := range cases {
		frame, err := Synth(in)
		if err != nil {
			t.Fatalf("Synth(%+v): %v", in, err)
		}
		if len(frame) != 5 {
			t.Fatalf("Synth(%+v): %d bytes, want 5", in, len(frame))
		}
		res, err := DecodeBytes(frame)
		if err != nil {
			t.Fatalf("DecodeBytes(%X): %v", frame, err)
		}
		var rd *Reading
		for i := range res.Readings {
			if normalizeProto(res.Readings[i].Protocol) == normalizeProto(in.Protocol) {
				rd = &res.Readings[i]
			}
		}
		if rd == nil {
			t.Fatalf("%+v: no matching reading decoded from %X (got %+v)", in, frame, res.Readings)
		}
		if rd.SensorIDDec != in.SensorID {
			t.Errorf("%+v: SensorID round-trips to %d", in, rd.SensorIDDec)
		}
		if rd.TemperatureC != in.TemperatureC {
			t.Errorf("%+v: temp round-trips to %.1f", in, rd.TemperatureC)
		}
		if rd.Humidity != in.Humidity {
			t.Errorf("%+v: humidity round-trips to %d", in, rd.Humidity)
		}
		if rd.BatteryLow != in.BatteryLow {
			t.Errorf("%+v: battery round-trips to %v", in, rd.BatteryLow)
		}
		if normalizeProto(in.Protocol) == "lacrosse" {
			if rd.Channel == nil || *rd.Channel != in.Channel {
				t.Errorf("%+v: channel round-trips to %v", in, rd.Channel)
			}
			if rd.TestButton == nil || *rd.TestButton != in.TestButton {
				t.Errorf("%+v: test button round-trips to %v", in, rd.TestButton)
			}
		}
	}
}

// TestSynth_HandComputedChecksum pins the Acurite frame layout + sum
// checksum independently of the decoder. SensorID 0x10, +21.5°C (raw 215 =
// 0x0D7 → b1 low nibble 0, b2 0xD7), humidity 48 (0x30).
func TestSynth_HandComputedChecksum(t *testing.T) {
	frame, err := Synth(SynthInput{Protocol: "Acurite-609TXC", SensorID: 0x10, TemperatureC: 21.5, Humidity: 48})
	if err != nil {
		t.Fatalf("Synth: %v", err)
	}
	want := []byte{0x10, 0x00, 0xD7, 0x30, 0}
	want[4] = (want[0] + want[1] + want[2] + want[3]) & 0xff // 0x10+0x00+0xD7+0x30 = 0x117 & 0xff = 0x17
	for i := range want {
		if frame[i] != want[i] {
			t.Fatalf("frame = %X, want %X (byte %d)", frame, want, i)
		}
	}
	if frame[4] != 0x17 {
		t.Errorf("checksum = %02X, want 17", frame[4])
	}
}

func TestSynth_RejectsBadInput(t *testing.T) {
	bad := []SynthInput{
		{Protocol: "Acurite-609TXC", SensorID: 256, TemperatureC: 20, Humidity: 50},
		{Protocol: "Acurite-609TXC", SensorID: 1, TemperatureC: 20, Humidity: 101},
		{Protocol: "Acurite-609TXC", SensorID: 1, TemperatureC: 300, Humidity: 50}, // 12-bit overflow
		{Protocol: "LaCrosse-TX141TH-Bv2", SensorID: 1, TemperatureC: 20, Humidity: 50, Channel: 4},
		{Protocol: "LaCrosse-TX141TH-Bv2", SensorID: 1, TemperatureC: -100, Humidity: 50}, // raw < 0
		{Protocol: "Nope", SensorID: 1, TemperatureC: 20, Humidity: 50},
	}
	for _, in := range bad {
		if _, err := Synth(in); err == nil {
			t.Errorf("Synth(%+v): expected error, got nil", in)
		}
	}
}
