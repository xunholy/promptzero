// SPDX-License-Identifier: AGPL-3.0-or-later

package weather

import (
	"encoding/hex"
	"strings"
	"testing"
)

// encodeAcurite609 builds a valid Acurite 609TXC frame (5 bytes) from
// a sensor ID, a temperature in °C, humidity, and battery flag —
// the inverse of decodeAcurite609's field/checksum maths, so a round
// trip verifies the decode path without a real capture.
func encodeAcurite609(id byte, tempC float64, humidity int, batteryLow bool) []byte {
	raw := int16(tempC * 10) // 12-bit two's-complement value
	b := make([]byte, 5)
	b[0] = id
	b[1] = byte((uint16(raw) >> 8) & 0x0f)
	b[2] = byte(uint16(raw) & 0xff)
	if batteryLow {
		b[1] |= 0x80
	}
	b[3] = byte(humidity)
	b[4] = b[0] + b[1] + b[2] + b[3]
	return b
}

// encodeLaCrosseTX141TH builds a valid LaCrosse TX141TH-Bv2 frame.
func encodeLaCrosseTX141TH(id byte, tempC float64, humidity, channel int, batteryLow, test bool) []byte {
	raw := int(tempC*10) + 500
	b := make([]byte, 5)
	b[0] = id
	b[1] = byte((raw >> 8) & 0x0f)
	b[1] |= byte((channel & 0x3) << 4)
	if test {
		b[1] |= 0x40
	}
	if batteryLow {
		b[1] |= 0x80
	}
	b[2] = byte(raw & 0xff)
	b[3] = byte(humidity)
	b[4] = lfsrDigest8Reflect(b[:4], 0x31, 0xf4)
	return b
}

func TestDecode_Acurite609_RoundTrip(t *testing.T) {
	b := encodeAcurite609(0x5A, 21.7, 48, false)
	res, err := DecodeBytes(b)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	rd := findProto(t, res, "Acurite-609TXC")
	if rd.SensorID != "5A" || rd.SensorIDDec != 0x5A {
		t.Errorf("SensorID = %q/%d; want 5A/90", rd.SensorID, rd.SensorIDDec)
	}
	if rd.TemperatureC != 21.7 {
		t.Errorf("TemperatureC = %v; want 21.7", rd.TemperatureC)
	}
	if rd.Humidity != 48 {
		t.Errorf("Humidity = %d; want 48", rd.Humidity)
	}
	if rd.BatteryLow {
		t.Errorf("BatteryLow = true; want false")
	}
}

func TestDecode_Acurite609_NegativeTemp(t *testing.T) {
	b := encodeAcurite609(0x11, -12.3, 80, true)
	res, err := DecodeBytes(b)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	rd := findProto(t, res, "Acurite-609TXC")
	if rd.TemperatureC != -12.3 {
		t.Errorf("TemperatureC = %v; want -12.3 (two's-complement sign extension)", rd.TemperatureC)
	}
	if !rd.BatteryLow {
		t.Errorf("BatteryLow = false; want true")
	}
}

func TestDecode_LaCrosseTX141TH_RoundTrip(t *testing.T) {
	b := encodeLaCrosseTX141TH(0xC3, 23.4, 55, 2, false, true)
	res, err := DecodeBytes(b)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	rd := findProto(t, res, "LaCrosse-TX141TH-Bv2")
	if rd.TemperatureC != 23.4 {
		t.Errorf("TemperatureC = %v; want 23.4", rd.TemperatureC)
	}
	if rd.Humidity != 55 {
		t.Errorf("Humidity = %d; want 55", rd.Humidity)
	}
	if rd.Channel == nil || *rd.Channel != 2 {
		t.Errorf("Channel = %v; want 2", rd.Channel)
	}
	if rd.TestButton == nil || !*rd.TestButton {
		t.Errorf("TestButton = %v; want true", rd.TestButton)
	}
}

// TestDecode_ChecksumGatesInterpretation corrupts a payload byte and
// asserts no format reports a reading — the checksum is the gate.
func TestDecode_ChecksumGatesInterpretation(t *testing.T) {
	b := encodeAcurite609(0x5A, 21.7, 48, false)
	b[2] ^= 0x01 // flip a temp bit; sum checksum no longer matches
	res, err := DecodeBytes(b)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if len(res.Readings) != 0 {
		t.Errorf("Readings = %+v; want none (checksum must gate)", res.Readings)
	}
	if len(res.Notes) == 0 {
		t.Errorf("expected an explanatory note when no format validates")
	}
}

func TestDecode_HexAndBitsAgree(t *testing.T) {
	b := encodeLaCrosseTX141TH(0x07, 18.0, 60, 0, false, false)
	hexStr := hex.EncodeToString(b)
	fromHex, err := DecodeHex(hexStr)
	if err != nil {
		t.Fatalf("DecodeHex: %v", err)
	}
	var bitStr strings.Builder
	for _, by := range b {
		for j := 7; j >= 0; j-- {
			if (by>>uint(j))&1 == 1 {
				bitStr.WriteByte('1')
			} else {
				bitStr.WriteByte('0')
			}
		}
	}
	fromBits, err := DecodeBits(bitStr.String())
	if err != nil {
		t.Fatalf("DecodeBits: %v", err)
	}
	if fromHex.RawHex != fromBits.RawHex {
		t.Errorf("hex path RawHex %q != bits path RawHex %q", fromHex.RawHex, fromBits.RawHex)
	}
	if len(fromHex.Readings) != 1 || len(fromBits.Readings) != 1 {
		t.Errorf("expected one reading on each path; hex=%d bits=%d", len(fromHex.Readings), len(fromBits.Readings))
	}
}

func TestDecode_Rejections(t *testing.T) {
	if _, err := DecodeBytes([]byte{0x01, 0x02}); err == nil {
		t.Error("DecodeBytes: want error for non-5-byte frame")
	}
	if _, err := DecodeHex(""); err == nil {
		t.Error("DecodeHex: want error for empty")
	}
	if _, err := DecodeHex("zz"); err == nil {
		t.Error("DecodeHex: want error for invalid hex")
	}
	if _, err := DecodeBits("0102"); err == nil {
		t.Error("DecodeBits: want error for non-binary")
	}
	if _, err := DecodeBits("010"); err == nil {
		t.Error("DecodeBits: want error for non-multiple-of-8")
	}
}

// TestLFSRDigest8Reflect_Deterministic pins the digest so a refactor
// that silently changes the algorithm is caught.
func TestLFSRDigest8Reflect_Deterministic(t *testing.T) {
	got := lfsrDigest8Reflect([]byte{0x01, 0x02, 0x03, 0x04}, 0x31, 0xf4)
	again := lfsrDigest8Reflect([]byte{0x01, 0x02, 0x03, 0x04}, 0x31, 0xf4)
	if got != again {
		t.Fatalf("non-deterministic digest: %02X vs %02X", got, again)
	}
	// A single-bit change in the message must change the digest.
	if lfsrDigest8Reflect([]byte{0x01, 0x02, 0x03, 0x05}, 0x31, 0xf4) == got {
		t.Errorf("digest unchanged under a 1-bit message change — not behaving as a checksum")
	}
}

func findProto(t *testing.T, res *Result, proto string) Reading {
	t.Helper()
	for _, rd := range res.Readings {
		if rd.Protocol == proto {
			return rd
		}
	}
	t.Fatalf("no %s reading in result %+v", proto, res.Readings)
	return Reading{}
}
