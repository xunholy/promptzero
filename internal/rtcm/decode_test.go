// SPDX-License-Identifier: AGPL-3.0-or-later

package rtcm

import (
	"math"
	"testing"
)

// msg1005 is a real RTCM3 type-1005 Stationary RTK Reference Station
// ARP frame; the decoded fields are cross-checked against pyrtcm's
// RTCMReader.parse (DF003 station 2003; ECEF X/Y/Z below).
const msg1005 = "d300133ed7d30202980edeef34b4bd62ac0941986f33360b98"

// msg1006 is a type-1006 frame (1005 + 1.5 m antenna height), built
// to the spec layout and confirmed to round-trip through pyrtcm.
const msg1006 = "d300153ee7d30002980edeef34b4bd62ac0941986f333a98885063"

func TestDecode1005(t *testing.T) {
	msgs, err := Decode(msg1005)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.MessageType != 1005 || !m.ChecksumOK {
		t.Fatalf("type/crc = %d/%v; want 1005/true", m.MessageType, m.ChecksumOK)
	}
	if m.TypeName != "Stationary RTK Reference Station ARP" {
		t.Errorf("TypeName = %q", m.TypeName)
	}
	if m.ReferenceStationID == nil || *m.ReferenceStationID != 2003 {
		t.Errorf("ReferenceStationID = %v; want 2003", m.ReferenceStationID)
	}
	a := m.StationARP
	if a == nil {
		t.Fatal("StationARP nil")
	}
	if math.Abs(a.ECEFXm-1114104.5999) > 1e-3 {
		t.Errorf("ECEFXm = %v; want 1114104.5999", a.ECEFXm)
	}
	if math.Abs(a.ECEFYm-(-4850729.7108)) > 1e-3 {
		t.Errorf("ECEFYm = %v; want -4850729.7108", a.ECEFYm)
	}
	if math.Abs(a.ECEFZm-3975521.4643) > 1e-3 {
		t.Errorf("ECEFZm = %v; want 3975521.4643", a.ECEFZm)
	}
	if a.AntennaHeightM != nil {
		t.Errorf("AntennaHeightM = %v; want nil for a 1005", a.AntennaHeightM)
	}
}

func TestDecode1006(t *testing.T) {
	msgs, err := Decode(msg1006)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := msgs[0]
	if m.MessageType != 1006 || !m.ChecksumOK {
		t.Fatalf("type/crc = %d/%v; want 1006/true", m.MessageType, m.ChecksumOK)
	}
	a := m.StationARP
	if a == nil {
		t.Fatal("StationARP nil")
	}
	if math.Abs(a.ECEFXm-1114104.5999) > 1e-3 || math.Abs(a.ECEFZm-3975521.4643) > 1e-3 {
		t.Errorf("ECEF mismatch: X=%v Z=%v", a.ECEFXm, a.ECEFZm)
	}
	if a.AntennaHeightM == nil || math.Abs(*a.AntennaHeightM-1.5) > 1e-4 {
		t.Errorf("AntennaHeightM = %v; want 1.5", a.AntennaHeightM)
	}
}

func TestDecodeStream(t *testing.T) {
	msgs, err := Decode(msg1005 + msg1006)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(msgs) != 2 || msgs[0].MessageType != 1005 || msgs[1].MessageType != 1006 {
		t.Fatalf("stream = %d msgs; want [1005,1006]", len(msgs))
	}
}

// msg1005neg is a 1005 with NEGATIVE ECEF X/Y/Z — it exercises the
// 38-bit two's-complement sign extension, the bug-prone path. Values
// cross-checked against pyrtcm: station 99, X -12345.6789, Y -200000.0,
// Z -0.005 m.
const msg1005neg = "d300133ed06302bff8a432eb3f88ca6c003fffffffce68014e"

func TestDecode1005NegativeECEF(t *testing.T) {
	msgs, err := Decode(msg1005neg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := msgs[0]
	if m.MessageType != 1005 || !m.ChecksumOK {
		t.Fatalf("type/crc = %d/%v", m.MessageType, m.ChecksumOK)
	}
	if m.ReferenceStationID == nil || *m.ReferenceStationID != 99 {
		t.Errorf("station = %v; want 99", m.ReferenceStationID)
	}
	a := m.StationARP
	if a == nil {
		t.Fatal("StationARP nil")
	}
	if math.Abs(a.ECEFXm-(-12345.6789)) > 1e-4 {
		t.Errorf("ECEFXm = %v; want -12345.6789 (sign extension)", a.ECEFXm)
	}
	if math.Abs(a.ECEFYm-(-200000.0)) > 1e-4 {
		t.Errorf("ECEFYm = %v; want -200000.0", a.ECEFYm)
	}
	if math.Abs(a.ECEFZm-(-0.005)) > 1e-4 {
		t.Errorf("ECEFZm = %v; want -0.005", a.ECEFZm)
	}
}

func TestDecodeSkipsLeadingGarbage(t *testing.T) {
	msgs, err := Decode("00ffd3" + msg1005[2:])
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(msgs) != 1 || msgs[0].MessageType != 1005 {
		t.Fatalf("got %d msgs; want 1 (1005)", len(msgs))
	}
}

func TestDecodeBadCRCNotEmitted(t *testing.T) {
	// Corrupt the last CRC byte: the frame must NOT decode (a bad CRC
	// reads as a false sync, so no message is emitted).
	bad := msg1005[:len(msg1005)-2] + "00"
	if _, err := Decode(bad); err == nil {
		t.Error("expected error (no valid frame) for corrupted CRC")
	}
}

func TestMessageTypeNames(t *testing.T) {
	cases := map[int]string{
		1004: "Extended L1/L2 GPS RTK observables",
		1019: "GPS Ephemeris",
		1077: "GPS MSM7 (Multiple Signal Message)",
		1087: "GLONASS MSM7 (Multiple Signal Message)",
		1097: "Galileo MSM7 (Multiple Signal Message)",
		1127: "BeiDou MSM7 (Multiple Signal Message)",
		1230: "GLONASS L1/L2 Code-Phase Biases",
	}
	for typ, want := range cases {
		if got := messageTypeName(typ); got != want {
			t.Errorf("messageTypeName(%d) = %q; want %q", typ, got, want)
		}
	}
}

func TestDecodeRejectsNonRTCM(t *testing.T) {
	for _, c := range []string{"", "zz", "00112233", "d3"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestCRC24Q(t *testing.T) {
	// "123456789" → CRC-24Q (poly 0x1864CFB, init 0) check value
	// 0xCDE703. (This differs from the OpenPGP CRC-24, which shares the
	// polynomial but seeds with 0xB704CE.) Confirmed against an
	// independent Python reference and the real pyrtcm-sourced frames,
	// whose CRCs validate with this implementation.
	if got := crc24q([]byte("123456789")); got != 0xCDE703 {
		t.Errorf("crc24q check value = %06X; want CDE703", got)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(msg1005)
	f.Add(msg1006)
	f.Add(msg1005 + msg1006)
	f.Add("d3")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
