// SPDX-License-Identifier: AGPL-3.0-or-later

package tpms

import "testing"

// validFrame builds a CRC-valid IEEE-Manchester TPMS frame for the given
// 4-byte sensor ID (plus two filler payload bytes), reusing the same
// encodeManchester/crc8 helpers the decode round-trip tests use.
func validFrame(id [4]byte) string {
	data := []byte{id[0], id[1], id[2], id[3], 0x80, 0x55}
	payload := append(append([]byte{}, data...), crc8(data, 0x07))
	return encodeManchester(payload, true)
}

func TestAnalyzeFrames_NoAnomalyAtWheelCount(t *testing.T) {
	frames := []string{
		validFrame([4]byte{0x11, 0x11, 0x11, 0x11}),
		validFrame([4]byte{0x22, 0x22, 0x22, 0x22}),
		validFrame([4]byte{0x33, 0x33, 0x33, 0x33}),
		validFrame([4]byte{0x44, 0x44, 0x44, 0x44}),
	}
	a, err := AnalyzeFrames(frames, 4)
	if err != nil {
		t.Fatalf("AnalyzeFrames: %v", err)
	}
	if len(a.UniqueSensorIDs) != 4 {
		t.Errorf("UniqueSensorIDs = %d, want 4", len(a.UniqueSensorIDs))
	}
	if a.CRCValidFrames != 4 || a.CRCInvalidFrames != 0 {
		t.Errorf("CRC valid/invalid = %d/%d, want 4/0", a.CRCValidFrames, a.CRCInvalidFrames)
	}
	if len(a.Anomalies) != 0 {
		t.Errorf("expected no anomalies at exactly the wheel count, got %+v", a.Anomalies)
	}
}

func TestAnalyzeFrames_ExcessSensorsWarns(t *testing.T) {
	frames := []string{
		validFrame([4]byte{0x11, 0x11, 0x11, 0x11}),
		validFrame([4]byte{0x22, 0x22, 0x22, 0x22}),
		validFrame([4]byte{0x33, 0x33, 0x33, 0x33}),
		validFrame([4]byte{0x44, 0x44, 0x44, 0x44}),
		validFrame([4]byte{0x55, 0x55, 0x55, 0x55}), // 5th distinct ID > 4 wheels
	}
	a, err := AnalyzeFrames(frames, 4)
	if err != nil {
		t.Fatalf("AnalyzeFrames: %v", err)
	}
	if len(a.UniqueSensorIDs) != 5 {
		t.Fatalf("UniqueSensorIDs = %d, want 5", len(a.UniqueSensorIDs))
	}
	var got *Anomaly
	for i := range a.Anomalies {
		if a.Anomalies[i].Kind == "excess_sensors" {
			got = &a.Anomalies[i]
		}
	}
	if got == nil {
		t.Fatalf("expected an excess_sensors anomaly, got %+v", a.Anomalies)
	}
	if got.Severity != "warning" {
		t.Errorf("excess_sensors severity = %q, want warning", got.Severity)
	}
}

func TestAnalyzeFrames_CRCInvalidFlagged(t *testing.T) {
	// A single-byte frame decodes (>= 8 bits) but carries no CRC, so it
	// matches no covered polynomial — reliably exercising the crc_invalid
	// path with no convention ambiguity.
	a, err := AnalyzeFrames([]string{encodeManchester([]byte{0xAA}, true)}, 4)
	if err != nil {
		t.Fatalf("AnalyzeFrames: %v", err)
	}
	if a.CRCInvalidFrames != 1 {
		t.Errorf("CRCInvalidFrames = %d, want 1", a.CRCInvalidFrames)
	}
	found := false
	for _, an := range a.Anomalies {
		if an.Kind == "crc_invalid" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a crc_invalid anomaly, got %+v", a.Anomalies)
	}
}

func TestAnalyzeFrames_EmptyErrors(t *testing.T) {
	if _, err := AnalyzeFrames(nil, 4); err == nil {
		t.Fatal("expected error for empty frame list, got nil")
	}
}
