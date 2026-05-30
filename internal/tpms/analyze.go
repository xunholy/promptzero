// SPDX-License-Identifier: AGPL-3.0-or-later

package tpms

import "fmt"

// DefaultExpectedSensors is the TPMS sensor count of a typical passenger
// vehicle (one direct sensor per wheel).
const DefaultExpectedSensors = 4

// Anomaly is one observation flagged during sequence analysis. It is an
// OBSERVATION with interpretation, never a definitive attack verdict —
// every flagged condition has a benign explanation that the detail spells
// out, in keeping with the package's "a confidently-wrong reading is worse
// than none" stance.
type Anomaly struct {
	Kind     string `json:"kind"`     // "excess_sensors" | "crc_invalid"
	Severity string `json:"severity"` // "info" | "warning"
	Detail   string `json:"detail"`
}

// FrameSummary is the per-frame view used by Analysis.
type FrameSummary struct {
	Index       int    `json:"index"`
	SensorID    string `json:"sensor_id,omitempty"`
	CRCValid    bool   `json:"crc_valid"`
	DecodedHex  string `json:"decoded_hex,omitempty"`
	DecodeError string `json:"decode_error,omitempty"`
}

// Analysis is the structured result of AnalyzeFrames.
type Analysis struct {
	FramesAnalyzed    int            `json:"frames_analyzed"`
	FramesDecoded     int            `json:"frames_decoded"`
	ExpectedSensors   int            `json:"expected_sensors"`
	UniqueSensorIDs   []string       `json:"unique_sensor_ids"`
	SensorFrameCounts map[string]int `json:"sensor_frame_counts"`
	CRCValidFrames    int            `json:"crc_valid_frames"`
	CRCInvalidFrames  int            `json:"crc_invalid_frames"`
	Frames            []FrameSummary `json:"frames"`
	Anomalies         []Anomaly      `json:"anomalies"`
	Notes             []string       `json:"notes,omitempty"`
}

// AnalyzeFrames decodes a sequence of TPMS bit-streams (each the same
// '0'/'1' input Decode accepts) and reports defensive anomaly signals over
// the set. expectedSensors is the vehicle's direct-TPMS wheel count
// (<=0 uses DefaultExpectedSensors).
//
// Two deterministic signals are surfaced, both with their benign
// explanation stated so the operator correlates rather than concludes:
//
//   - excess_sensors: more unique 32-bit sensor IDs than a single vehicle
//     carries. Consistent with sensor-ID injection/spoofing (the TPMS
//     attack class) OR simply more than one vehicle in radio range.
//   - crc_invalid: frames matching no covered CRC-8 polynomial. Consistent
//     with a crafted/injected frame OR a TPMS family whose CRC poly is not
//     among the covered set (0x07/0x2F/0x13). Not conclusive on its own.
//
// Pressure/temperature anomaly detection is intentionally absent: the
// field layouts are per-family and unverifiable here (see decode.go), so
// flagging on them would risk the confidently-wrong reading this package
// refuses to produce.
func AnalyzeFrames(bitStreams []string, expectedSensors int) (*Analysis, error) {
	if len(bitStreams) == 0 {
		return nil, fmt.Errorf("tpms: no frames supplied")
	}
	if expectedSensors <= 0 {
		expectedSensors = DefaultExpectedSensors
	}

	a := &Analysis{
		FramesAnalyzed:    len(bitStreams),
		ExpectedSensors:   expectedSensors,
		SensorFrameCounts: map[string]int{},
	}
	seen := map[string]bool{}

	for i, bits := range bitStreams {
		fs := FrameSummary{Index: i}
		res, err := Decode(bits)
		if err != nil {
			fs.DecodeError = err.Error()
			a.Frames = append(a.Frames, fs)
			continue
		}
		a.FramesDecoded++
		fs.DecodedHex = res.DecodedHex
		fs.SensorID = res.SensorID
		fs.CRCValid = len(res.CRC8Matches) > 0
		if fs.CRCValid {
			a.CRCValidFrames++
		} else {
			a.CRCInvalidFrames++
		}
		if res.SensorID != "" {
			a.SensorFrameCounts[res.SensorID]++
			if !seen[res.SensorID] {
				seen[res.SensorID] = true
				a.UniqueSensorIDs = append(a.UniqueSensorIDs, res.SensorID)
			}
		}
		a.Frames = append(a.Frames, fs)
	}

	if n := len(a.UniqueSensorIDs); n > expectedSensors {
		a.Anomalies = append(a.Anomalies, Anomaly{
			Kind:     "excess_sensors",
			Severity: "warning",
			Detail: fmt.Sprintf("%d unique sensor IDs observed, exceeding the %d of a single vehicle — "+
				"consistent with sensor-ID injection/spoofing OR more than one vehicle in radio range. "+
				"Correlate with location/time before concluding.", n, expectedSensors),
		})
	}
	if a.CRCInvalidFrames > 0 {
		a.Anomalies = append(a.Anomalies, Anomaly{
			Kind:     "crc_invalid",
			Severity: "info",
			Detail: fmt.Sprintf("%d of %d decoded frame(s) matched no covered CRC-8 polynomial (0x07/0x2F/0x13) — "+
				"consistent with a crafted/injected frame OR a TPMS family whose CRC poly is not covered. "+
				"Not conclusive on its own.", a.CRCInvalidFrames, a.FramesDecoded),
		})
	}
	if a.FramesDecoded == 0 {
		a.Notes = append(a.Notes, "no frame decoded cleanly; nothing to correlate")
	}
	return a, nil
}
