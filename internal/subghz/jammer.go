// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"fmt"
	"math"
	"sort"
)

// JammingOpts carries the (overridable) decision thresholds for AnalyzeJamming.
// A zero value selects the documented defaults. They are surfaced in the result
// so the operator sees exactly what the flags were computed against — the flags
// are heuristic OBSERVATIONS, not a verdict, and the raw statistics are always
// reported regardless of the thresholds.
type JammingOpts struct {
	// BusyThresholdDbm: a sample at or above this RSSI counts the channel as
	// occupied (default -80 dBm).
	BusyThresholdDbm float64
	// ElevatedFloorDbm: a noise floor at or above this flags an elevated floor
	// (default -85 dBm) — a jammer raises the floor the channel idles at.
	ElevatedFloorDbm float64
	// FloorPercentile: the percentile used to estimate the noise floor, robust
	// to a few high bursts (default 10).
	FloorPercentile float64
	// OccupancyFlag: an occupancy fraction at or above this flags sustained
	// occupancy (default 0.85).
	OccupancyFlag float64
	// DwellFlagFraction: a longest-continuous-run-above-busy fraction at or
	// above this flags a long dwell (default 0.5 of the samples).
	DwellFlagFraction float64
}

func (o JammingOpts) withDefaults() JammingOpts {
	if o.BusyThresholdDbm == 0 {
		o.BusyThresholdDbm = -80
	}
	if o.ElevatedFloorDbm == 0 {
		o.ElevatedFloorDbm = -85
	}
	if o.FloorPercentile == 0 {
		o.FloorPercentile = 10
	}
	if o.OccupancyFlag == 0 {
		o.OccupancyFlag = 0.85
	}
	if o.DwellFlagFraction == 0 {
		o.DwellFlagFraction = 0.5
	}
	return o
}

// JammingObservation is one signal flagged during RSSI-sequence analysis. Like
// RollbackObservation and internal/tpms.Anomaly it is an OBSERVATION with its
// benign explanation stated, never a definitive jammer verdict — a
// confidently-wrong alert is worse than none.
type JammingObservation struct {
	Kind     string `json:"kind"`     // elevated_noise_floor | sustained_occupancy | long_dwell
	Severity string `json:"severity"` // info | warning
	Detail   string `json:"detail"`
}

// JammingAnalysis is the structured result of AnalyzeJamming. The statistics
// are objective; the observations apply the (reported) thresholds.
type JammingAnalysis struct {
	SamplesAnalyzed int `json:"samples_analyzed"`

	MinDbm        float64 `json:"min_dbm"`
	MaxDbm        float64 `json:"max_dbm"`
	MeanDbm       float64 `json:"mean_dbm"`
	MedianDbm     float64 `json:"median_dbm"`
	StdDevDb      float64 `json:"std_dev_db"`
	NoiseFloorDbm float64 `json:"noise_floor_dbm"` // FloorPercentile of the samples

	OccupancyFraction    float64 `json:"occupancy_fraction"`    // fraction at/above BusyThresholdDbm
	LongestDwellSamples  int     `json:"longest_dwell_samples"` // longest run at/above BusyThresholdDbm
	LongestDwellFraction float64 `json:"longest_dwell_fraction"`

	Thresholds   JammingOpts          `json:"thresholds"`
	Observations []JammingObservation `json:"observations"`
	Notes        []string             `json:"notes,omitempty"`
}

// AnalyzeJamming inspects a sequence of RSSI samples (in dBm, capture order) for
// the signatures of a continuous-carrier / sweep jammer — the offline,
// host-side complement to the on-device "Sub-GHz Jammer Detect" FAP
// (loader_subghz_jammer_detect), which only flags on the Flipper itself. The
// operator feeds an already-captured RSSI series; the analyser does no RF work.
//
// It is built on the same receive-only "RSSI floor + dwell" heuristic, and like
// subghz_rollback_detect / tpms_anomaly_detect every flag is an OBSERVATION with
// its benign explanation stated — never a verdict. The objective statistics
// (min/max/mean/median/std-dev/noise-floor/occupancy/longest-dwell) are always
// reported; the three flags apply the documented, overridable thresholds (which
// are echoed back in the result):
//
//   - elevated_noise_floor: the noise floor (a low percentile, robust to
//     bursts) sits at/above ElevatedFloorDbm. A jammer raises the level the
//     channel idles at. Benign: a strong nearby legitimate transmitter, or a
//     congested band.
//   - sustained_occupancy: the fraction of samples at/above the busy threshold
//     is at/above OccupancyFlag. Normal traffic is bursty (low duty cycle); a
//     jammer is continuous. Benign: a legitimate continuous carrier (e.g. an
//     analogue video/audio link).
//   - long_dwell: the longest unbroken run above the busy threshold spans
//     at/above DwellFlagFraction of the capture. Benign: same as above.
//
// No claim is made that a flagged capture IS a jammer — the statistics and
// flags are for an operator to correlate, never a confidently-wrong verdict.
func AnalyzeJamming(samples []float64, opts JammingOpts) (*JammingAnalysis, error) {
	if len(samples) == 0 {
		return nil, fmt.Errorf("subghz: no RSSI samples supplied")
	}
	o := opts.withDefaults()

	a := &JammingAnalysis{SamplesAnalyzed: len(samples), Thresholds: o}

	// Min / max / mean / std-dev.
	a.MinDbm, a.MaxDbm = samples[0], samples[0]
	var sum float64
	for _, v := range samples {
		if v < a.MinDbm {
			a.MinDbm = v
		}
		if v > a.MaxDbm {
			a.MaxDbm = v
		}
		sum += v
	}
	a.MeanDbm = sum / float64(len(samples))
	var ss float64
	for _, v := range samples {
		d := v - a.MeanDbm
		ss += d * d
	}
	a.StdDevDb = math.Sqrt(ss / float64(len(samples)))

	// Median + noise-floor percentile (over a sorted copy).
	sorted := make([]float64, len(samples))
	copy(sorted, samples)
	sort.Float64s(sorted)
	a.MedianDbm = percentile(sorted, 50)
	a.NoiseFloorDbm = percentile(sorted, o.FloorPercentile)

	// Occupancy + longest dwell above the busy threshold (in original order).
	busy := 0
	run, longest := 0, 0
	for _, v := range samples {
		if v >= o.BusyThresholdDbm {
			busy++
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	a.OccupancyFraction = float64(busy) / float64(len(samples))
	a.LongestDwellSamples = longest
	a.LongestDwellFraction = float64(longest) / float64(len(samples))

	// Observations (heuristic, with benign explanations).
	if a.NoiseFloorDbm >= o.ElevatedFloorDbm {
		a.Observations = append(a.Observations, JammingObservation{
			Kind: "elevated_noise_floor", Severity: "warning",
			Detail: fmt.Sprintf("noise floor %.1f dBm is at/above the %.1f dBm threshold — the channel idles at an elevated level. Benign: a strong nearby legitimate transmitter or a congested band.", a.NoiseFloorDbm, o.ElevatedFloorDbm),
		})
	}
	if a.OccupancyFraction >= o.OccupancyFlag {
		a.Observations = append(a.Observations, JammingObservation{
			Kind: "sustained_occupancy", Severity: "warning",
			Detail: fmt.Sprintf("%.0f%% of samples are at/above the %.1f dBm busy threshold (>= %.0f%%) — continuous rather than bursty energy. Benign: a legitimate continuous carrier (analogue video/audio link).", a.OccupancyFraction*100, o.BusyThresholdDbm, o.OccupancyFlag*100),
		})
	}
	if a.LongestDwellFraction >= o.DwellFlagFraction {
		a.Observations = append(a.Observations, JammingObservation{
			Kind: "long_dwell", Severity: "warning",
			Detail: fmt.Sprintf("the longest unbroken run above the busy threshold spans %d samples (%.0f%% of the capture, >= %.0f%%) — sustained dwell. Benign: same continuous-carrier explanation.", a.LongestDwellSamples, a.LongestDwellFraction*100, o.DwellFlagFraction*100),
		})
	}
	if len(a.Observations) == 0 {
		a.Notes = append(a.Notes, "no jamming indicators on the default heuristic — bursty, low-duty-cycle energy with a low noise floor (the normal-traffic profile).")
	} else {
		a.Notes = append(a.Notes, "observations are heuristic signals for correlation, not a jammer verdict; tune the thresholds to your band/hardware.")
	}
	return a, nil
}

// percentile returns the p-th percentile (0..100) of an already-sorted slice
// using linear interpolation between the closest ranks.
func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 1 {
		return sorted[0]
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	rank := p / 100 * float64(n-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo] + frac*(sorted[hi]-sorted[lo])
}
