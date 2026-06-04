// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"math"
	"testing"
)

func hasObs(a *JammingAnalysis, kind string) bool {
	for _, o := range a.Observations {
		if o.Kind == kind {
			return true
		}
	}
	return false
}

// Hand-computed statistics over a known ramp, verifying the math exactly.
func TestJammingStats(t *testing.T) {
	a, err := AnalyzeJamming([]float64{-100, -90, -80, -70, -60}, JammingOpts{})
	if err != nil {
		t.Fatalf("AnalyzeJamming: %v", err)
	}
	if a.MinDbm != -100 || a.MaxDbm != -60 || a.MeanDbm != -80 || a.MedianDbm != -80 {
		t.Errorf("min/max/mean/median = %v/%v/%v/%v, want -100/-60/-80/-80", a.MinDbm, a.MaxDbm, a.MeanDbm, a.MedianDbm)
	}
	if math.Abs(a.StdDevDb-math.Sqrt(200)) > 1e-9 { // sqrt(1000/5)=sqrt(200)=14.1421
		t.Errorf("stddev = %v, want %v", a.StdDevDb, math.Sqrt(200))
	}
	// 10th-percentile floor over [-100,-90,-80,-70,-60]: rank 0.4 -> -96.
	if math.Abs(a.NoiseFloorDbm-(-96)) > 1e-9 {
		t.Errorf("noise_floor = %v, want -96", a.NoiseFloorDbm)
	}
	// busy >= -80: {-80,-70,-60} = 3/5; they are the trailing run -> dwell 3.
	if math.Abs(a.OccupancyFraction-0.6) > 1e-9 {
		t.Errorf("occupancy = %v, want 0.6", a.OccupancyFraction)
	}
	if a.LongestDwellSamples != 3 {
		t.Errorf("longest_dwell = %d, want 3", a.LongestDwellSamples)
	}
}

// A continuous high carrier fires all three indicators.
func TestJammingContinuousCarrier(t *testing.T) {
	samples := make([]float64, 16)
	for i := range samples {
		samples[i] = -45
	}
	a, err := AnalyzeJamming(samples, JammingOpts{})
	if err != nil {
		t.Fatalf("AnalyzeJamming: %v", err)
	}
	if a.NoiseFloorDbm != -45 || a.OccupancyFraction != 1.0 || a.LongestDwellSamples != 16 {
		t.Errorf("floor/occ/dwell = %v/%v/%d, want -45/1/16", a.NoiseFloorDbm, a.OccupancyFraction, a.LongestDwellSamples)
	}
	for _, k := range []string{"elevated_noise_floor", "sustained_occupancy", "long_dwell"} {
		if !hasObs(a, k) {
			t.Errorf("missing observation %q on a continuous carrier", k)
		}
	}
}

// Bursty low-duty-cycle traffic (the normal profile) fires nothing.
func TestJammingNormalBursty(t *testing.T) {
	a, err := AnalyzeJamming([]float64{-105, -105, -105, -60, -105, -105, -105, -105, -62, -105}, JammingOpts{})
	if err != nil {
		t.Fatalf("AnalyzeJamming: %v", err)
	}
	if math.Abs(a.NoiseFloorDbm-(-105)) > 1e-9 {
		t.Errorf("noise_floor = %v, want -105", a.NoiseFloorDbm)
	}
	if math.Abs(a.OccupancyFraction-0.2) > 1e-9 {
		t.Errorf("occupancy = %v, want 0.2", a.OccupancyFraction)
	}
	if a.LongestDwellSamples != 1 {
		t.Errorf("longest_dwell = %d, want 1 (isolated bursts)", a.LongestDwellSamples)
	}
	if len(a.Observations) != 0 {
		t.Errorf("observations = %v, want none for normal bursty traffic", a.Observations)
	}
}

// Overridable thresholds are honoured and echoed.
func TestJammingCustomThresholds(t *testing.T) {
	// A moderate level that the default -80 busy threshold would miss but a
	// -95 threshold catches.
	samples := []float64{-90, -90, -90, -90}
	a, _ := AnalyzeJamming(samples, JammingOpts{BusyThresholdDbm: -95, ElevatedFloorDbm: -95, OccupancyFlag: 0.9, DwellFlagFraction: 0.9})
	if a.OccupancyFraction != 1.0 || !hasObs(a, "sustained_occupancy") {
		t.Errorf("custom busy threshold not applied: occ=%v obs=%v", a.OccupancyFraction, a.Observations)
	}
	if a.Thresholds.BusyThresholdDbm != -95 {
		t.Errorf("thresholds not echoed: %v", a.Thresholds)
	}
}

func TestJammingEmpty(t *testing.T) {
	if _, err := AnalyzeJamming(nil, JammingOpts{}); err == nil {
		t.Error("AnalyzeJamming(nil) = nil error, want rejection")
	}
}
