package flipper

import (
	"math"
	"strings"
	"testing"
)

// IRTxRaw validates frequency and duty cycle before transport. Prior to
// the fix, both fields were forwarded verbatim to the firmware — an LLM
// passing 0 frequency or 2.5 duty cycle would either silently no-op or
// surface as an opaque firmware error several seconds later.
func TestIRTxRaw_RejectsAbsurdFrequency(t *testing.T) {
	f := &Flipper{}
	cases := []uint32{0, 1, 9999, 56001, 100000}
	for _, freq := range cases {
		_, err := f.IRTxRaw(freq, 0.33, "100 200")
		if err == nil {
			t.Errorf("expected error for frequency=%d; got nil", freq)
			continue
		}
		if !strings.Contains(err.Error(), "frequency") {
			t.Errorf("freq=%d err = %v; want frequency validation error", freq, err)
		}
	}
}

func TestIRTxRaw_RejectsDutyCycleOutOfRange(t *testing.T) {
	cases := []float64{-0.1, 0, 1.1, math.NaN(), math.Inf(1), math.Inf(-1)}
	f := &Flipper{}
	for _, dc := range cases {
		_, err := f.IRTxRaw(38000, dc, "100 200")
		if err == nil {
			t.Errorf("expected error for duty_cycle=%v; got nil", dc)
			continue
		}
		if !strings.Contains(err.Error(), "duty") {
			t.Errorf("dc=%v err = %v; want duty cycle validation error", dc, err)
		}
	}
}

func TestIRTxRaw_RejectsEmptyData(t *testing.T) {
	f := &Flipper{}
	for _, data := range []string{"", "   ", "\t\n"} {
		_, err := f.IRTxRaw(38000, 0.33, data)
		if err == nil {
			t.Errorf("expected error for data=%q; got nil", data)
			continue
		}
		if !strings.Contains(err.Error(), "data") {
			t.Errorf("data=%q err = %v; want data validation error", data, err)
		}
	}
}
