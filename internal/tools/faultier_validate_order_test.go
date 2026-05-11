package tools

import (
	"strings"
	"testing"
)

// TestFaultierHandlers_ValidateBeforeTransport pins the v0.178 contract.
// Two Faultier handlers (glitch_set_pulse, glitch_sweep) previously checked
// RequireFaultier before validating their timing args, masking the actual
// defect behind "faultier not connected". Same defect class as the
// canbus v0.174/v0.175, buspirate v0.176, and Bruce v0.177 fixes.
//
// Also pins a new ordering invariant on glitch_sweep: end_us must be >=
// start_us, otherwise the response envelope's "steps" field carried a
// negative value via (endUS-startUS)/stepUS+1.
func TestFaultierHandlers_ValidateBeforeTransport(t *testing.T) {
	cases := []struct {
		spec   string
		args   map[string]any
		expect string
	}{
		{
			spec:   "glitch_set_pulse",
			args:   map[string]any{}, // both timings missing -> -1 sentinel
			expect: "delay_us must be >= 0",
		},
		{
			spec:   "glitch_set_pulse",
			args:   map[string]any{"delay_us": float64(10)}, // missing pulse_us
			expect: "pulse_us must be >= 0",
		},
		{
			spec:   "glitch_sweep",
			args:   map[string]any{"end_us": float64(100), "step_us": float64(10)},
			expect: "start_us must be >= 0",
		},
		{
			spec:   "glitch_sweep",
			args:   map[string]any{"start_us": float64(0), "step_us": float64(10)},
			expect: "end_us must be >= 0",
		},
		{
			spec:   "glitch_sweep",
			args:   map[string]any{"start_us": float64(0), "end_us": float64(100), "step_us": float64(0)},
			expect: "step_us must be > 0",
		},
		{
			spec: "glitch_sweep",
			// New v0.178 ordering invariant: end < start is rejected so
			// the response envelope's "steps" field can't go negative.
			args:   map[string]any{"start_us": float64(100), "end_us": float64(10), "step_us": float64(5)},
			expect: "end_us 10 must be >= start_us 100",
		},
	}
	for _, c := range cases {
		t.Run(c.spec+"_"+c.expect, func(t *testing.T) {
			spec, ok := Get(c.spec)
			if !ok {
				t.Fatalf("%s not registered", c.spec)
			}
			_, err := spec.Handler(t.Context(), &Deps{}, c.args)
			if err == nil {
				t.Fatalf("expected error; got nil")
			}
			if strings.Contains(err.Error(), "not connected") {
				t.Errorf("err = %v; want validation error before transport check", err)
			}
			if !strings.Contains(err.Error(), c.expect) {
				t.Errorf("err = %v; want substring %q", err, c.expect)
			}
		})
	}
}
