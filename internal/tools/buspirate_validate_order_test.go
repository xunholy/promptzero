package tools

import (
	"strings"
	"testing"
)

// TestBuspirateHandlers_ValidateBeforeTransport pins the v0.176 contract.
// Five buspirate handlers (mode, spi_dump, uart_bridge, pin_set, pin_read)
// previously checked RequireBusPirate before validating their args, so a
// missing/invalid argument masqueraded as "bus pirate 5 not connected" —
// sending the LLM to chase a transport fix it can't perform.
//
// Same defect class fixed for canbus handlers in v0.174/v0.175.
func TestBuspirateHandlers_ValidateBeforeTransport(t *testing.T) {
	cases := []struct {
		spec   string
		args   map[string]any
		expect string // substring the error must contain
	}{
		{
			spec:   "buspirate_mode",
			args:   map[string]any{}, // missing name
			expect: "name is required",
		},
		{
			spec:   "buspirate_spi_dump",
			args:   map[string]any{"n": float64(0)},
			expect: "n must be > 0",
		},
		{
			spec:   "buspirate_uart_bridge",
			args:   map[string]any{"send_hex": "ZZZZ"}, // not hex
			expect: "send_hex",
		},
		{
			spec:   "buspirate_pin_set",
			args:   map[string]any{"pin": float64(99), "value": float64(1)},
			expect: "pin must be 1-8",
		},
		{
			spec:   "buspirate_pin_set",
			args:   map[string]any{"pin": float64(0), "value": float64(1)},
			expect: "pin must be 1-8",
		},
		{
			spec:   "buspirate_pin_read",
			args:   map[string]any{"pin": float64(9)},
			expect: "pin must be 1-8",
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
