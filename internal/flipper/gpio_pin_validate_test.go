package flipper

import (
	"strings"
	"testing"
)

// TestGPIOSet_RejectsUnknownPin pins the v0.180 contract: pin is
// validated against gpioPinByName on the CLI path before any dispatch.
// Pre-fix only the RPC path validated the pin name; the CLI path
// forwarded any string through sanitizeArg, reaching the firmware as
// an opaque "unknown pin" or silent no-op.
//
// We use Flipper{} with no transport on purpose: pin validation must
// run BEFORE dispatch, so the test never reaches the panic path of
// trying to send to a nil transport (which is exactly the symptom of
// the pre-fix code path).
func TestGPIOSet_RejectsUnknownPin(t *testing.T) {
	f := &Flipper{}
	bad := []string{
		"not_a_pin",
		"PA77",  // off-by-one typo
		"PA1",   // not in Flipper's exposed set
		"PD0",   // wrong port letter
		"GPIO5", // wrong nomenclature
		"",      // empty
	}
	for _, pin := range bad {
		t.Run(pin, func(t *testing.T) {
			_, err := f.GPIOSet(pin, 1)
			if err == nil {
				t.Fatalf("expected error for pin %q; got nil", pin)
			}
			if !strings.Contains(err.Error(), "invalid GPIO pin") {
				t.Errorf("err = %v; want 'invalid GPIO pin' validation error before dispatch", err)
			}
		})
	}
}

// TestGPIORead_RejectsUnknownPin mirrors the GPIOSet contract for the
// read path. Same allowlist, same pre-dispatch check.
func TestGPIORead_RejectsUnknownPin(t *testing.T) {
	f := &Flipper{}
	bad := []string{"badpin", "PA1", "PD0", ""}
	for _, pin := range bad {
		t.Run(pin, func(t *testing.T) {
			_, err := f.GPIORead(pin)
			if err == nil {
				t.Fatalf("expected error for pin %q; got nil", pin)
			}
			if !strings.Contains(err.Error(), "invalid GPIO pin") {
				t.Errorf("err = %v; want 'invalid GPIO pin' validation error", err)
			}
		})
	}
}
