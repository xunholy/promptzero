package buspirate

import (
	"context"
	"strings"
	"testing"
)

// PinSet and PinRead now validate the pin index against the Bus
// Pirate 5 IO range (0-7). Pre-fix, an LLM picking pin=99 saw the
// firmware silently no-op the `D 99 1` / `a 99` command.

func TestValidatePin(t *testing.T) {
	for pin := 0; pin <= 7; pin++ {
		if err := validatePin(pin); err != nil {
			t.Errorf("validatePin(%d) = %v; want nil", pin, err)
		}
	}
	for _, pin := range []int{-1, -100, 8, 99, 1000} {
		if err := validatePin(pin); err == nil {
			t.Errorf("validatePin(%d) = nil; want error", pin)
		}
	}
}

func TestPinSet_RejectsOutOfRangePin(t *testing.T) {
	c, _ := newTestClient(t)
	for _, pin := range []int{-1, 8, 99, 200} {
		err := c.PinSet(context.Background(), pin, true)
		if err == nil {
			t.Errorf("expected error for pin=%d; got nil", pin)
			continue
		}
		if !strings.Contains(err.Error(), "pin") {
			t.Errorf("pin=%d err = %v; want pin validation error", pin, err)
		}
	}
}

func TestPinRead_RejectsOutOfRangePin(t *testing.T) {
	c, _ := newTestClient(t)
	for _, pin := range []int{-1, 8, 99, 200} {
		_, err := c.PinRead(context.Background(), pin)
		if err == nil {
			t.Errorf("expected error for pin=%d; got nil", pin)
			continue
		}
		if !strings.Contains(err.Error(), "pin") {
			t.Errorf("pin=%d err = %v; want pin validation error", pin, err)
		}
	}
}
