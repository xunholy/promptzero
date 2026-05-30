package flipper

import (
	"strings"
	"testing"
	"time"
)

// TestValidateSubGHzFreq pins the CC1101 band gate now shared by the
// receive/chat paths (previously only the transmit path validated, so an
// out-of-band `subghz rx` came back as a firmware error banner on stdout
// with no Go error — verified momentum/mntm-dev 2026-05-31).
func TestValidateSubGHzFreq(t *testing.T) {
	valid := []uint32{
		300_000_000, 315_000_000, 348_000_000, // band 1 + upper edge
		387_000_000, 433_920_000, 464_000_000, // band 2
		779_000_000, 868_350_000, 915_000_000, 928_000_000, // band 3
	}
	for _, f := range valid {
		if err := validateSubGHzFreq(f); err != nil {
			t.Errorf("freq %d Hz should be valid: %v", f, err)
		}
	}
	invalid := []uint32{
		0, 100_000_000,
		360_000_000, // in the 348-387 MHz gap
		500_000_000, // in the 464-779 MHz gap
		999_000_000, 2_400_000_000,
	}
	for _, f := range invalid {
		if err := validateSubGHzFreq(f); err == nil {
			t.Errorf("freq %d Hz should be rejected", f)
		}
	}
}

// TestSubGHzRx_RejectsOutOfBandBeforeDispatch confirms the receive path
// validates the frequency before touching the transport — the bug was that
// it didn't, and the firmware error was returned as a successful result.
// A nil-transport Flipper never reaches dispatch because validation fails
// first.
func TestSubGHzRx_RejectsOutOfBandBeforeDispatch(t *testing.T) {
	f := &Flipper{}
	for _, fn := range []struct {
		name string
		call func() (string, error)
	}{
		{"SubGHzRx", func() (string, error) { return f.SubGHzRx(999_000_000, time.Second) }},
		{"SubGHzChat", func() (string, error) { return f.SubGHzChat(100_000_000, time.Second) }},
	} {
		_, err := fn.call()
		if err == nil {
			t.Errorf("%s: expected out-of-band error before dispatch, got nil", fn.name)
			continue
		}
		if !strings.Contains(err.Error(), "allowed bands") {
			t.Errorf("%s: err = %v; want band-list diagnostic", fn.name, err)
		}
	}
}
