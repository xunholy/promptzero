package flipper

import (
	"errors"
	"testing"

	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
)

// TestMomentumDumpProtocolToken pins the canonical → Momentum-token map.
// Validated against real Momentum hardware: the verbose canonical names
// (e.g. "Mifare_Classic") are rejected by Momentum's `dump -p` parser
// with `Unable to parse value 'Mifare_Classic' for key 'p'`. The short
// tokens (mfc/mfu/mfp/felica) are what the firmware actually accepts.
// New protocol names should be added here in lockstep with the wrapper.
func TestMomentumDumpProtocolToken(t *testing.T) {
	cases := map[string]string{
		"Mifare_Classic":    "mfc",
		"mifare_classic":    "mfc",
		"Mifare Classic":    "mfc",
		"classic":           "mfc",
		"Mifare_Ultralight": "mfu",
		"NTAG215":           "mfu",
		"Mifare_Plus":       "mfp",
		"FeliCa":            "felica",
		"unknown_proto":     "unknown_proto",
	}
	for in, want := range cases {
		if got := momentumDumpProtocolToken(in); got != want {
			t.Errorf("momentumDumpProtocolToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGPIOPinByName covers the case-insensitive name → enum map used by
// the BLE-RPC GPIO branches. The mapping itself is generated from
// pb.GpioPin_value, so the test pins the trim/case behaviour and the
// "unknown pin" sentinel rather than re-asserting the firmware enum
// values.
func TestGPIOPinByName(t *testing.T) {
	cases := []struct {
		in     string
		want   pb.GpioPin
		wantOK bool
	}{
		{"PA7", pb.GpioPin_PA7, true},
		{"pa7", pb.GpioPin_PA7, true},
		{"  PA7 ", pb.GpioPin_PA7, true},
		{"PC0", pb.GpioPin_PC0, true},
		{"PB3", pb.GpioPin_PB3, true},
		{"", 0, false},
		{"P99", 0, false},
		{"GPIO_PA7", 0, false},
	}
	for _, tc := range cases {
		got, ok := gpioPinByName(tc.in)
		if ok != tc.wantOK {
			t.Errorf("gpioPinByName(%q) ok=%v, want %v", tc.in, ok, tc.wantOK)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("gpioPinByName(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestDesktopAndPropertyUSBOnly asserts the BLE-only methods surface
// the documented USB-only error when the transport is USB (i.e.
// IsBLE() is false on a freshly-zeroed Flipper). The error must wrap
// ErrCommandRequiresUSB so callers using errors.Is keep working.
func TestDesktopAndPropertyUSBOnly(t *testing.T) {
	f := &Flipper{} // zero value: transport == nil, IsBLE() == false

	t.Run("DesktopIsLocked", func(t *testing.T) {
		_, err := f.DesktopIsLocked()
		if err == nil {
			t.Fatal("expected error on USB transport")
		}
		if !errors.Is(err, ErrCommandRequiresUSB) {
			t.Errorf("got %v, want errors.Is ErrCommandRequiresUSB", err)
		}
	})
	t.Run("DesktopUnlock", func(t *testing.T) {
		err := f.DesktopUnlock()
		if err == nil {
			t.Fatal("expected error on USB transport")
		}
		if !errors.Is(err, ErrCommandRequiresUSB) {
			t.Errorf("got %v, want errors.Is ErrCommandRequiresUSB", err)
		}
	})
	t.Run("PropertyGet", func(t *testing.T) {
		_, err := f.PropertyGet("")
		if err == nil {
			t.Fatal("expected error on USB transport")
		}
		if !errors.Is(err, ErrCommandRequiresUSB) {
			t.Errorf("got %v, want errors.Is ErrCommandRequiresUSB", err)
		}
	})
}
