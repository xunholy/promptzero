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

// TestStorageErrorBanner pins every recognised firmware-status →
// human-readable banner mapping. The CLI emits banners like
// "Storage error: not exist\n" so callers (notably ParseStorageStat
// in parse.go) can match against a stable text form regardless of
// which transport surfaced the error. A regression here would
// silently classify errors as the catch-all "Storage error: <raw
// msg>" fallback, breaking those parsers.
func TestStorageErrorBanner(t *testing.T) {
	tests := []struct {
		errMsg string
		want   string
	}{
		{"wrapped: ERROR_STORAGE_NOT_EXIST: file missing", "Storage error: not exist\n"},
		{"wrapped: ERROR_STORAGE_NOT_READY: sd unmounted", "Storage error: not ready\n"},
		{"wrapped: ERROR_STORAGE_DENIED: write protected", "Storage error: denied\n"},
		{"wrapped: ERROR_STORAGE_INVALID_NAME: bad path", "Storage error: invalid name\n"},
		{"wrapped: ERROR_STORAGE_INVALID_PARAMETER: bad arg", "Storage error: invalid parameter\n"},
		{"wrapped: ERROR_STORAGE_EXIST: already there", "Storage error: already exist\n"},
		{"wrapped: ERROR_STORAGE_INTERNAL: fs glitch", "Storage error: internal\n"},
		{"wrapped: ERROR_STORAGE_NOT_IMPLEMENTED: rpc-only", "Storage error: not implemented\n"},
		{"wrapped: ERROR_STORAGE_ALREADY_OPEN: locked", "Storage error: already open\n"},
		{"wrapped: ERROR_STORAGE_DIR_NOT_EMPTY: rmdir failed", "Storage error: dir not empty\n"},

		// Unmatched errors fall through to the catch-all form.
		{"unrelated network error", "Storage error: unrelated network error\n"},
		{"", "Storage error: \n"},
	}
	for _, tc := range tests {
		err := errors.New(tc.errMsg)
		if got := storageErrorBanner(err); got != tc.want {
			t.Errorf("storageErrorBanner(%q) = %q, want %q", tc.errMsg, got, tc.want)
		}
	}
}

// TestRFIDDetectionLine pins the streamed-line classifier used by
// the RFID-read tool to decide which lines are tag detections vs
// scanner banner / status. The "Reading 125 kHz RFID..." startup
// banner must NOT be classified as a detection.
func TestRFIDDetectionLine(t *testing.T) {
	detections := []string{
		"EM4100  data: 1234567890",
		"em-410x detected",
		"HIDProx card",
		"HID Prox H10301",
		"H10301 facility:1 card:42",
		"Indala 1234",
		"AWID",
		"FDX-A",
		"FDX-B",
		"Pyramid",
		"Viking",
		"IOProx",
		"Jablotron",
		"Paradox",
		"NexWatch",
		"Presco",
		"Keri",
		"Data: deadbeef",
		"Key: 1234",
		"Card id: 42",
		"Facility: 7",
	}
	for _, line := range detections {
		if !rfidDetectionLine(line) {
			t.Errorf("rfidDetectionLine(%q) = false, want true (recognised detection)", line)
		}
	}

	nonDetections := []string{
		"Reading 125 kHz RFID...",
		"reading rfid",
		"Press EXIT to stop",
		"",
		"  ",
		"vibro 1",
	}
	for _, line := range nonDetections {
		if rfidDetectionLine(line) {
			t.Errorf("rfidDetectionLine(%q) = true, want false (not a detection)", line)
		}
	}
}

// TestSanitizeArg pins the exported wrapper that the agent's
// inline bruteforce dispatch calls when it builds Flipper CLI
// commands directly. Delegates to clisafe.SanitizeArg; the strip-
// set is CR / LF / NUL / ETX / double-quote.
func TestSanitizeArg(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"with\rCR", "withCR"},
		{"with\nLF", "withLF"},
		{"with\x00NUL", "withNUL"},
		{"with\x03ETX", "withETX"},
		{`with"quote`, "withquote"},
		{"two words", "two words"}, // spaces preserved
		{"a\rb\nc\x00d\"e", "abcde"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := SanitizeArg(tc.in); got != tc.want {
			t.Errorf("SanitizeArg(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
