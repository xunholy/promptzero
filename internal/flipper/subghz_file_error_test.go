//go:build linux

package flipper_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// TestSubGHzTx_SurfacesFileOpenError pins the v0.370 fix: a missing/
// unreadable .sub file is reported by firmware on stdout with NO CLI error
// (verified momentum/mntm-dev: "subghz tx_from_file: Error open file ..."),
// so a failed transmit must not read as success.
func TestSubGHzTx_SurfacesFileOpenError(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("subghz", func(args []string) string {
			// tx_from_file of a missing file: keystore banners then the error.
			return "Load_keystore keeloq_mfcodes OK\n" +
				"subghz tx_from_file: Error open file /ext/subghz/missing.sub"
		}),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.SubGHzTx("/ext/subghz/missing.sub")
	if err == nil {
		t.Fatal("expected a Go error for a missing .sub file; transmit reported success")
	}
	if !strings.Contains(err.Error(), "Error open file") {
		t.Errorf("err = %v; want the firmware's file-open banner surfaced", err)
	}
}

// TestSubGHzTx_SuccessHasNoError confirms a normal transmit (no error
// banner) does not get a spurious file error from the detector.
func TestSubGHzTx_SuccessHasNoError(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("subghz", func(args []string) string {
			return "Load_keystore keeloq_mfcodes OK\nSending..."
		}),
	)
	flip := connectAndDetect(t, m)

	if _, err := flip.SubGHzTx("/ext/subghz/real.sub"); err != nil {
		t.Errorf("unexpected error on a clean transmit: %v", err)
	}
}
