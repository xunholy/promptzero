//go:build linux

package flipper_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// TestDetectApps_SDScanConfirmsExternalFAPs proves the /ext/apps scan pass:
// starting from stock defaults (all FAP flags false), the presence of the
// backing .fap files flips the matching capability flags true, while a FAP
// with no file on the SD card stays at its (false) default. This is the
// path that `loader list` alone cannot cover, since external FAPs never
// appear there.
func TestDetectApps_SDScanConfirmsExternalFAPs(t *testing.T) {
	listings := map[string]string{
		"/ext/apps/Bluetooth": "\t[F] ble_spam.fap 72784b\n\t[F] findmy.fap 23720b",
		"/ext/apps/NFC": "\t[F] seader.fap 131308b\n\t[F] picopass.fap 157528b\n" +
			"\t[F] mfkey.fap 38548b\n\t[F] nfc_magic.fap 92592b\n\t[D] subdir",
		"/ext/apps/Sub-GHz": "\t[F] subghz_bruteforcer.fap 62288b\n\t[F] tpms.fap 45168b",
	}
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return stockDeviceInfo }),
		mock.WithHandler("loader", func(_ []string) string { return "Apps:\n\tNFC\nSettings:\n" }),
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "list" {
				return listings[args[1]] // "" for categories we don't script
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	// Baseline: stock firmware leaves every FAP flag at its false default.
	pre := flip.Capabilities()
	if pre.HasBLESpam || pre.HasSeaderFAP || pre.HasSubGHzBruteforcer {
		t.Fatalf("expected stock defaults all false, got BLESpam=%v Seader=%v Bruteforcer=%v",
			pre.HasBLESpam, pre.HasSeaderFAP, pre.HasSubGHzBruteforcer)
	}

	flip.DetectApps()
	c := flip.Capabilities()

	for name, got := range map[string]bool{
		"HasBLESpam":           c.HasBLESpam,
		"HasSeaderFAP":         c.HasSeaderFAP,
		"HasPicopassFAP":       c.HasPicopassFAP,
		"HasMFKeyFAP":          c.HasMFKeyFAP,
		"HasNFCMagicFAP":       c.HasNFCMagicFAP,
		"HasSubGHzBruteforcer": c.HasSubGHzBruteforcer,
	} {
		if !got {
			t.Errorf("%s: expected true after /ext/apps scan, got false", name)
		}
	}

	// No mousejacker.fap was listed, so the flag must stay at its default.
	if c.HasMouseJackerFAP {
		t.Errorf("HasMouseJackerFAP: expected false (no backing .fap listed), got true")
	}
}
