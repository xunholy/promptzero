package flipper

import "strings"

// DetectApps updates the FAP (Flipper App Package) capability flags
// (HasBLESpam, HasSubGHzBruteforcer, HasMouseJackerFAP, etc.) by probing the
// connected device two ways:
//
//  1. `loader list` — catches apps that are in-tree / menu-registered on the
//     running fork (e.g. MFKey on Unleashed).
//  2. A scan of /ext/apps/<category>/ for the backing `.fap` files — catches
//     EXTERNAL FAPs, which never appear in `loader list` (verified on
//     momentum/mntm-dev 2026-05-30: `loader list` returns only the built-in
//     menu apps, while the real apps live under /ext/apps/Bluetooth,
//     /ext/apps/NFC, /ext/apps/Sub-GHz, …). Without this scan the FAP flags
//     are never actually confirmed against what is installed.
//
// Both passes are ADDITIVE: a flag is only ever set true, never cleared. An
// incomplete category/filename map therefore degrades to the fork-typical
// static defaults from detectCapabilities (conservative for Unleashed,
// optimistic for RogueMaster per firmware-matrix.md §6 Q8) and can never
// produce a false negative. A failed probe never propagates an error — the
// device_info parse is the authoritative signal for fork/version detection.
//
// Integration note: DetectApps should be called from DetectCapabilities
// (serial.go) after the device_info parse and initial caps.Store. Since
// serial.go is managed by the transport layer (not in this engineer's write
// scope for v0.5), callers may invoke DetectApps() independently after
// DetectCapabilities() when FAP-presence accuracy is required. The
// firmware_introspect Handler (internal/tools/firmware.go) calls it when
// refresh=true.
//
// Name-to-flag mapping (firmware-matrix.md §4.3):
//
//	"BLE Spam"           → HasBLESpam
//	"SubGHz Bruteforcer" → HasSubGHzBruteforcer
//	"Sub-GHz BF"         → HasSubGHzBruteforcer (alternate name on some forks)
//	"NRF24 Mousejacker"  → HasMouseJackerFAP
//	"Seader"             → HasSeaderFAP
//	"PicoPass"           → HasPicopassFAP
//	"NFC Magic"          → HasNFCMagicFAP
//	"MFKey"              → HasMFKeyFAP   (Unleashed in-tree path)
//	"MFKey32"            → HasMFKeyFAP   (RM/Momentum external FAP)
//	"Mifare Nested"      → HasMifareNestedFAP
func (f *Flipper) DetectApps() {
	apps, err := f.LoaderListParsed()
	if err != nil {
		// Best-effort: leave fork-typical static defaults unchanged.
		return
	}

	// Take a copy of the current caps, update FAP flags, then swap the
	// pointer atomically so concurrent Capabilities() reads see a
	// consistent snapshot.
	caps := f.Capabilities()

	for _, app := range apps.Apps {
		name := strings.TrimSpace(app)
		switch name {
		case "BLE Spam":
			caps.HasBLESpam = true
		case "SubGHz Bruteforcer", "Sub-GHz BF":
			caps.HasSubGHzBruteforcer = true
		case "NRF24 Mousejacker":
			caps.HasMouseJackerFAP = true
		case "Seader":
			caps.HasSeaderFAP = true
		case "PicoPass":
			caps.HasPicopassFAP = true
		case "NFC Magic":
			caps.HasNFCMagicFAP = true
		case "MFKey", "MFKey32":
			caps.HasMFKeyFAP = true
		case "Mifare Nested":
			caps.HasMifareNestedFAP = true
		}
	}

	// Pass 2: scan /ext/apps/<category>/ for the backing .fap files. External
	// FAPs never surface in `loader list`, so this is the only signal that
	// confirms them. Additive only — presence flips a flag true; absence
	// leaves the static default untouched (an incomplete map can't regress).
	fapToFlag := map[string]*bool{
		"ble_spam.fap":           &caps.HasBLESpam,
		"seader.fap":             &caps.HasSeaderFAP,
		"picopass.fap":           &caps.HasPicopassFAP,
		"nfc_magic.fap":          &caps.HasNFCMagicFAP,
		"mfkey.fap":              &caps.HasMFKeyFAP,
		"mfkey32.fap":            &caps.HasMFKeyFAP,
		"nested.fap":             &caps.HasMifareNestedFAP,
		"mfkey_nested.fap":       &caps.HasMifareNestedFAP,
		"subghz_bruteforcer.fap": &caps.HasSubGHzBruteforcer,
		"subbrute.fap":           &caps.HasSubGHzBruteforcer,
		"nrf24_mousejacker.fap":  &caps.HasMouseJackerFAP,
		"mousejacker.fap":        &caps.HasMouseJackerFAP,
	}
	for _, cat := range []string{"Bluetooth", "NFC", "Sub-GHz", "GPIO", "GPIO/NRF24"} {
		listing, err := f.StorageList("/ext/apps/" + cat)
		if err != nil {
			continue // category absent on this fork/SD — fall back to defaults
		}
		for _, fap := range parseFapNames(listing) {
			if flag, ok := fapToFlag[fap]; ok {
				*flag = true
			}
		}
	}

	f.caps.Store(&caps)
}

// parseFapNames extracts the .fap filenames from a `storage list` listing.
// Each file entry is "[F] <name> <size>b" (leading whitespace tolerated);
// directory entries ("[D] <name>") are skipped.
func parseFapNames(listing string) []string {
	var out []string
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "[F]" && strings.HasSuffix(fields[1], ".fap") {
			out = append(out, fields[1])
		}
	}
	return out
}
