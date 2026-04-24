package flipper

import "strings"

// DetectApps queries the connected Flipper's FAP (Flipper App Package) list via
// `loader list` and updates the capability flags for app-presence fields
// (HasBLESpam, HasSubGHzBruteforcer, HasMouseJackerFAP, etc.).
//
// This is a best-effort probe: if `loader list` fails or times out, the FAP
// flags retain their fork-typical static defaults from detectCapabilities (set
// conservatively for Unleashed and optimistically for RogueMaster per
// firmware-matrix.md §6 Q8). A failed probe never propagates an error — the
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

	f.caps.Store(&caps)
}
