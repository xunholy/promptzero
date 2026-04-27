// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Direct-connect fallback for every build configuration that does NOT
// have native CoreBluetooth (darwin without CGO, plus all non-darwin
// platforms). These targets always go through the scan path: Linux and
// Windows because they don't gain anything from "skip scan" — the OS
// returns hardware MACs that the rest of the transport already knows
// how to match — and darwin-without-CGO because the BLE stub in
// ble_darwin.go shadows the real transport entirely.
//
// Build constraint mirrors ble.go's so this file is built whenever the
// real BLE implementation is, but only when the darwin-specific
// CoreBluetooth path is unavailable.

//go:build !darwin

package transport

import "tinygo.org/x/bluetooth"

// tryDirectConnectAddr is a no-op on non-darwin builds. The scan path
// is the canonical resolver on Linux/Windows; there is no equivalent
// of CoreBluetooth's retrievePeripherals(withIdentifiers:) to skip
// scanning against.
func tryDirectConnectAddr(_ string) (bluetooth.Address, bool) {
	return bluetooth.Address{}, false
}
