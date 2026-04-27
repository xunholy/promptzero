// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Direct-connect fallback for every build configuration that does NOT have
// native CoreBluetooth (all non-darwin platforms). Linux/Windows always go
// through the scan path: their OSes return hardware MACs that the rest of the
// transport already knows how to match — there is no equivalent of
// CoreBluetooth's retrievePeripherals(withIdentifiers:) to skip scanning
// against.
//
// darwin without CGO is handled by transport_ble_darwin.go (which short-circuits
// before tryDirectConnectAddrMarauder is ever called), so this file only
// guards against non-darwin builds.

//go:build !darwin

package marauder

import "tinygo.org/x/bluetooth"

// tryDirectConnectAddrMarauder is a no-op on non-darwin builds.
func tryDirectConnectAddrMarauder(_ string) (bluetooth.Address, bool) {
	return bluetooth.Address{}, false
}
