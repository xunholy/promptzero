// SPDX-License-Identifier: AGPL-3.0-or-later
//
// darwin direct-connect helper. tinygo.org/x/bluetooth's Adapter.Connect on
// darwin wraps cbgo.RetrievePeripheralsWithIdentifiers, which lets a previously
// seen CoreBluetooth peripheral identifier UUID be reconnected without
// rescanning — the same pattern Apple recommends in "Best Practices for
// Interacting with a Remote Peripheral Device". Address.Set parses the UUID
// into the bluetooth.Address type tinygo uses on darwin (which embeds a UUID
// rather than a MAC).

//go:build darwin && cgo

package marauder

import "tinygo.org/x/bluetooth"

// tryDirectConnectAddrMarauder returns a bluetooth.Address constructed from a
// stored CoreBluetooth identifier UUID, suitable for passing straight to
// Adapter.Connect. The bool is false when the input doesn't parse as a UUID,
// in which case the caller should fall back to a scan.
func tryDirectConnectAddrMarauder(uuidStr string) (bluetooth.Address, bool) {
	if _, err := bluetooth.ParseUUID(uuidStr); err != nil {
		return bluetooth.Address{}, false
	}
	var a bluetooth.Address
	a.Set(uuidStr)
	return a, true
}
