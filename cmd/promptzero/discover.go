// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/transport"
)

// runBLEDiscover handles the --ble-discover early-exit flag. It scans
// for nearby BLE peripherals for the requested duration and prints a
// human-readable table of addresses, names, and RSSI — the canonical
// "find my Flipper's identifier" UX.
//
// The output also includes a copy-pasteable example command using the
// strongest-RSSI peripheral, with the right URL form for the host OS:
// MAC on Linux/Windows, CoreBluetooth UUID on darwin. This is the
// equivalent of running `bleak --scan` or `core-bluetooth-tool
// devices` and saves operators from grepping debug logs.
func runBLEDiscover(duration time.Duration) error {
	if duration <= 0 {
		duration = 8 * time.Second
	}

	fmt.Printf("\n  %sScanning for BLE peripherals for %s...%s\n\n", dim, duration, reset)

	ctx, cancel := context.WithTimeout(context.Background(), duration+5*time.Second)
	defer cancel()

	devices, err := transport.Discover(ctx, duration)
	if err != nil {
		return fmt.Errorf("ble-discover: %w", err)
	}
	if len(devices) == 0 {
		fmt.Printf("  %sNo peripherals heard.%s Make sure Bluetooth is on and other\n", yellow, reset)
		fmt.Printf("  devices are advertising. On macOS, an active scan from\n")
		fmt.Printf("  System Settings > Bluetooth can also surface nearby devices.\n\n")
		return nil
	}

	addrLabel := "ADDRESS (MAC)"
	if runtime.GOOS == "darwin" {
		addrLabel = "ADDRESS (CoreBluetooth UUID — local to this Mac)"
	}

	fmt.Printf("  %s%-22s  %-44s  %s%s\n", bold, "NAME", addrLabel, "RSSI", reset)
	fmt.Printf("  %s%s%s\n", dim, divider(22+2+44+2+5), reset)
	for _, d := range devices {
		name := d.Name
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Printf("  %-22s  %-44s  %4d dBm\n", truncate(name, 22), d.Address, d.RSSI)
	}

	// Pick a candidate to suggest: prefer one with name "Unholy" (this
	// repo's pet Flipper), then any name containing "Flipper", then
	// the strongest signal. Helps the user paste a working command
	// without manually scanning the output.
	candidate := pickFlipperCandidate(devices)
	fmt.Printf("\n  %sTo connect to a peripheral, pass its address as a ble:// URL:%s\n", bold, reset)
	fmt.Printf("    promptzero --transport \"ble://%s\"\n", candidate.Address)
	if runtime.GOOS == "darwin" {
		fmt.Printf("\n  %sNote: macOS hides hardware MACs and gives apps a per-Mac\n", dim)
		fmt.Printf("  CoreBluetooth UUID instead. The address above is stable on\n")
		fmt.Printf("  this Mac for the lifetime of the pairing, but different on\n")
		fmt.Printf("  every other Mac.%s\n", reset)
	}
	fmt.Println()
	return nil
}

// pickFlipperCandidate returns the device most likely to be a Flipper
// (name match wins; otherwise strongest RSSI). devices is assumed to
// be already sorted strongest-first.
func pickFlipperCandidate(devices []transport.DiscoveredDevice) transport.DiscoveredDevice {
	for _, d := range devices {
		if d.Name == "Unholy" || containsFold(d.Name, "Flipper") {
			return d
		}
	}
	return devices[0]
}

func containsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	lo := toLower(s)
	subLo := toLower(sub)
	for i := 0; i+len(subLo) <= len(lo); i++ {
		if lo[i:i+len(subLo)] == subLo {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func divider(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}
