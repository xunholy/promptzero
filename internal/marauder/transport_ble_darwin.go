// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package marauder — darwin BLE stub for CGO-disabled builds.
//
// tinygo.org/x/bluetooth depends on github.com/tinygo-org/cbgo on darwin which
// uses Objective-C bindings and requires CGO + the macOS SDK. When CGO is
// disabled (cross-compiled darwin builds on a Linux runner) cbgo fails with
// "undefined: CentralManager", so we ship a friendly stub here that returns a
// clear error from ConnectBLE. A native macOS build with CGO enabled compiles
// transport_ble.go instead (see its //go:build constraint).

//go:build darwin && !cgo

package marauder

import (
	"context"
	"fmt"
	"time"
)

// dialMarauderBLE is the darwin/no-CGO stub. Returns the same shape as the
// real implementation so the public ConnectBLE entry point compiles on every
// permutation.
func dialMarauderBLE(_ context.Context, _ string) (*marauderBLEPort, error) {
	return nil, fmt.Errorf("marauder/ble: darwin BLE requires a macOS build with CGO enabled (GOOS=darwin CGO_ENABLED=1 go build). Cross-compiled darwin binaries do not include BLE")
}

// marauderBLEPort is a placeholder type that lets the rest of the package
// compile under this build configuration. It is never instantiated — the
// stub dialMarauderBLE always errors out before construction.
type marauderBLEPort struct{}

// Read / Write / Close / SetReadTimeout satisfy the marauder.Port interface so
// the unused type still type-checks if anything in the package references it.
func (*marauderBLEPort) Read(_ []byte) (int, error)  { return 0, fmt.Errorf("marauder/ble: stub") }
func (*marauderBLEPort) Write(_ []byte) (int, error) { return 0, fmt.Errorf("marauder/ble: stub") }
func (*marauderBLEPort) Close() error                { return nil }
func (*marauderBLEPort) SetReadTimeout(_ time.Duration) error {
	return fmt.Errorf("marauder/ble: stub")
}
