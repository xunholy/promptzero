// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package transport — darwin BLE stub for CGO-disabled builds.
//
// tinygo.org/x/bluetooth depends on github.com/tinygo-org/cbgo on darwin
// which uses Objective-C bindings and requires CGO + the macOS SDK. When
// CGO is disabled (cross-compiled darwin builds on a Linux runner) cbgo
// fails with "undefined: CentralManager", so we register a friendly stub
// dialer here that returns a clear error. A native macOS build with CGO
// enabled compiles ble.go instead (see its //go:build constraint) and
// links the full tinygo stack.

//go:build darwin && !cgo

package transport

import (
	"fmt"
)

func init() {
	Register("ble", bleDialerDarwin)
}

// bleDialerDarwin returns a clear error instead of a partial BLE
// implementation. Match the shape of the non-darwin dialer's error
// messages so operator-facing text is consistent.
func bleDialerDarwin(url string) (Transport, error) {
	return nil, fmt.Errorf("transport/ble: darwin BLE requires a macOS build with CGO enabled (GOOS=darwin CGO_ENABLED=1 go build). Cross-compiled darwin binaries do not include BLE")
}
