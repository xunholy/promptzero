// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package transport — darwin BLE stub.
//
// tinygo.org/x/bluetooth depends on github.com/tinygo-org/cbgo on darwin
// which uses Objective-C bindings and requires CGO + the macOS SDK. The
// cross-compile CI matrix builds darwin targets from a Linux host with
// CGO disabled, which fails with "undefined: CentralManager" errors from
// cbgo. We sidestep that by excluding the real BLE code on darwin (see
// the //go:build !darwin constraint on ble.go) and registering a
// friendly stub dialer here instead. A real macOS build with CGO
// enabled (`GOOS=darwin CGO_ENABLED=1 go build`) would link the full
// tinygo stack — at which point someone cares enough about Mac BLE to
// swap this stub out.

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
