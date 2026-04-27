package flipper

import (
	"fmt"
	"strings"
)

// This file owns the firmware-compatibility / command-routing decision
// for Flipper command wrappers. The motivation is to centralise the
// hand-rolled `if f.IsBLE() { return f.xViaRPC(...) }; return f.Exec(...)`
// pattern that has spread across ~27 wrappers in commands.go. As we add
// commands or new firmware quirks the duplication compounds; routing
// the call through a single table-driven function lets future commands
// declare WHAT they want (an RPC verb? a CLI string? a fork-gated
// feature?) and leave HOW to dispatch to one decision function.
//
// Phase A (this file) introduces the types, the decision function,
// and migrates three proof-of-concept commands (DeviceInfo, PowerInfo,
// Reboot). The remaining ~24 commands keep their inline dispatch and
// are migrated in Phase B.
//
// Layering rule: this file is pure logic. It MUST NOT import the
// rpc/transport packages or call any *Flipper method. The single
// helper that wires a RouteDecision to actual viaCLI/viaRPC closures
// (Flipper.dispatch) lives in serial.go alongside the transport-aware
// Flipper handle.
//
// Reference reading: V3SP3R's FirmwareCompatibilityProfile.kt informed
// the route-enum shape; their `assessCliCommand` is too tied to Kotlin
// idioms (sealed-class result, suspend funs) to translate directly.

// CommandRoute enumerates the dispatch paths a Flipper command can
// take. The set is closed: every (transport, support) pair in
// RouteFor must resolve to one of these values.
type CommandRoute int

const (
	// RouteTextCLI sends the command as plain text down the serial
	// channel and parses the firmware's `>: ` prompt response. This
	// is the default route for USB transports where the firmware
	// exposes a text CLI.
	RouteTextCLI CommandRoute = iota
	// RouteRPC streams a protobuf request through the persistent
	// rpc.Client. This is the default route for BLE transports — the
	// firmware exposes ONLY protobuf RPC over BLE Serial, never a
	// text CLI — and is also valid on USB when the caller prefers
	// the structured response shape.
	RouteRPC
	// RouteUSBOnly indicates the requested operation cannot be
	// serviced on the live transport. Most often this means the
	// firmware has no RPC verb for the operation and the caller is
	// on BLE; the wrapper must surface ErrCommandRequiresUSB.
	RouteUSBOnly
)

// String returns a stable, lower-case route name suitable for log
// lines and error reasons.
func (r CommandRoute) String() string {
	switch r {
	case RouteTextCLI:
		return "text-cli"
	case RouteRPC:
		return "rpc"
	case RouteUSBOnly:
		return "usb-only"
	default:
		return fmt.Sprintf("CommandRoute(%d)", int(r))
	}
}

// RouteDecision is the result of a routing decision. Reason is a
// short human-readable phrase that explains WHY the route was chosen
// — it gets wrapped into errors when Route is RouteUSBOnly so the
// agent layer can show the operator something more actionable than a
// bare "command failed".
type RouteDecision struct {
	Route  CommandRoute
	Reason string
}

// CommandSupport describes the capability surface a wrapper expects
// from the firmware. Each field captures a single yes/no fact about
// the command:
//
//   - HasRPCVerb — true when the firmware exposes a protobuf RPC
//     request for this operation. Default false (most CLI verbs do
//     NOT have an RPC equivalent — Sub-GHz, NFC, IR, RFID, iButton,
//     BadUSB are CLI-only on every fork).
//   - HasCLI — true when the firmware exposes a text-CLI verb for
//     this operation. Default true (almost every command this
//     codebase wraps is a CLI verb; the exceptions are pure-RPC ops
//     like the gpio/loader pairs that some forks dropped from CLI).
//   - FirmwareForkRequired — when non-empty, the operation is only
//     supported on the named fork (case-insensitive). Used for
//     Momentum-only or Xtreme-only features.
//
// The zero value (HasRPCVerb=false, HasCLI=false, fork="") is
// intentionally "broken" — every wrapper must explicitly state at
// least one supported transport. RouteFor returns RouteUSBOnly with
// a clear reason when the zero value is passed, which gives the
// migration script a loud failure if a wrapper forgot to fill the
// struct.
type CommandSupport struct {
	HasRPCVerb           bool
	HasCLI               bool
	FirmwareForkRequired string
}

// transport-kind constants used by RouteFor. The values match
// transport.Transport.Kind() so callers can pass through the
// transport identifier verbatim.
const (
	transportKindBLE    = "ble"
	transportKindSerial = "serial"
	transportKindHTTP   = "http"
	transportKindMock   = "mock"
)

// RouteFor picks the dispatch path for an operation given the
// command's declared CommandSupport, the live transport kind, and
// the detected firmware capabilities. The function is pure — same
// inputs always produce the same output — so it is straightforward
// to unit-test with table-driven cases.
//
// Decision matrix (Phase A):
//
//	transport | HasRPCVerb | HasCLI | route
//	----------+------------+--------+------------------
//	ble       | true       | *      | RouteRPC
//	ble       | false      | *      | RouteUSBOnly (no RPC verb)
//	usb/mock  | *          | true   | RouteTextCLI
//	usb/mock  | *          | false  | RouteUSBOnly (no CLI verb)
//
// FirmwareForkRequired is checked AFTER the transport-based
// selection: if the live caps.FirmwareFork does not match (case-
// insensitive), the route is rewritten to RouteUSBOnly with a
// descriptive reason regardless of what the transport offered.
func RouteFor(operation string, support CommandSupport, transportKind string, caps Capabilities) RouteDecision {
	// 1. Transport-driven primary selection.
	primary := routeByTransport(support, transportKind)

	// 2. Fork gate. If the wrapper requires a specific fork and the
	//    live device is on a different fork, downgrade to USBOnly
	//    with a clear reason. The check happens AFTER the transport
	//    decision so the reason can mention BOTH the route we'd have
	//    taken AND the fork mismatch — but in practice a single
	//    reason is more useful, so we just report the fork mismatch.
	if req := strings.TrimSpace(support.FirmwareForkRequired); req != "" {
		live := strings.ToLower(strings.TrimSpace(caps.FirmwareFork))
		want := strings.ToLower(req)
		if live != want {
			liveLabel := live
			if liveLabel == "" {
				liveLabel = "stock"
			}
			return RouteDecision{
				Route: RouteUSBOnly,
				Reason: fmt.Sprintf(
					"%s requires firmware fork %q; live device reports %q",
					operation, req, liveLabel,
				),
			}
		}
	}

	return primary
}

// routeByTransport implements the transport-driven half of the
// decision matrix without the fork gate. Split out so RouteFor reads
// linearly and the table-driven tests can exercise the two halves
// independently if needed.
func routeByTransport(support CommandSupport, transportKind string) RouteDecision {
	switch strings.ToLower(strings.TrimSpace(transportKind)) {
	case transportKindBLE:
		if support.HasRPCVerb {
			return RouteDecision{Route: RouteRPC, Reason: "BLE transport with RPC verb"}
		}
		return RouteDecision{
			Route:  RouteUSBOnly,
			Reason: "no RPC verb in firmware for this operation; BLE has no text CLI",
		}
	default:
		// Treat every non-BLE transport (serial, http, mock, "") as
		// USB-equivalent for routing purposes. The firmware's text
		// CLI is the dominant interface; falling back here keeps
		// the decision logic future-proof against new USB-class
		// transports without changing the table.
		if support.HasCLI {
			return RouteDecision{Route: RouteTextCLI, Reason: "USB-class transport with text CLI"}
		}
		// Rare: a wrapper opts out of CLI entirely (e.g. RPC-only
		// commands that some forks dropped from text CLI). On a
		// USB-class transport the only path left is RPC, but
		// EnterRPC is a different lifecycle than the persistent BLE
		// client — surfacing USBOnly here is conservative; Phase B
		// can add a RouteRPCOnUSB variant if a real wrapper needs
		// it. For now, the message is explicit so the operator
		// knows what's happening.
		return RouteDecision{
			Route:  RouteUSBOnly,
			Reason: "operation has no text-CLI verb on this firmware",
		}
	}
}
