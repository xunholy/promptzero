package marauder

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/transport"
)

// DefaultBridgeCommand is the canonical Flipper CLI string to launch the
// USB-UART Bridge app on Momentum/Unleashed/RogueMaster/OFW 0.99+.
// Operators on bespoke firmware can override via marauder.bridge_command
// or --marauder-bridge-command.
const DefaultBridgeCommand = `loader open "USB-UART Bridge"`

// ErrBridgeRejected is returned when the Flipper firmware did not
// recognise the configured bridge command (App not found, could not find
// command, etc). The wrapped error carries the firmware's verbatim
// response so the operator can confirm the app name on their build.
var ErrBridgeRejected = errors.New("flipper rejected bridge launch command")

// bridgeFlipper is the slice of *flipper.Flipper that ConnectViaFlipper
// needs. Defining the surface as an interface keeps marauder free of any
// dependency on the flipper command-layer package (sidestepping the only
// known cycle risk in SPEC §4.2) and lets unit tests inject a fake
// without a real serial port. *flipper.Flipper satisfies it implicitly.
//
// Transport is consulted to derive single-cable vs hybrid (BLE+USB)
// behaviour — see SPEC-hybrid §1. flipper/transport is a leaf package so
// the import does not introduce a cycle.
type bridgeFlipper interface {
	ExecCtx(ctx context.Context, cmd string) (string, error)
	// LaunchBridge invokes the configured bridge-launch verb. On USB
	// CDC this is identical to ExecCtx; on BLE the bridge command's
	// `loader open "App Name"` shape is parsed and dispatched as an
	// RPC app_start request because text CLI is not available on BLE.
	LaunchBridge(ctx context.Context, cmd string) (string, error)
	Suspend(reason string) error
	IsSuspended() bool
	Transport() transport.Transport
}

// connectFn opens a Marauder over a real serial port. Tests override
// this package-level var with an in-memory fake so the retry loop in
// ConnectViaFlipper can be exercised without touching a device.
var connectFn = Connect

// bridgeRejectionMarkers is the case-insensitive substring set used to
// classify a CLI response as "the firmware did not run the bridge app".
// Each phrase is sourced from a real firmware response in either OFW,
// Momentum, Unleashed, or RogueMaster — see SPEC §4.2 step 2.
//
// The "application" markers (case-insensitive) catch Momentum's actual
// response shape — e.g. `Application "USB-UART Bridge" not found` —
// which the older "app not found" prefix-style matchers missed; without
// these the launcher used to false-success on Momentum and downstream
// code would think the bridge was active when it wasn't.
var bridgeRejectionMarkers = []string{
	"app not found",
	"application not found",
	"application \"",
	"app is not installed",
	"could not find command",
	"unknown command",
	"invalid app",
	"loader: error",
}

// ConnectViaFlipper launches the USB-UART Bridge app on flip, suspends
// the Flipper handle, and reopens the same OS-level serial port as a
// Marauder. On success the returned *Marauder is ready for Exec/Stream;
// flip is left in a suspended state (every flipper.Flipper CLI op will
// return flipper.ErrFlipperSuspended until process exit).
//
// On failure the function makes a best-effort attempt to leave flip
// usable: if the bridge command was rejected the CLI is still alive and
// flip is NOT suspended; if the launch succeeded but the reopen failed,
// flip IS suspended (the firmware committed to the swap regardless) and
// the caller must treat the Flipper as unrecoverable without a physical
// replug.
//
// Parameters:
//
//	ctx           : honoured for cancellation during launch + reopen polling
//	flip          : connected, non-suspended Flipper handle (required)
//	portName      : OS device path; in the canonical single-cable rig this
//	                is the Flipper's own serial port
//	baudRate      : baud for the Marauder side of the bridge (default 115200)
//	bridgeCmd     : Flipper CLI string; pass "" to use DefaultBridgeCommand
//	settle        : post-launch sleep before reopen (default 750ms when 0)
//	reopenTimeout : max time to keep retrying marauder.Connect (default 5s)
func ConnectViaFlipper(
	ctx context.Context,
	flip bridgeFlipper,
	portName string,
	baudRate int,
	bridgeCmd string,
	settle time.Duration,
	reopenTimeout time.Duration,
) (*Marauder, error) {
	if flip == nil {
		return nil, errors.New("flipper handle required for bridge mode")
	}
	if flip.IsSuspended() {
		return nil, errors.New("flipper already suspended")
	}
	// keepCLI: when the Flipper is reached over a non-USB transport (BLE
	// today), the USB-CDC interface is independent of the CLI link, so
	// the bridge app can own USB without taking the CLI down. We skip
	// Suspend in that case so flipper_* tools stay usable. See
	// SPEC-hybrid §1 / §2.1.
	keepCLI := false
	if t := flip.Transport(); t != nil {
		switch t.Kind() {
		case "ble":
			keepCLI = true
		case "serial":
			keepCLI = false
		default:
			return nil, fmt.Errorf("bridge mode is not supported on %s transport", t.Kind())
		}
	}
	if bridgeCmd == "" {
		bridgeCmd = DefaultBridgeCommand
	}
	if settle <= 0 {
		settle = 750 * time.Millisecond
	}
	if reopenTimeout <= 0 {
		reopenTimeout = 5 * time.Second
	}
	if baudRate == 0 {
		baudRate = 115200
	}

	// Step 1: launch. If the CLI errors or rejects the verb, flip is
	// still alive — leave it unsuspended so the caller can keep using
	// flipper_* tools. LaunchBridge handles transport routing: text
	// CLI on USB, RPC app_start on BLE (parsed from the configured
	// loader-open command shape).
	out, err := flip.LaunchBridge(ctx, bridgeCmd)
	if err != nil {
		return nil, fmt.Errorf("launching bridge app: %w", err)
	}
	if reason := classifyBridgeRejection(out); reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrBridgeRejected, reason)
	}

	// Step 2: suspend (single-cable only). From this point on the
	// function owns the suspended state — failures below leave flip
	// permanently suspended for this process (the firmware has
	// already swapped CDC handlers; there is no software-only path
	// back). In hybrid mode the BLE CLI link is independent of USB-CDC,
	// so we skip Suspend and let flipper_* tools keep working.
	if !keepCLI {
		if err := flip.Suspend("UART bridge active"); err != nil {
			return nil, fmt.Errorf("suspending flipper: %w", err)
		}
	}

	// Step 3: settle. Cancellable so a Ctrl+C between launch and reopen
	// surfaces immediately.
	select {
	case <-time.After(settle):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Step 4: reopen with retry-until-deadline. The host kernel may
	// take a few hundred ms to re-issue line coding after the firmware
	// swaps CDC handlers; the fixed 150ms inter-attempt delay keeps
	// the worst-case number of probes manageable.
	deadline := time.Now().Add(reopenTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, oerr := connectFn(portName, baudRate)
		if oerr == nil {
			return m, nil
		}
		lastErr = oerr
		select {
		case <-time.After(150 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("reopening %s after bridge launch: %w", portName, lastErr)
}

// classifyBridgeRejection returns a non-empty trimmed copy of out when it
// contains any known firmware-side rejection marker, or "" otherwise.
// Match is case-insensitive on the marker substring; the returned text
// preserves the original casing so operators can copy-paste it.
func classifyBridgeRejection(out string) string {
	lower := strings.ToLower(out)
	for _, m := range bridgeRejectionMarkers {
		if strings.Contains(lower, m) {
			return strings.TrimSpace(out)
		}
	}
	return ""
}
