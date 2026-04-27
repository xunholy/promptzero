package flipper

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/rpc"
)

// ErrInRPCMode is returned by CLI methods when the Flipper is held by a
// concurrent RPC session. Release the mirror (call the closure returned by
// EnterRPC) before issuing CLI commands.
var ErrInRPCMode = errors.New("flipper is in RPC (mirror) mode; release the mirror to use CLI commands")

// ErrCommandRequiresUSB is returned by Flipper command methods when the
// underlying transport is BLE and the requested operation has no
// equivalent RPC verb in the firmware. Sub-GHz, NFC, IR, RFID, iButton,
// and BadUSB are CLI-only on every Flipper firmware (stock + Momentum)
// because the firmware exposes only RPC over BLE Serial — see
// flipperdevices/flipperzero-firmware applications/services/bt and
// applications/services/rpc/. Surface this error to operators with the
// command name + the suggestion to attach the Flipper via USB.
var ErrCommandRequiresUSB = errors.New("this Flipper command has no RPC equivalent in firmware and is only available over USB")

// usbOnlyError wraps ErrCommandRequiresUSB with the calling command name
// for clearer messaging in the agent layer. Use sparingly — only for
// commands the firmware genuinely cannot service over BLE. errors.Is
// against ErrCommandRequiresUSB still works.
func usbOnlyError(command string) error {
	return fmt.Errorf("%s: %w (connect the Flipper via USB to use this command)", command, ErrCommandRequiresUSB)
}

// EnterRPC transitions the Flipper into RPC mode and returns a typed client
// along with a release closure.
//
// Semantics on USB CDC:
//  1. Acquires f.mu for the entire RPC session.
//  2. Attempts reconnect if the transport is marked disconnected.
//  3. Drains any pending CLI output from the buffer.
//  4. Constructs rpc.NewClient, calls Open. On error: unlocks and returns.
//  5. Sets rpcMode to true.
//  6. Returns the client and a release closure that: clears rpcMode, closes
//     the client, re-handshakes the CLI prompt, and unlocks the mutex.
//
// Semantics on BLE:
//
// The Flipper firmware has no text CLI on its BLE Serial endpoint — RPC
// is permanent for the lifetime of the connection. ConnectURL already
// opened the persistent client (f.bleClient) at handshake time and
// latched rpcMode=true, so EnterRPC returns that client with a no-op
// release closure. The caller's release() call is therefore safe and
// idempotent on both transports, but on BLE no CLI re-handshake runs
// (there is no CLI to return to).
//
// The release closure is safe to call exactly once; subsequent calls are no-ops.
func (f *Flipper) EnterRPC(ctx context.Context) (*rpc.Client, func(), error) {
	if f.bleClient != nil {
		// BLE: client is permanent. No mutex acquisition (callers don't
		// share state outside the rpc.Client's own lock), no Open call
		// (already done at ConnectURL time), no release teardown.
		return f.bleClient, func() {}, nil
	}

	f.mu.Lock()

	if err := f.reconnectIfNeededLocked(ctx); err != nil {
		f.mu.Unlock()
		return nil, nil, err
	}

	f.drain()

	client := rpc.NewClient(f.transport)
	pl := f.pipeline()
	if err := client.Open(ctx, rpc.WithPipeline(rpc.HandshakePolicy{
		Attempts:    pl.RPCRetryAttempts,
		PingTimeout: pl.RPCRetryDelay,
	})); err != nil {
		f.mu.Unlock()
		return nil, nil, fmt.Errorf("rpc: open session: %w", err)
	}

	f.rpcMode.Store(true)

	var released bool
	release := func() {
		if released {
			return
		}
		released = true

		f.rpcMode.Store(false)
		_ = client.Close()

		// Re-prove that the CLI prompt is back. 2 s is generous; the firmware
		// re-enters CLI within one Ctrl+C round-trip (~50 ms on USB-CDC).
		hsCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = f.handshake(hsCtx)

		f.mu.Unlock()
	}

	return client, release, nil
}
