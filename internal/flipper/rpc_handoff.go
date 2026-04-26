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

// EnterRPC transitions the Flipper into RPC mode and returns a typed client
// along with a release closure.
//
// Semantics:
//  1. Acquires f.mu for the entire RPC session.
//  2. Attempts reconnect if the transport is marked disconnected.
//  3. Drains any pending CLI output from the buffer.
//  4. Constructs rpc.NewClient, calls Open. On error: unlocks and returns.
//  5. Sets rpcMode to true.
//  6. Returns the client and a release closure that: clears rpcMode, closes
//     the client, re-handshakes the CLI prompt, and unlocks the mutex.
//
// The release closure is safe to call exactly once; subsequent calls are no-ops.
func (f *Flipper) EnterRPC(ctx context.Context) (*rpc.Client, func(), error) {
	f.mu.Lock()

	if err := f.reconnectIfNeededLocked(ctx); err != nil {
		f.mu.Unlock()
		return nil, nil, err
	}

	f.drain()

	client := rpc.NewClient(f.transport)
	if err := client.Open(ctx); err != nil {
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
