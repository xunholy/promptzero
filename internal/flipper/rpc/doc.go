// Package rpc implements a typed Flipper Zero RPC client over a
// transport.Transport.
//
// # Mode switching
//
// The Flipper firmware supports two mutually-exclusive modes on the USB CDC-ACM
// port: CLI text mode (the default) and RPC protobuf mode. Switching is
// initiated by writing "start_rpc_session\r\n" to the port; the firmware
// immediately transitions and from that point onwards the byte stream is
// length-prefixed protobuf (see framing.go).
//
// The high-level entry point is (*flipper.Flipper).EnterRPC in the parent
// package. EnterRPC acquires the Flipper mutex, drains any pending CLI output,
// constructs a Client, and returns a release closure that sends StopSession,
// re-handshakes the CLI prompt, and unlocks the mutex. The web layer calls
// EnterRPC to acquire the mirror and holds the closure until the websocket
// session ends.
//
// Usage
//
//	client, release, err := f.EnterRPC(ctx)
//	if err != nil { ... }
//	defer release()
//
//	frames, err := client.StartScreenStream(ctx)
//	if err != nil { ... }
//	for frame := range frames {
//	    // deliver frame to browser via websocket
//	}
package rpc
