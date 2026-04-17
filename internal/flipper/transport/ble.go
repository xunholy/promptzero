// TODO(BLE-phase-B): real BLE transport implementation.
//
// Scope for the follow-up phase:
//
//   1. Scanner — enumerate Bluetooth LE peripherals advertising the
//      Flipper Serial Service UUID (0000fe60-cc7a-482a-984a-7f2ed5b3e58f).
//      Offer both "scan and pick first" (default) and "scan and match
//      MAC from URL" modes.
//
//   2. Service/characteristic discovery — after connect, resolve the
//      Flipper Serial Service + its RX/TX characteristics. Cache
//      handles on the transport so Read/Write don't redo discovery.
//
//   3. MTU handshake — exchange MTU up to 512; remember the negotiated
//      value so Write can chunk payloads >MTU. The flipper WriteFile
//      path already streams in 512-byte buffers so chunking above
//      native MTU is the only concern.
//
//   4. Notify-based pseudo-prompt framing — the serial transport relies
//      on the Flipper's shell printing ">: " as a prompt sentinel. BLE
//      delivers bytes via notifications; the same ">: " byte pattern
//      still arrives, but the transport layer must stitch notifications
//      into a byte stream so the flipper layer's readUntilPrompt loop
//      sees a continuous Read. A bounded internal channel buffer
//      (e.g. 64 KiB) backed by the notify callback is the usual shape.
//
//   5. Auto-reconnect via scan-match — if the peripheral drops, the
//      next Reconnect should rescan and match by MAC (the URL MAC is
//      the stable identifier). Preserve the same 2 s connect-timeout
//      budget the serial transport uses.
//
//   6. DrainTimeout — bump to ~250 ms. BLE notifications batch, and
//      100 ms (the serial default) is too tight in practice.
//
//   7. Tests — enable the hardware-gated contract test against a
//      known mock peripheral; flip ErrNotImplemented to nil and let
//      the shared contract_test run.
//
// Everything above the transport (commands.go, capabilities.go,
// reconnect logic in flipper.go) should need zero changes when BLE
// lands — that's the whole point of this phase.

package transport

// BLE is a Phase-B follow-up. The scheme is reserved here so callers
// get a stable, recognisable error (transport.ErrNotImplemented) rather
// than a generic "unknown scheme" message when they try
// ble://AA:BB:CC:DD:EE:FF today. When the real implementation lands,
// replace the body of bleDialer with a constructor that returns a
// *bleTransport and let the existing Open → Dial flow drive it.

func init() { Register("ble", bleDialer) }

func bleDialer(rawURL string) (Transport, error) {
	return nil, ErrNotImplemented
}
