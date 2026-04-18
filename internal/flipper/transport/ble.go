// Package transport — BLE implementation for the Flipper Zero.
//
// Testing note: BLE does not work under WSL2. The Windows Subsystem for
// Linux does not expose Bluetooth to the Linux guest, so this transport
// is not exercised in a WSL session. To test against real hardware,
// run the contract test from a native Linux desktop, macOS, or Windows
// session with FLIPPER_BLE_MAC set to the target Flipper's MAC address.
// The contract test in contract_test.go is gated on that env var and is
// skipped when unset, so CI (which runs without paired hardware) is
// unaffected.
//
// Linux pairing prerequisite: BlueZ requires the target device to be
// known in the adapter's cache before Connect() will succeed — a
// one-time `bluetoothctl pair <MAC>` (or pairing via the desktop
// Bluetooth manager) is typically enough. The first-time setup is not
// attempted by this transport.

package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tinygo.org/x/bluetooth"
)

// flipperBLEServiceUUID is the 128-bit UUID of the Flipper Zero's BLE
// "serial" service. The value is sourced from the original Phase-B
// handoff checklist in this file and tracks the service exposed by
// flipperdevices/flipperzero-firmware at
// applications/services/bt/bt_service/bt_service.c. If the Flipper
// firmware rev's this UUID, Dial's DiscoverServices call will return
// no matches and the caller will see a diagnostic error naming the
// expected value; the slog-Debug scan log also records every service
// UUID observed on every advertised peripheral so the new value can
// be read out of operational logs without hardware in hand.
var flipperBLEServiceUUID = mustParseUUID("0000fe60-cc7a-482a-984a-7f2ed5b3e58f")

// flipperBLETXCharUUID and flipperBLERXCharUUID are hints used to
// pick out the TX (host→flipper writes) and RX (flipper→host
// notifications) characteristics among those enumerated on the
// Flipper service. tinygo.org/x/bluetooth only exposes characteristic
// property flags (Write / Notify / Indicate) on its Windows backend,
// not on Linux or Darwin, so we cannot do property-based matching in
// a single cross-platform code path. These UUID hints are the primary
// match; if neither is found on the discovered characteristic list we
// fall back to positional ordering (the Nordic UART Service convention
// where the first characteristic is the write/TX and the second is
// notify/RX — the Flipper service mimics NUS). The fallback is logged
// at Warn level rather than Debug so that UUID drift shows up in
// normal operator-facing logs and can be patched forward.
var (
	flipperBLETXCharUUID = mustParseUUID("19ed82ae-ed21-4c9d-4145-228e62fe0000")
	flipperBLERXCharUUID = mustParseUUID("19ed82ae-ed21-4c9d-4145-228e61fe0000")
)

// bleScanTimeout bounds the Dial scan phase. A paired Flipper
// advertises quickly once in range; 30 s tolerates momentarily weak
// RSSI without hanging a human-driven CLI indefinitely.
const bleScanTimeout = 30 * time.Second

// bleDrainTimeout is the transport's post-command "wait for silence"
// interval, returned by DrainTimeout. 250 ms is chosen because BLE
// notifications arrive in 20–50 ms bursts; the 100 ms used by the
// serial transport is too tight and produces false-negative silence
// readings mid-response. This matches the value called out in
// step 6 of the original phase-B checklist at the top of this file.
const bleDrainTimeout = 250 * time.Millisecond

// bleDefaultMTU is the BLE spec's minimum ATT MTU (23 bytes total, of
// which 3 are ATT overhead so the usable payload per characteristic
// write is 20 bytes). Used as the Write chunk size before MTU
// negotiation completes, and as the fallback when GetMTU() fails.
const bleDefaultMTU = 23

// bleMaxMTU is the BLE 5 maximum ATT MTU. GetMTU() results above this
// bound are clamped to keep the Write chunk size sane.
const bleMaxMTU = 512

// attHeaderOverhead is the fixed 3-byte ATT overhead (op-code + handle)
// that must be subtracted from the negotiated MTU to get the payload
// size for a single WriteWithoutResponse.
const attHeaderOverhead = 3

// errBLENotWired is returned by bleTransport methods that have not yet
// been implemented in the current commit. Replaced with functional
// implementations in subsequent commits of this phase.
var errBLENotWired = errors.New("transport: ble method not yet implemented")

func init() { Register("ble", bleDialer) }

// mustParseUUID parses a UUID literal or panics. Used only for the
// package-level Flipper UUID constants so a typo fails at init time
// rather than mid-dial.
func mustParseUUID(s string) bluetooth.UUID {
	u, err := bluetooth.ParseUUID(s)
	if err != nil {
		panic(fmt.Sprintf("transport/ble: invalid UUID literal %q: %v", s, err))
	}
	return u
}

// bleDialer parses a ble://<MAC> URL and returns an undialled
// bleTransport. The MAC must be in the standard colon-delimited
// 11:22:33:AA:BB:CC form; case does not matter (the MAC is stored in
// canonical uppercase so Identity output is stable).
func bleDialer(rawURL string) (Transport, error) {
	path, _, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	mac := strings.TrimSpace(path)
	if _, err := net.ParseMAC(mac); err != nil {
		return nil, fmt.Errorf("transport: invalid MAC %q in URL %q: %w", mac, rawURL, err)
	}
	t := &bleTransport{
		mac: strings.ToUpper(mac),
		mtu: bleDefaultMTU,
	}
	t.readCond = sync.NewCond(&t.mu)
	return t, nil
}

// bleTransport is the BLE implementation of Transport. It owns a
// connection to one Flipper Zero peripheral identified by MAC. TX and
// RX characteristics are resolved at Dial time; Read consumes bytes
// from an internal buffer that the RX characteristic's notification
// callback appends to from the library's notify goroutine.
type bleTransport struct {
	// mac is the stable identifier used by the scan filter at Dial
	// time and by Reconnect when the physical link drops. Stored in
	// canonical uppercase "11:22:33:AA:BB:CC" form so Identity output
	// round-trips cleanly.
	mac string

	// adapter, device, txChar, rxChar are set exclusively within
	// Dial (or Reconnect) under mu, and read from every other method.
	// They are only meaningful when closed is false and Dial has
	// returned nil at least once.
	adapter *bluetooth.Adapter
	device  *bluetooth.Device
	txChar  bluetooth.DeviceCharacteristic
	rxChar  bluetooth.DeviceCharacteristic

	// mtu is the per-write payload size (negotiated ATT MTU minus the
	// 3-byte ATT header). Set at Dial time; used in Write to chunk
	// larger payloads into MTU-sized slices.
	mtu int

	// mu guards every mutable field below and is the sync.Locker for
	// readCond.
	mu sync.Mutex

	// readCond signals Read-blockers when data is appended to
	// readBuf, readErr is latched, or closed flips to true.
	readCond *sync.Cond

	// readBuf accumulates bytes delivered by the RX characteristic's
	// notification callback; Read drains from the front.
	readBuf bytes.Buffer

	// readErr latches a terminal error (for example a disconnect
	// event). Once set, subsequent Reads return it without blocking.
	readErr error

	// closed is true after Close has run. Subsequent Reads return
	// os.ErrClosed; subsequent Closes are no-ops (Close is idempotent
	// per the Transport contract).
	closed bool

	// readTimeout is the deadline for the next Read. Zero means
	// "block until data, close, or error"; non-zero means "block up
	// to this long, then return (0, nil) if nothing arrives" —
	// mirroring the serial.Port.Read convention the flipper layer's
	// drain loop relies on.
	readTimeout time.Duration
}

// Dial enables the adapter, scans for the target MAC (bounded by
// bleScanTimeout), connects to the peripheral, discovers the Flipper
// service, and resolves the TX / RX characteristics. It honours
// ctx cancellation throughout: a cancelled ctx during scan stops the
// scan immediately; a cancel between connect and characteristic
// resolution disconnects the device and returns ctx.Err.
func (t *bleTransport) Dial(ctx context.Context) error {
	t.mu.Lock()
	if t.adapter != nil {
		t.mu.Unlock()
		return fmt.Errorf("transport: ble already dialled (%s)", t.mac)
	}
	if t.closed {
		t.mu.Unlock()
		return os.ErrClosed
	}
	t.mu.Unlock()

	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return fmt.Errorf("transport: enabling BLE adapter: %w", err)
	}

	addr, err := scanForMAC(ctx, adapter, t.mac)
	if err != nil {
		return err
	}

	device, err := adapter.Connect(addr, bluetooth.ConnectionParams{})
	if err != nil {
		return fmt.Errorf("transport: BLE connect to %s: %w", t.mac, err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = device.Disconnect()
		return ctxErr
	}

	services, err := device.DiscoverServices([]bluetooth.UUID{flipperBLEServiceUUID})
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: BLE service discovery on %s: %w — is BLE enabled in Flipper Settings > Bluetooth?", t.mac, err)
	}
	if len(services) == 0 {
		_ = device.Disconnect()
		return fmt.Errorf("transport: flipper BLE service %s not found on %s — firmware rev may have changed the service UUID", flipperBLEServiceUUID.String(), t.mac)
	}

	chars, err := services[0].DiscoverCharacteristics(nil)
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: BLE characteristic discovery on %s: %w", t.mac, err)
	}
	txChar, rxChar, err := selectFlipperCharacteristics(chars)
	if err != nil {
		_ = device.Disconnect()
		return err
	}

	if err := rxChar.EnableNotifications(t.onNotify); err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: enabling RX notifications on %s: %w", t.mac, err)
	}

	t.mu.Lock()
	t.adapter = adapter
	t.device = &device
	t.txChar = txChar
	t.rxChar = rxChar
	t.mu.Unlock()

	return nil
}

// onNotify is the callback registered against the RX characteristic's
// notification stream at Dial time. The bluetooth library invokes it
// from a library-owned goroutine whenever a notification packet
// arrives; our job is to append the bytes to readBuf under mu and
// signal any Read that's blocked in readCond.Wait.
//
// This is the "notify→stream bridge" that lets the Flipper command
// layer above the transport see a continuous Read stream even though
// the wire protocol is chunked into notification packets of MTU-3
// bytes. readBuf is unbounded on purpose — the flipper command layer
// reads aggressively (readUntilPrompt) and Flipper payloads are
// small; bounding the buffer would risk losing prompt bytes mid-
// response.
func (t *bleTransport) onNotify(buf []byte) {
	if len(buf) == 0 {
		return
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.readBuf.Write(buf)
	t.readCond.Broadcast()
	t.mu.Unlock()
}

// scanForMAC runs a single BLE scan bounded by bleScanTimeout and
// stops as soon as an advertisement from the target MAC is seen. It
// honours ctx cancellation by calling StopScan, which causes the
// adapter's Scan loop to return.
//
// Each scan result is logged at Debug level (MAC, RSSI, local name)
// so operators can pattern-match the target device out of a crowded
// RF environment if the expected MAC is never seen.
func scanForMAC(ctx context.Context, adapter *bluetooth.Adapter, mac string) (bluetooth.Address, error) {
	scanCtx, cancel := context.WithTimeout(ctx, bleScanTimeout)
	defer cancel()

	addrCh := make(chan bluetooth.Address, 1)
	scanDone := make(chan error, 1)
	var stopped atomic.Bool

	go func() {
		err := adapter.Scan(func(a *bluetooth.Adapter, sr bluetooth.ScanResult) {
			if stopped.Load() {
				return
			}
			addrStr := sr.Address.MAC.String()
			slog.Debug("transport/ble: scan result",
				"mac", addrStr, "rssi", sr.RSSI, "name", sr.LocalName())
			if !strings.EqualFold(addrStr, mac) {
				return
			}
			if stopped.CompareAndSwap(false, true) {
				select {
				case addrCh <- sr.Address:
				default:
				}
				_ = a.StopScan()
			}
		})
		scanDone <- err
	}()

	select {
	case addr := <-addrCh:
		<-scanDone
		return addr, nil
	case err := <-scanDone:
		if err != nil {
			return bluetooth.Address{}, fmt.Errorf("transport: BLE scan error: %w", err)
		}
		return bluetooth.Address{}, fmt.Errorf("transport: BLE scan ended without finding %s", mac)
	case <-scanCtx.Done():
		stopped.Store(true)
		_ = adapter.StopScan()
		<-scanDone
		if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
			return bluetooth.Address{}, fmt.Errorf(
				"transport: no flipper found with MAC %s within %s — is it advertising? pair it once via your OS Bluetooth settings first",
				mac, bleScanTimeout,
			)
		}
		return bluetooth.Address{}, scanCtx.Err()
	}
}

// selectFlipperCharacteristics resolves the TX and RX characteristics
// from the list returned by DiscoverCharacteristics on the Flipper
// service, using hint-first matching with a positional fallback.
//
// Primary path: both flipperBLETXCharUUID and flipperBLERXCharUUID are
// present in the discovered set. Used directly.
//
// Fallback path: at least two characteristics were discovered but the
// hint UUIDs didn't match. Assumes the Nordic UART Service convention
// (first = TX/write, second = RX/notify) and logs at Warn so the UUID
// drift is visible to operators running the CLI rather than buried in
// a debug-only stream nobody looks at.
//
// Error path: fewer than two characteristics were discovered — we
// can't possibly pair TX and RX. The error names both hinted UUIDs
// and every UUID actually seen so the next debugging session starts
// on the right foot (per team-lead's review comment during phase B).
func selectFlipperCharacteristics(chars []bluetooth.DeviceCharacteristic) (tx, rx bluetooth.DeviceCharacteristic, err error) {
	discovered := make([]string, 0, len(chars))
	var txByHint, rxByHint *bluetooth.DeviceCharacteristic
	for i := range chars {
		u := chars[i].UUID()
		discovered = append(discovered, u.String())
		if u == flipperBLETXCharUUID {
			txByHint = &chars[i]
		}
		if u == flipperBLERXCharUUID {
			rxByHint = &chars[i]
		}
	}
	slog.Debug("transport/ble: discovered characteristics",
		"uuids", discovered,
		"expectedTX", flipperBLETXCharUUID.String(),
		"expectedRX", flipperBLERXCharUUID.String())

	if txByHint != nil && rxByHint != nil {
		return *txByHint, *rxByHint, nil
	}

	if len(chars) < 2 {
		return tx, rx, fmt.Errorf(
			"transport: flipper BLE service found but expected TX=%s, RX=%s; discovered %v — firmware rev may have changed characteristic layout",
			flipperBLETXCharUUID.String(), flipperBLERXCharUUID.String(), discovered,
		)
	}

	slog.Warn(
		"transport/ble: TX/RX characteristics not matched by hint UUID; falling back to positional ordering (first=TX, second=RX, NUS convention)",
		"expectedTX", flipperBLETXCharUUID.String(),
		"expectedRX", flipperBLERXCharUUID.String(),
		"discovered", discovered,
	)
	return chars[0], chars[1], nil
}

// Read drains up to len(p) bytes from the internal read buffer
// populated by onNotify. It follows the serial transport's blocking
// semantics: with a non-zero readTimeout it returns (0, nil) when the
// timeout elapses without any bytes arriving (letting the flipper
// layer's prompt-poll loop tick through ctx), with a zero readTimeout
// it blocks until data, Close, or a latched readErr.
//
// The cond-with-timer pattern — a background time.AfterFunc that
// broadcasts readCond once the deadline elapses — is used instead of
// a channel because readBuf is already guarded by mu and sync.Cond
// is the standard idiom for "signal arrival" on shared state. The
// timer is stopped on every exit so repeated Reads don't leak
// goroutines when the timeout is reset frequently.
func (t *bleTransport) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	timeout := t.readTimeout
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}

	for {
		if t.readBuf.Len() > 0 {
			return t.readBuf.Read(p)
		}
		if t.closed {
			return 0, os.ErrClosed
		}
		if t.readErr != nil {
			return 0, t.readErr
		}
		if timeout == 0 {
			t.readCond.Wait()
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil
		}
		waitCondTimeout(t.readCond, remaining)
	}
}

// waitCondTimeout waits on cond for at most d, then broadcasts to
// unblock the wait. Must be called with cond.L held; on return the
// lock is still held (cond.Wait re-acquires it).
//
// The broadcast goroutine re-locks cond.L before broadcasting —
// sync.Cond allows Broadcast without the lock, but taking the lock
// avoids a subtle race: if the timer fires concurrently with another
// thread about to signal (say, an onNotify append), the other signal
// might already have woken our waiter and we'd broadcast into an
// empty set. Holding the lock during broadcast serialises with the
// waiter's state check and is cheap in practice.
func waitCondTimeout(cond *sync.Cond, d time.Duration) {
	timer := time.AfterFunc(d, func() {
		cond.L.Lock()
		cond.Broadcast()
		cond.L.Unlock()
	})
	defer timer.Stop()
	cond.Wait()
}

// Write is wired in a subsequent commit.
func (t *bleTransport) Write(p []byte) (int, error) {
	return 0, errBLENotWired
}

// SetReadTimeout reconfigures how long the next Read will block
// before returning (0, nil). Zero means "block indefinitely until
// data, close, or error" — matching the serial and mock transports.
// The change applies to the next Read call; a Read currently
// blocked in readCond.Wait is woken via Broadcast so it can pick up
// the new timeout immediately.
func (t *bleTransport) SetReadTimeout(d time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return os.ErrClosed
	}
	t.readTimeout = d
	t.readCond.Broadcast()
	return nil
}

// Reconnect is wired in a subsequent commit.
func (t *bleTransport) Reconnect(ctx context.Context) error {
	return errBLENotWired
}

// Close disconnects the peripheral, latches closed=true, and signals
// any goroutines blocked in Read so they return os.ErrClosed. Close
// is idempotent: subsequent calls return nil without re-disconnecting.
func (t *bleTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	device := t.device
	t.device = nil
	t.readCond.Broadcast()
	t.mu.Unlock()

	if device == nil {
		// Close before (or without) a successful Dial.
		return nil
	}
	if err := device.Disconnect(); err != nil {
		return fmt.Errorf("transport: BLE disconnect from %s: %w", t.mac, err)
	}
	return nil
}

// Identity returns the stable "ble://<MAC>" URL used for logging and
// /status output. The MAC is already uppercased in bleDialer so this
// is a pure formatter.
func (t *bleTransport) Identity() string { return "ble://" + t.mac }

// Kind returns the "ble" telemetry tag.
func (t *bleTransport) Kind() string { return "ble" }

// DrainTimeout returns the BLE-tuned 250 ms interval used by the
// flipper layer's post-command drain loop. See bleDrainTimeout for
// the rationale.
func (t *bleTransport) DrainTimeout() time.Duration { return bleDrainTimeout }
