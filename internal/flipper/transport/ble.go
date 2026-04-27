// Package transport — BLE implementation for the Flipper Zero.
//
// Build constraint: this file is excluded on darwin because
// tinygo.org/x/bluetooth pulls in github.com/tinygo-org/cbgo on darwin,
// which needs CGO + the macOS SDK to compile. The cross-compile CI
// matrix builds darwin from a Linux host without CGO, which errors out
// with "undefined: CentralManager". A sibling ble_darwin.go provides a
// stub dialer that returns a clear "build promptzero on macOS with CGO
// to enable BLE" error; real BLE on macOS is unlocked by building on a
// Mac (GOOS=darwin CGO_ENABLED=1 go build).
//
// Testing note: BLE does not work under WSL2. The Windows Subsystem for
// Linux does not expose Bluetooth to the Linux guest, so this transport
// is not exercised in a WSL session. To test against real hardware,
// run the contract test from a native Linux desktop or Windows session
// with FLIPPER_BLE_MAC set to the target Flipper's MAC address. The
// contract test in contract_test.go is gated on that env var and is
// skipped when unset, so CI (which runs without paired hardware) is
// unaffected.
//
// Linux pairing prerequisite: BlueZ requires the target device to be
// known in the adapter's cache before Connect() will succeed — a
// one-time `bluetoothctl pair <MAC>` (or pairing via the desktop
// Bluetooth manager) is typically enough. The first-time setup is not
// attempted by this transport.

//go:build !darwin || (darwin && cgo)

package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"runtime"
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

// addrKind classifies the form of a BLE address supplied via ble:// URLs.
// The form determines how scanForAddress matches against advertisements
// and whether establish can take the darwin direct-connect fast path.
type addrKind int

const (
	// addrKindMAC is a 6-octet hardware MAC (80:E1:26:69:6E:55). The
	// canonical form on Linux and Windows where the OS exposes the
	// peer's BLE hardware address. Rejected by CoreBluetooth on darwin.
	addrKindMAC addrKind = iota

	// addrKindUUID is the canonical 8-4-4-4-12 CoreBluetooth peripheral
	// identifier (e127efc1-05ec-ce53-014e-b79fee9117fa). darwin-only,
	// per-Mac-stable but never portable across machines. Use
	// `promptzero --ble-discover` to enumerate identifiers visible to
	// the local CoreBluetooth daemon.
	addrKindUUID

	// addrKindName matches against the BLE advertising LocalName, e.g.
	// "Unholy". Convenient cross-platform fallback when the user
	// doesn't want to deal with MACs/UUIDs, but not authoritative —
	// names are user-set on the Flipper and not unique.
	addrKindName
)

func (k addrKind) String() string {
	switch k {
	case addrKindMAC:
		return "MAC"
	case addrKindUUID:
		return "UUID"
	case addrKindName:
		return "name"
	}
	return "address"
}

// bleAddrUUIDPattern is the canonical 8-4-4-4-12 hex form of a
// CoreBluetooth peripheral identifier. Used by parseBLEAddress to
// distinguish UUID-form ble:// URLs from MACs (which use colons, not
// hyphens) and bare device names (no separators of either kind).
var bleAddrUUIDPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

// parseBLEAddress recognises three URL forms by shape:
//
//   - MAC  ("80:E1:26:69:6E:55") — 6 octets via net.ParseMAC. Linux/Windows.
//   - UUID ("e127efc1-05ec-...")  — CoreBluetooth identifier. darwin only.
//   - Name ("Unholy")             — anything else, matched against
//     advertising LocalName at scan time.
//
// The forms are unambiguous: MACs contain colons (or hyphens with
// 6-octet length), UUIDs contain hyphens at fixed offsets, names
// contain neither. MAC normalises to uppercase canonical form; UUID
// to lowercase; names round-trip verbatim (case-insensitive matching
// happens at scan time).
func parseBLEAddress(s string) (addrKind, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, "", fmt.Errorf("empty BLE address")
	}
	if mac, err := net.ParseMAC(s); err == nil && len(mac) == 6 {
		return addrKindMAC, strings.ToUpper(mac.String()), nil
	}
	if bleAddrUUIDPattern.MatchString(s) {
		return addrKindUUID, strings.ToLower(s), nil
	}
	return addrKindName, s, nil
}

// bleDialer parses a ble://<addr> URL and returns an undialled
// bleTransport. The address may be a hardware MAC (Linux/Windows),
// a CoreBluetooth identifier UUID (darwin), or a device LocalName
// (any platform — fallback). See parseBLEAddress for the shape rules.
func bleDialer(rawURL string) (Transport, error) {
	path, _, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	kind, addr, err := parseBLEAddress(path)
	if err != nil {
		return nil, fmt.Errorf("transport: in URL %q: %w", rawURL, err)
	}
	t := &bleTransport{
		addr:     addr,
		addrKind: kind,
		mtu:      bleDefaultMTU,
	}
	t.readCond = sync.NewCond(&t.mu)
	return t, nil
}

// bleTransport is the BLE implementation of Transport. It owns a
// connection to one Flipper Zero peripheral identified by an address
// whose form depends on the host OS — see addrKind. TX and RX
// characteristics are resolved at Dial time; Read consumes bytes
// from an internal buffer that the RX characteristic's notification
// callback appends to from the library's notify goroutine.
type bleTransport struct {
	// addr is the stable identifier used by resolveAddress at Dial
	// time and by Reconnect when the physical link drops. Storage
	// canonicalisation is per-kind: uppercase MAC, lowercase UUID,
	// verbatim for names — so Identity output round-trips cleanly.
	addr string

	// addrKind determines whether addr is a MAC, a CoreBluetooth UUID,
	// or a LocalName, which in turn controls scan-match logic and
	// whether the darwin direct-connect fast path is available.
	addrKind addrKind

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

// Dial enables the adapter and runs the scan → connect → discover →
// notify-enable → MTU negotiation pipeline. It honours ctx
// cancellation throughout: a cancelled ctx during scan stops the
// scan immediately; a cancel between connect and characteristic
// resolution disconnects the device and returns ctx.Err.
func (t *bleTransport) Dial(ctx context.Context) error {
	t.mu.Lock()
	if t.adapter != nil {
		t.mu.Unlock()
		return fmt.Errorf("transport: ble already dialled (%s)", t.addr)
	}
	if t.closed {
		t.mu.Unlock()
		return os.ErrClosed
	}
	t.mu.Unlock()

	return t.establish(ctx)
}

// establish runs the full scan → connect → discover → notify-enable →
// MTU-handshake pipeline and commits the resulting handles to t.
// Shared between Dial and Reconnect so the wire-level steps have
// exactly one implementation. The caller is responsible for clearing
// any previous adapter/device/char state (Reconnect does this under
// mu before calling).
func (t *bleTransport) establish(ctx context.Context) error {
	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return fmt.Errorf("transport: enabling BLE adapter: %w", err)
	}

	addr, fast, err := t.resolveAddress(ctx, adapter)
	if err != nil {
		return err
	}

	device, err := adapter.Connect(addr, bluetooth.ConnectionParams{})
	if err != nil {
		// On the darwin fast path we handed Connect an address that
		// CoreBluetooth's retrievePeripherals cache may no longer
		// recognise (peripheral removed, BT stack bounced, etc.). Fall
		// back to a full scan once before giving up.
		if !fast {
			return fmt.Errorf("transport: BLE connect to %s: %w", t.addr, err)
		}
		slog.Debug("transport/ble: direct connect failed, retrying via scan",
			"addr", t.addr, "err", err)
		scanAddr, scanErr := scanForAddress(ctx, adapter, t.addrKind, t.addr)
		if scanErr != nil {
			return fmt.Errorf("transport: BLE connect to %s: %w (scan fallback also failed: %v)",
				t.addr, err, scanErr)
		}
		device, err = adapter.Connect(scanAddr, bluetooth.ConnectionParams{})
		if err != nil {
			return fmt.Errorf("transport: BLE connect to %s after scan fallback: %w", t.addr, err)
		}
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = device.Disconnect()
		return ctxErr
	}

	services, err := device.DiscoverServices([]bluetooth.UUID{flipperBLEServiceUUID})
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: BLE service discovery on %s: %w — is BLE enabled in Flipper Settings > Bluetooth?", t.addr, err)
	}
	if len(services) == 0 {
		_ = device.Disconnect()
		return fmt.Errorf("transport: flipper BLE service %s not found on %s — firmware rev may have changed the service UUID", flipperBLEServiceUUID.String(), t.addr)
	}

	chars, err := services[0].DiscoverCharacteristics(nil)
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: BLE characteristic discovery on %s: %w", t.addr, err)
	}
	txChar, rxChar, err := selectFlipperCharacteristics(chars)
	if err != nil {
		_ = device.Disconnect()
		return err
	}

	if err := rxChar.EnableNotifications(t.onNotify); err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: enabling RX notifications on %s: %w", t.addr, err)
	}

	mtu := negotiateMTU(txChar)

	t.mu.Lock()
	t.adapter = adapter
	t.device = &device
	t.txChar = txChar
	t.rxChar = rxChar
	t.mtu = mtu
	// Wake any Read already parked before Reconnect — onNotify for
	// the new connection will refill readBuf, but a Read blocked
	// with a stale readErr latch should re-evaluate.
	t.readErr = nil
	t.readCond.Broadcast()
	t.mu.Unlock()

	return nil
}

// negotiateMTU queries the negotiated ATT MTU via GetMTU on the TX
// characteristic and returns the usable per-Write payload size
// (negotiated MTU minus the 3-byte ATT header). Falls back to the
// BLE spec minimum (23 − 3 = 20 bytes) if GetMTU errors or returns a
// value below spec — some backends return 0 on Linux before the
// peripheral confirms the MTU exchange, and the flipper-layer's
// first command is small enough that a 20-byte chunk size is always
// correct. Clamps above bleMaxMTU to keep chunk sizes sane.
func negotiateMTU(c bluetooth.DeviceCharacteristic) int {
	raw, err := c.GetMTU()
	if err != nil || int(raw) < bleDefaultMTU {
		slog.Warn("transport/ble: MTU negotiation unavailable; using BLE default",
			"mtu", raw, "err", err, "fallback", bleDefaultMTU)
		return bleDefaultMTU - attHeaderOverhead
	}
	mtu := int(raw)
	if mtu > bleMaxMTU {
		mtu = bleMaxMTU
	}
	return mtu - attHeaderOverhead
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

// scanForAddress runs a single BLE scan bounded by bleScanTimeout and
// stops as soon as an advertisement matching the target identifier is
// seen. The match field depends on kind: MAC and UUID compare against
// sr.Address.String(); name compares against sr.LocalName(). Honours
// ctx cancellation by calling StopScan, which causes the adapter's
// Scan loop to return.
//
// Each scan result is logged at Debug level (address, RSSI, local
// name) so operators can pattern-match the target device out of a
// crowded RF environment if the expected identifier is never seen.
func scanForAddress(ctx context.Context, adapter *bluetooth.Adapter, kind addrKind, target string) (bluetooth.Address, error) {
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
			addrStr := sr.Address.String()
			name := sr.LocalName()
			slog.Debug("transport/ble: scan result",
				"addr", addrStr, "rssi", sr.RSSI, "name", name)
			var matched bool
			switch kind {
			case addrKindMAC, addrKindUUID:
				matched = strings.EqualFold(addrStr, target)
			case addrKindName:
				matched = strings.EqualFold(name, target)
			}
			if !matched {
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
		return bluetooth.Address{}, fmt.Errorf("transport: BLE scan ended without finding %s %s", kind, target)
	case <-scanCtx.Done():
		stopped.Store(true)
		_ = adapter.StopScan()
		<-scanDone
		if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
			hint := "is it advertising? pair it once via your OS Bluetooth settings first"
			if runtime.GOOS == "darwin" && kind == addrKindMAC {
				hint = "macOS hides hardware MACs; use `promptzero --ble-discover` to find the per-machine UUID and connect via ble://<uuid>"
			} else if runtime.GOOS == "darwin" {
				hint = "run `promptzero --ble-discover` to enumerate visible peripherals"
			}
			return bluetooth.Address{}, fmt.Errorf(
				"transport: no flipper found with %s %s within %s — %s",
				kind, target, bleScanTimeout, hint,
			)
		}
		return bluetooth.Address{}, scanCtx.Err()
	}
}

// resolveAddress is the platform-aware "find my Flipper" step. On
// darwin with a UUID-form identifier it skips scanning entirely and
// returns a synthetic Address that Adapter.Connect resolves via
// CoreBluetooth's retrievePeripherals(withIdentifiers:) — the
// canonical reconnect-by-stored-identifier pattern (Apple's
// "Best Practices for Interacting with a Remote Peripheral Device").
// All other paths (Linux/Windows; darwin with MAC or name) scan.
//
// The bool return signals "fast path was taken" so the caller can
// optionally fall back to scan if Connect fails — the fast-path
// Address may correspond to a peripheral that CoreBluetooth has
// dropped from its cache (BT stack restart, peripheral unpaired
// elsewhere, etc.).
func (t *bleTransport) resolveAddress(ctx context.Context, adapter *bluetooth.Adapter) (bluetooth.Address, bool, error) {
	if t.addrKind == addrKindUUID && runtime.GOOS == "darwin" {
		if addr, ok := tryDirectConnectAddr(t.addr); ok {
			slog.Debug("transport/ble: darwin direct-connect path", "uuid", t.addr)
			return addr, true, nil
		}
	}
	addr, err := scanForAddress(ctx, adapter, t.addrKind, t.addr)
	return addr, false, err
}

// DiscoveredDevice is one peripheral seen during a Discover scan.
// Address.String() is OS-dependent (MAC on Linux/Windows, CoreBluetooth
// UUID on darwin); Name is whatever LocalName the peripheral
// advertised, or empty.
type DiscoveredDevice struct {
	Address string
	Name    string
	RSSI    int16
}

// Discover scans for nearby BLE peripherals and returns one entry per
// distinct address seen, deduplicated and sorted by RSSI (strongest
// first). Used by the --ble-discover CLI flag so operators can find
// their Flipper's stable identifier without grepping debug logs.
//
// The scan runs for at most timeout, or until ctx is cancelled. A
// nil-or-empty result with no error means the adapter is up but no
// peripherals were heard — usually indicates BT is off on the
// surrounding devices, not a tool failure.
func Discover(ctx context.Context, timeout time.Duration) ([]DiscoveredDevice, error) {
	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return nil, fmt.Errorf("transport: enabling BLE adapter: %w", err)
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stopped atomic.Bool
	scanDone := make(chan error, 1)
	var mu sync.Mutex
	seen := make(map[string]DiscoveredDevice)

	go func() {
		err := adapter.Scan(func(a *bluetooth.Adapter, sr bluetooth.ScanResult) {
			if stopped.Load() {
				return
			}
			addrStr := sr.Address.String()
			mu.Lock()
			prev, ok := seen[addrStr]
			// Keep the strongest sighting and any non-empty name.
			d := DiscoveredDevice{Address: addrStr, RSSI: sr.RSSI, Name: sr.LocalName()}
			if ok {
				if prev.Name != "" && d.Name == "" {
					d.Name = prev.Name
				}
				if prev.RSSI > d.RSSI {
					d.RSSI = prev.RSSI
				}
			}
			seen[addrStr] = d
			mu.Unlock()
		})
		scanDone <- err
	}()

	select {
	case err := <-scanDone:
		if err != nil {
			return nil, fmt.Errorf("transport: BLE scan error: %w", err)
		}
	case <-scanCtx.Done():
		stopped.Store(true)
		_ = adapter.StopScan()
		<-scanDone
	}

	mu.Lock()
	out := make([]DiscoveredDevice, 0, len(seen))
	for _, d := range seen {
		out = append(out, d)
	}
	mu.Unlock()

	// Strongest signal first; ties broken by name then address for
	// deterministic output across runs.
	sortDiscovered(out)
	return out, nil
}

func sortDiscovered(d []DiscoveredDevice) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0; j-- {
			if discoveredLess(d[j], d[j-1]) {
				d[j], d[j-1] = d[j-1], d[j]
				continue
			}
			break
		}
	}
}

func discoveredLess(a, b DiscoveredDevice) bool {
	if a.RSSI != b.RSSI {
		return a.RSSI > b.RSSI
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Address < b.Address
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

// Write sends p to the Flipper via the TX characteristic. BLE ATT
// payloads are bounded by the negotiated MTU minus the 3-byte header,
// so writes larger than t.mtu are chunked into consecutive
// WriteWithoutResponse calls. WriteWithoutResponse is preferred over
// Write because the Flipper's BLE serial service does not ACK
// individual writes at the GATT layer — the application-level prompt
// response (read back via notifications) is what confirms delivery.
//
// The characteristic handle is snapshot under mu before the chunk
// loop so a concurrent Close or Reconnect doesn't mutate txChar
// mid-write, but the actual library call is made outside the lock so
// a stalled write cannot block readers in onNotify. A Close or error
// mid-loop returns the bytes successfully sent so far, matching
// io.Writer's partial-write contract.
func (t *bleTransport) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, os.ErrClosed
	}
	if t.device == nil {
		t.mu.Unlock()
		return 0, fmt.Errorf("transport: ble write before Dial on %s", t.addr)
	}
	txChar := t.txChar
	chunkSize := t.mtu
	if chunkSize <= 0 {
		chunkSize = bleDefaultMTU - attHeaderOverhead
	}
	t.mu.Unlock()

	total := 0
	for total < len(p) {
		end := total + chunkSize
		if end > len(p) {
			end = len(p)
		}
		n, err := txChar.WriteWithoutResponse(p[total:end])
		total += n
		if err != nil {
			return total, fmt.Errorf("transport: BLE write to %s: %w", t.addr, err)
		}
		if n == 0 {
			return total, fmt.Errorf("transport: BLE write to %s returned 0 bytes", t.addr)
		}
	}
	return total, nil
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

// Reconnect tears down the current peripheral connection and re-runs
// the Dial pipeline. Used by the flipper layer when a Read or Write
// surfaces a disconnect-class error (the Transport contract says the
// caller is responsible for driving Reconnect; we do not auto-
// reconnect from inside onNotify because the library's notification
// goroutine must return quickly).
//
// The old device handle is Disconnected outside the lock — BlueZ's
// Disconnect can block on DBus for several seconds if the peripheral
// already dropped — and readErr is cleared inside establish so a Read
// parked with a stale latched error picks up the new connection.
func (t *bleTransport) Reconnect(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return os.ErrClosed
	}
	oldDevice := t.device
	t.device = nil
	t.adapter = nil
	t.txChar = bluetooth.DeviceCharacteristic{}
	t.rxChar = bluetooth.DeviceCharacteristic{}
	t.readBuf.Reset()
	t.mu.Unlock()

	if oldDevice != nil {
		if err := oldDevice.Disconnect(); err != nil {
			slog.Debug("transport/ble: disconnect during reconnect returned error (continuing)",
				"mac", t.addr, "err", err)
		}
	}

	return t.establish(ctx)
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
		return fmt.Errorf("transport: BLE disconnect from %s: %w", t.addr, err)
	}
	return nil
}

// Identity returns the stable "ble://<MAC>" URL used for logging and
// /status output. The MAC is already uppercased in bleDialer so this
// is a pure formatter.
func (t *bleTransport) Identity() string { return "ble://" + t.addr }

// Kind returns the "ble" telemetry tag.
func (t *bleTransport) Kind() string { return "ble" }

// DrainTimeout returns the BLE-tuned 250 ms interval used by the
// flipper layer's post-command drain loop. See bleDrainTimeout for
// the rationale.
func (t *bleTransport) DrainTimeout() time.Duration { return bleDrainTimeout }
