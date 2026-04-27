// Package marauder — BLE transport for standalone ESP32-Marauder devboards.
//
// This transport targets ESP32-Marauder firmware running its own Nordic-UART-
// style BLE serial service (https://github.com/justcallmekoko/ESP32Marauder),
// NOT the Flipper Zero. It mirrors the layout of internal/flipper/transport/ble.go
// without the firmware-specific extras: no flow-control characteristic, no
// fork-detection, no RPC layer. Writes are bounded by the negotiated ATT MTU
// only; the wire surface is a transparent bidirectional serial pipe.
//
// Build constraint: this file is excluded on darwin without CGO because
// tinygo.org/x/bluetooth pulls in github.com/tinygo-org/cbgo on darwin, which
// needs CGO + the macOS SDK to compile. The cross-compile CI matrix builds
// darwin from a Linux host without CGO, so a sibling transport_ble_darwin.go
// provides a stub constructor that returns a clear error. Real BLE on macOS is
// unlocked by building on a Mac (GOOS=darwin CGO_ENABLED=1 go build).
//
// Testing note: BLE does not work under WSL2. The Windows Subsystem for Linux
// does not expose Bluetooth to the Linux guest, so this transport cannot be
// exercised in a WSL session. To test against real hardware, run from a native
// Linux desktop or Windows session with a paired devboard.

//go:build !darwin || (darwin && cgo)

package marauder

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

// marauderBLEServiceUUID is the 128-bit UUID of the Nordic-UART-style serial
// service exposed by ESP32-Marauder firmware. Standard ESP32 Arduino BLE
// "serial" service per
// https://github.com/justcallmekoko/ESP32Marauder/blob/master/esp32_marauder/MenuFunctions.cpp
// (search for the BLEService constructor). The same UUID is used by the
// V3SP3R MarauderBridge reference at
// https://github.com/elder-plinius/V3SP3R/blob/main/app/src/main/java/com/vesper/flipper/ble/MarauderBridge.kt.
var marauderBLEServiceUUID = mustParseMarauderUUID("4fafc201-1fb5-459e-8fcc-c5c9c331914b")

// marauderBLETXCharUUID is the host→Marauder write characteristic. The host
// writes plain-text Marauder commands (`scanap`, `attack -t deauth -ssid "…"`
// etc.) here. Properties typically include WriteWithoutResponse and Write.
//
// Naming follows the host-perspective convention used by the Marauder firmware
// and the V3SP3R reference: TX is "host-transmits-to-board".
var marauderBLETXCharUUID = mustParseMarauderUUID("beb5483e-36e1-4688-b7f5-ea07361b26a8")

// marauderBLERXCharUUID is the Marauder→host notify characteristic. The host
// subscribes here and receives the firmware's text output as notification
// packets. Properties typically include Notify.
//
// Naming follows the host-perspective convention: RX is "host-receives-from-board".
var marauderBLERXCharUUID = mustParseMarauderUUID("beb5483e-36e1-4688-b7f5-ea07361b26a9")

// bleScanTimeout bounds the Dial scan phase. Standard ESP32 advertisements
// arrive in ~100ms intervals; 30s tolerates momentarily weak RSSI without
// hanging a human-driven CLI indefinitely.
const bleScanTimeout = 30 * time.Second

// bleDefaultMTU is the BLE spec's minimum ATT MTU (23 bytes total, 3 of which
// are ATT overhead so the usable payload per characteristic write is 20).
// Used as the fallback when GetMTU() fails.
const bleDefaultMTU = 23

// bleMaxMTU is the BLE 5 maximum ATT MTU. GetMTU() results above this bound
// are clamped to keep Write chunk sizes sane.
const bleMaxMTU = 512

// attHeaderOverhead is the fixed 3-byte ATT overhead (op-code + handle) that
// must be subtracted from the negotiated MTU to get the per-write payload size.
const attHeaderOverhead = 3

// mustParseMarauderUUID parses a UUID literal or panics. Used only for the
// package-level UUID constants so a typo fails at init time rather than
// mid-dial.
func mustParseMarauderUUID(s string) bluetooth.UUID {
	u, err := bluetooth.ParseUUID(s)
	if err != nil {
		panic(fmt.Sprintf("marauder/ble: invalid UUID literal %q: %v", s, err))
	}
	return u
}

// reverseUUID returns the byte-reversed form of a 128-bit UUID. Used to
// normalise comparison against darwin's little-endian form of custom UUIDs.
// Same dance as the Flipper transport — see internal/flipper/transport/ble.go
// for the long-form rationale.
func reverseUUID(u bluetooth.UUID) bluetooth.UUID {
	hex := strings.ReplaceAll(u.String(), "-", "")
	if len(hex) != 32 {
		return u
	}
	rev := make([]byte, 32)
	for i := 0; i < 16; i++ {
		rev[(15-i)*2] = hex[i*2]
		rev[(15-i)*2+1] = hex[i*2+1]
	}
	canonical := fmt.Sprintf("%s-%s-%s-%s-%s",
		rev[0:8], rev[8:12], rev[12:16], rev[16:20], rev[20:32])
	parsed, err := bluetooth.ParseUUID(canonical)
	if err != nil {
		return u
	}
	return parsed
}

// uuidsMatch reports whether two 128-bit UUIDs are equal in either canonical
// or byte-reversed (little-endian-on-the-wire) form.
func uuidsMatch(got, want bluetooth.UUID) bool {
	if got == want {
		return true
	}
	return got == reverseUUID(want)
}

// bleAddrKind classifies the form of a BLE address supplied via ble:// URLs.
// The form determines how scanForAddress matches against advertisements and
// whether dial can take the darwin direct-connect fast path.
type bleAddrKind int

const (
	// bleAddrKindMAC is a 6-octet hardware MAC. Linux + Windows.
	bleAddrKindMAC bleAddrKind = iota

	// bleAddrKindUUID is the canonical 8-4-4-4-12 CoreBluetooth peripheral
	// identifier. darwin-only, per-Mac-stable.
	bleAddrKindUUID

	// bleAddrKindName matches the BLE advertising LocalName. Cross-platform
	// fallback; not authoritative — names are not unique.
	bleAddrKindName
)

func (k bleAddrKind) String() string {
	switch k {
	case bleAddrKindMAC:
		return "MAC"
	case bleAddrKindUUID:
		return "UUID"
	case bleAddrKindName:
		return "name"
	}
	return "address"
}

// bleAddrUUIDPattern matches the canonical 8-4-4-4-12 CoreBluetooth UUID form.
var bleAddrUUIDPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

// parseMarauderBLEAddress recognises three URL forms by shape:
//
//   - MAC  ("80:E1:26:69:6E:55") — 6 octets via net.ParseMAC. Linux/Windows.
//   - UUID ("e127efc1-05ec-…")   — CoreBluetooth identifier. darwin only.
//   - Name ("Marauder")          — anything else, matched against advertising
//     LocalName at scan time.
//
// MAC normalises to uppercase canonical form; UUID to lowercase; names round-
// trip verbatim with surrounding whitespace stripped (case-insensitive
// matching happens at scan time).
func parseMarauderBLEAddress(s string) (bleAddrKind, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, "", errors.New("empty BLE address")
	}
	if mac, err := net.ParseMAC(s); err == nil && len(mac) == 6 {
		return bleAddrKindMAC, strings.ToUpper(mac.String()), nil
	}
	if bleAddrUUIDPattern.MatchString(s) {
		return bleAddrKindUUID, strings.ToLower(s), nil
	}
	return bleAddrKindName, s, nil
}

// stripBLEScheme accepts either a bare address ("AA:BB:…") or a "ble://<addr>"
// URL and returns just the address portion. We don't use net/url.Parse here
// because MAC addresses look like host:port to it ("AA:BB:CC:DD:EE:FF" trips
// "invalid port" errors). The hand-rolled split mirrors flipper/transport's
// splitScheme.
func stripBLEScheme(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", errors.New("marauder/ble: empty address")
	}
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		// Bare address (no scheme). Tolerate any non-empty form; the address
		// classifier downstream will validate the shape.
		return rawURL, nil
	}
	scheme := rawURL[:idx]
	rest := rawURL[idx+3:]
	if scheme != "" && scheme != "ble" {
		return "", fmt.Errorf("marauder/ble: expected ble:// scheme, got %q", scheme)
	}
	// Strip a trailing query string (kept for forward-compat with future
	// per-connection tunables; nothing consumes it today).
	if qi := strings.Index(rest, "?"); qi >= 0 {
		rest = rest[:qi]
	}
	if rest == "" {
		return "", fmt.Errorf("marauder/ble: empty path in URL %q", rawURL)
	}
	return rest, nil
}

// marauderBLEPort is an io.ReadWriteCloser + SetReadTimeout that owns a BLE
// connection to one ESP32-Marauder peripheral. Implements the unexported
// `Port` interface declared in marauder.go so a single *Marauder shape works
// for both the serial and BLE backends.
type marauderBLEPort struct {
	addr     string
	addrKind bleAddrKind

	// adapter, device, and the two characteristics are set by dial and read
	// from every other method. They are only meaningful when closed is false
	// and dial has returned nil.
	adapter *bluetooth.Adapter
	device  *bluetooth.Device
	txChar  bluetooth.DeviceCharacteristic // host → board write
	rxChar  bluetooth.DeviceCharacteristic // board → host notify

	// mtu is the per-write payload size (negotiated ATT MTU minus 3-byte ATT
	// header). Set at dial time; used in Write to chunk larger payloads.
	mtu int

	// mu guards every mutable field below and is the sync.Locker for readCond.
	mu sync.Mutex

	// readCond signals Read-blockers when data is appended to readBuf, readErr
	// is latched, or closed flips to true.
	readCond *sync.Cond

	// readBuf accumulates bytes delivered by the RX notification callback;
	// Read drains from the front.
	readBuf bytes.Buffer

	// readErr latches a terminal error (e.g. disconnect). Once set, subsequent
	// Reads return it without blocking.
	readErr error

	// closed is true after Close. Subsequent Reads return os.ErrClosed;
	// subsequent Closes are no-ops (Close is idempotent).
	closed bool

	// readTimeout bounds the next Read. Zero means "block until data, close,
	// or error"; non-zero means "block up to this long, then return (0, nil)
	// if nothing arrives" — mirroring the serial.Port.Read convention the
	// existing Marauder readUntilPrompt loop relies on.
	readTimeout time.Duration
}

// newMarauderBLEPort constructs an undialled port keyed by the given address
// string. Whitespace is trimmed; the input may be either a bare address or a
// ble:// URL.
func newMarauderBLEPort(rawAddr string) (*marauderBLEPort, error) {
	addr, err := stripBLEScheme(rawAddr)
	if err != nil {
		return nil, err
	}
	kind, normalised, err := parseMarauderBLEAddress(addr)
	if err != nil {
		return nil, fmt.Errorf("marauder/ble: %w", err)
	}
	p := &marauderBLEPort{
		addr:     normalised,
		addrKind: kind,
		mtu:      bleDefaultMTU - attHeaderOverhead,
	}
	p.readCond = sync.NewCond(&p.mu)
	return p, nil
}

// dial enables the adapter and runs scan → connect → discover → notify-enable
// → MTU negotiation. Honours ctx cancellation throughout.
func (p *marauderBLEPort) dial(ctx context.Context) error {
	p.mu.Lock()
	if p.adapter != nil {
		p.mu.Unlock()
		return fmt.Errorf("marauder/ble: already dialled (%s)", p.addr)
	}
	if p.closed {
		p.mu.Unlock()
		return os.ErrClosed
	}
	p.mu.Unlock()

	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return fmt.Errorf("marauder/ble: enabling adapter: %w", err)
	}

	addr, fast, err := p.resolveAddress(ctx, adapter)
	if err != nil {
		return err
	}

	device, err := adapter.Connect(addr, bluetooth.ConnectionParams{})
	if err != nil {
		if !fast {
			return fmt.Errorf("marauder/ble: connect to %s: %w", p.addr, err)
		}
		slog.Debug("marauder/ble: direct connect failed, retrying via scan",
			"addr", p.addr, "err", err)
		scanAddr, scanErr := scanForMarauderAddress(ctx, adapter, p.addrKind, p.addr)
		if scanErr != nil {
			return fmt.Errorf("marauder/ble: connect to %s: %w (scan fallback also failed: %v)",
				p.addr, err, scanErr)
		}
		device, err = adapter.Connect(scanAddr, bluetooth.ConnectionParams{})
		if err != nil {
			return fmt.Errorf("marauder/ble: connect to %s after scan fallback: %w", p.addr, err)
		}
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = device.Disconnect()
		return ctxErr
	}

	allServices, err := device.DiscoverServices(nil)
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("marauder/ble: service discovery on %s: %w", p.addr, err)
	}
	advertised := make([]string, 0, len(allServices))
	var marauderSvc *bluetooth.DeviceService
	for i := range allServices {
		uuid := allServices[i].UUID()
		advertised = append(advertised, uuid.String())
		if uuidsMatch(uuid, marauderBLEServiceUUID) {
			marauderSvc = &allServices[i]
		}
	}
	slog.Debug("marauder/ble: discovered services", "addr", p.addr, "services", advertised)
	if marauderSvc == nil {
		_ = device.Disconnect()
		return fmt.Errorf(
			"marauder/ble: service %s not found on %s; advertised %v — is this an ESP32-Marauder devboard?",
			marauderBLEServiceUUID.String(), p.addr, advertised,
		)
	}

	chars, err := marauderSvc.DiscoverCharacteristics(nil)
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("marauder/ble: characteristic discovery on %s: %w", p.addr, err)
	}
	tx, rx, err := selectMarauderCharacteristics(chars)
	if err != nil {
		_ = device.Disconnect()
		return err
	}

	if err := rx.EnableNotifications(p.onNotify); err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("marauder/ble: enabling RX notifications on %s: %w", p.addr, err)
	}

	mtu := negotiateMTU(rx)

	p.mu.Lock()
	p.adapter = adapter
	p.device = &device
	p.txChar = tx
	p.rxChar = rx
	p.mtu = mtu
	p.readErr = nil
	p.readCond.Broadcast()
	p.mu.Unlock()

	return nil
}

// negotiateMTU queries the negotiated ATT MTU and returns the usable per-Write
// payload size (negotiated MTU minus 3-byte ATT header). Falls back to the
// BLE spec minimum (23 - 3 = 20) when GetMTU errors. Clamps above bleMaxMTU.
func negotiateMTU(c bluetooth.DeviceCharacteristic) int {
	raw, err := c.GetMTU()
	if err != nil || int(raw) < bleDefaultMTU {
		slog.Warn("marauder/ble: MTU negotiation unavailable; using BLE default",
			"mtu", raw, "err", err, "fallback", bleDefaultMTU)
		return bleDefaultMTU - attHeaderOverhead
	}
	mtu := int(raw)
	if mtu > bleMaxMTU {
		mtu = bleMaxMTU
	}
	return mtu - attHeaderOverhead
}

// onNotify is the RX-characteristic notification callback. Invoked from the
// bluetooth library's notify goroutine — append bytes to readBuf under mu and
// signal Read.
func (p *marauderBLEPort) onNotify(buf []byte) {
	if len(buf) == 0 {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.readBuf.Write(buf)
	p.readCond.Broadcast()
	p.mu.Unlock()
}

// resolveAddress is the platform-aware "find my Marauder" step. On darwin with
// a UUID-form identifier it skips scanning entirely and returns a synthetic
// Address that Adapter.Connect resolves via CoreBluetooth's
// retrievePeripherals(withIdentifiers:). All other paths scan.
//
// The bool return signals "fast path was taken" so the caller can fall back
// to scan if Connect fails — the fast-path Address may correspond to a
// peripheral that CoreBluetooth has dropped from its cache.
func (p *marauderBLEPort) resolveAddress(ctx context.Context, adapter *bluetooth.Adapter) (bluetooth.Address, bool, error) {
	if p.addrKind == bleAddrKindUUID && runtime.GOOS == "darwin" {
		if addr, ok := tryDirectConnectAddrMarauder(p.addr); ok {
			slog.Debug("marauder/ble: darwin direct-connect path", "uuid", p.addr)
			return addr, true, nil
		}
	}
	addr, err := scanForMarauderAddress(ctx, adapter, p.addrKind, p.addr)
	return addr, false, err
}

// scanForMarauderAddress runs a single bounded BLE scan and stops as soon as
// an advertisement matching the target identifier is seen. Honours ctx.
func scanForMarauderAddress(ctx context.Context, adapter *bluetooth.Adapter, kind bleAddrKind, target string) (bluetooth.Address, error) {
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
			slog.Debug("marauder/ble: scan result",
				"addr", addrStr, "rssi", sr.RSSI, "name", name)
			var matched bool
			switch kind {
			case bleAddrKindMAC, bleAddrKindUUID:
				matched = strings.EqualFold(addrStr, target)
			case bleAddrKindName:
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
			return bluetooth.Address{}, fmt.Errorf("marauder/ble: scan error: %w", err)
		}
		return bluetooth.Address{}, fmt.Errorf("marauder/ble: scan ended without finding %s %s", kind, target)
	case <-scanCtx.Done():
		stopped.Store(true)
		_ = adapter.StopScan()
		<-scanDone
		if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
			hint := "is the devboard advertising? typical names: \"ESP32-S3\", \"Marauder\""
			if runtime.GOOS == "darwin" && kind == bleAddrKindMAC {
				hint = "macOS hides hardware MACs; use `promptzero --ble-discover` to find the per-machine UUID and connect via ble://<uuid>"
			} else if runtime.GOOS == "darwin" {
				hint = "run `promptzero --ble-discover` to enumerate visible peripherals"
			}
			return bluetooth.Address{}, fmt.Errorf(
				"marauder/ble: no devboard found with %s %s within %s — %s",
				kind, target, bleScanTimeout, hint,
			)
		}
		return bluetooth.Address{}, scanCtx.Err()
	}
}

// selectMarauderCharacteristics resolves the TX/RX serial characteristics from
// the list returned by DiscoverCharacteristics. Both are mandatory — without
// them we can't send commands or receive output. Returns descriptive errors
// naming every discovered UUID so debugging starts informed.
func selectMarauderCharacteristics(chars []bluetooth.DeviceCharacteristic) (tx, rx bluetooth.DeviceCharacteristic, err error) {
	discovered := make([]string, 0, len(chars))
	var txHit, rxHit *bluetooth.DeviceCharacteristic
	for i := range chars {
		u := chars[i].UUID()
		discovered = append(discovered, u.String())
		switch {
		case uuidsMatch(u, marauderBLETXCharUUID):
			txHit = &chars[i]
		case uuidsMatch(u, marauderBLERXCharUUID):
			rxHit = &chars[i]
		}
	}
	slog.Debug("marauder/ble: discovered characteristics",
		"uuids", discovered,
		"expectedTX", marauderBLETXCharUUID.String(),
		"expectedRX", marauderBLERXCharUUID.String())

	missing := make([]string, 0, 2)
	if txHit == nil {
		missing = append(missing, "TX/"+marauderBLETXCharUUID.String())
	}
	if rxHit == nil {
		missing = append(missing, "RX/"+marauderBLERXCharUUID.String())
	}
	if len(missing) > 0 {
		return bluetooth.DeviceCharacteristic{}, bluetooth.DeviceCharacteristic{}, fmt.Errorf(
			"marauder/ble: missing required characteristic(s) %v; discovered %v — firmware rev may have changed the layout",
			missing, discovered,
		)
	}
	return *txHit, *rxHit, nil
}

// Read drains up to len(p) bytes from the internal buffer populated by
// onNotify. Same blocking semantics as the serial Marauder client: with a
// non-zero readTimeout returns (0, nil) when the timeout elapses without any
// bytes; with a zero readTimeout blocks until data, Close, or a latched error.
func (p *marauderBLEPort) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	timeout := p.readTimeout
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}

	for {
		if p.readBuf.Len() > 0 {
			return p.readBuf.Read(b)
		}
		if p.closed {
			return 0, os.ErrClosed
		}
		if p.readErr != nil {
			return 0, p.readErr
		}
		if timeout == 0 {
			p.readCond.Wait()
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil
		}
		waitCondTimeout(p.readCond, remaining)
	}
}

// waitCondTimeout waits on cond for at most d, then broadcasts to unblock the
// wait. Must be called with cond.L held; on return the lock is still held.
func waitCondTimeout(cond *sync.Cond, d time.Duration) {
	timer := time.AfterFunc(d, func() {
		cond.L.Lock()
		cond.Broadcast()
		cond.L.Unlock()
	})
	defer timer.Stop()
	cond.Wait()
}

// Write sends b to the Marauder via the TX characteristic. Payloads larger
// than the per-chunk MTU minus the 3-byte ATT header are split into
// consecutive WriteWithoutResponse calls. No flow-control credit machinery —
// the ESP32-Marauder firmware doesn't expose a credit characteristic.
func (p *marauderBLEPort) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, os.ErrClosed
	}
	if p.device == nil {
		p.mu.Unlock()
		return 0, fmt.Errorf("marauder/ble: write before Dial on %s", p.addr)
	}
	txChar := p.txChar
	maxChunk := p.mtu
	if maxChunk <= 0 {
		maxChunk = bleDefaultMTU - attHeaderOverhead
	}
	p.mu.Unlock()

	total := 0
	for total < len(b) {
		remaining := len(b) - total
		chunkSize := maxChunk
		if remaining < chunkSize {
			chunkSize = remaining
		}
		n, err := txChar.WriteWithoutResponse(b[total : total+chunkSize])
		total += n
		if err != nil {
			return total, fmt.Errorf("marauder/ble: write to %s: %w", p.addr, err)
		}
		if n == 0 {
			return total, fmt.Errorf("marauder/ble: write to %s returned 0 bytes", p.addr)
		}
	}
	return total, nil
}

// SetReadTimeout reconfigures how long the next Read will block before
// returning (0, nil). Zero means "block indefinitely until data, close, or
// error" — matching the serial backend's contract.
func (p *marauderBLEPort) SetReadTimeout(d time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return os.ErrClosed
	}
	p.readTimeout = d
	p.readCond.Broadcast()
	return nil
}

// Close disconnects the peripheral, latches closed=true, and signals any
// goroutines blocked in Read so they return os.ErrClosed. Idempotent —
// subsequent calls return nil.
func (p *marauderBLEPort) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	device := p.device
	p.device = nil
	p.readCond.Broadcast()
	p.mu.Unlock()

	if device == nil {
		return nil
	}
	if err := device.Disconnect(); err != nil {
		return fmt.Errorf("marauder/ble: disconnect from %s: %w", p.addr, err)
	}
	return nil
}

// dialMarauderBLE is the package-internal entry point used by ConnectBLE.
// Returns a dialled *marauderBLEPort that satisfies the unexported Port
// interface declared in marauder.go.
func dialMarauderBLE(ctx context.Context, rawAddr string) (*marauderBLEPort, error) {
	p, err := newMarauderBLEPort(rawAddr)
	if err != nil {
		return nil, err
	}
	if err := p.dial(ctx); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}
