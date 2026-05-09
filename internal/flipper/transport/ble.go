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

	"github.com/xunholy/promptzero/internal/obs"
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
//
// On darwin (CoreBluetooth via cbgo) custom UUIDs come back in
// little-endian byte order — the Flipper's canonical serial UUID
// 0000fe60-cc7a-482a-984a-7f2ed5b3e58f is reported as
// 8fe5b3d5-2e7f-4a98-2a48-7acc60fe0000. uuidsMatch handles both
// endiannesses so the same hardcoded canonical form works on every
// platform. Standard 16-bit-derived UUIDs (Battery, Device Info)
// are handled correctly by the OS layer and don't need this dance.
var flipperBLEServiceUUID = mustParseUUID("0000fe60-cc7a-482a-984a-7f2ed5b3e58f")

// reverseUUID returns the byte-reversed form of a 128-bit UUID. Used
// to normalise comparison against darwin's little-endian form of
// custom service / characteristic UUIDs without introducing per-OS
// branches at every match site.
//
// Implemented via the canonical hex string rather than UUID.Bytes()
// because tinygo.org/x/bluetooth's UUID is a [4]uint32 whose Bytes()
// + NewUUID round-trip doesn't surface the on-the-wire byte order
// the same way per-platform — the string form is the only stable
// 16-byte projection across Linux/Windows/Darwin.
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

// uuidsMatch reports whether two 128-bit UUIDs are equal in either
// canonical or byte-reversed form. The reversed form is the
// little-endian-on-the-wire representation that cbgo surfaces on
// darwin for custom UUIDs; comparing both forms keeps every call
// site OS-agnostic.
func uuidsMatch(got, want bluetooth.UUID) bool {
	if got == want {
		return true
	}
	return got == reverseUUID(want)
}

// Flipper BLE Serial GATT layout. Names match the firmware enum in
// flipperdevices/flipperzero-firmware
// targets/f7/ble_glue/services/serial_service.c (lines 14-62) — RX is
// the host-writes-to-flipper characteristic, TX is the flipper-writes-
// back-to-host characteristic, both from the Flipper's perspective.
// Earlier revisions of this file had RX/TX swapped (they were named
// from the host's perspective), which made every Write go to a
// characteristic with Indicate-only properties and every Read wait on
// a characteristic with Write-only properties — the firmware silently
// dropped traffic and Ping handshakes timed out. The two-byte CCCDs
// are written by EnableNotifications/EnableIndications via the
// underlying tinygo bluetooth library.
//
// FlowControl publishes a uint32 buffer credit (big-endian, see
// serial_service.c:188-208) every time the firmware drains its inbound
// fifo. The host MUST subscribe and MUST NOT send more than the most
// recently advertised credit's worth of bytes between updates. Skipping
// this step is what made the early skip-RPC handshake hang.
//
// RPCStatus is informational: 0 = inactive, 1 = active. We don't
// touch it; observation only.
var (
	// flipperBLERXCharUUID is the host→flipper write characteristic
	// (serial_service.c:[SerialSvcGattCharacteristicRx],
	// serial_service_uuid.inc:BLE_SVC_SERIAL_RX_CHAR_UUID = ...fe62...).
	// Properties: Write, WriteWithoutResponse, Read. Names are from
	// the FLIPPER's perspective: "RX" means flipper-receives-here, so
	// this is where the host writes RPC bytes.
	flipperBLERXCharUUID = mustParseUUID("19ed82ae-ed21-4c9d-4145-228e62fe0000")

	// flipperBLETXCharUUID is the flipper→host indicate characteristic
	// (serial_service.c:[SerialSvcGattCharacteristicTx],
	// serial_service_uuid.inc:BLE_SVC_SERIAL_TX_CHAR_UUID = ...fe61...).
	// Properties: Read, Indicate. "TX" means flipper-transmits-here, so
	// the host subscribes to receive RPC responses. Despite the spec
	// distinguishing notify vs indicate, tinygo's EnableNotifications
	// writes the appropriate CCCD bit based on the characteristic's
	// properties — it works for either.
	flipperBLETXCharUUID = mustParseUUID("19ed82ae-ed21-4c9d-4145-228e61fe0000")

	// flipperBLEFlowControlCharUUID publishes uint32 BE buffer credits
	// (serial_service.c:43-52: SerialSvcGattCharacteristicFlowCtrl).
	// Properties: Read, Notify. Subscription is mandatory for RPC
	// traffic to flow.
	flipperBLEFlowControlCharUUID = mustParseUUID("19ed82ae-ed21-4c9d-4145-228e63fe0000")

	// flipperBLERPCStatusCharUUID is informational
	// (serial_service.c:53-62: SerialSvcGattCharacteristicStatus).
	// Properties: Read, Write, Notify. Read returns 0=NotActive,
	// 1=Active. Writing 0 triggers an internal BleResetRequest
	// (serial_service.c:117-128) — we never write here.
	flipperBLERPCStatusCharUUID = mustParseUUID("19ed82ae-ed21-4c9d-4145-228e64fe0000")
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
	t.creditCond = sync.NewCond(&t.mu)
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

	// adapter, device, and the four serial characteristics are set
	// exclusively within Dial (or Reconnect) under mu, and read from
	// every other method. They are only meaningful when closed is false
	// and Dial has returned nil at least once.
	//
	// rxChar is the host-writes-here characteristic (firmware name:
	// SerialSvcGattCharacteristicRx). txChar is the
	// flipper-indicates-back-here characteristic (firmware name:
	// SerialSvcGattCharacteristicTx). flowChar publishes uint32 BE
	// buffer-credit notifications (firmware name:
	// SerialSvcGattCharacteristicFlowCtrl).
	adapter  *bluetooth.Adapter
	device   *bluetooth.Device
	rxChar   bluetooth.DeviceCharacteristic
	txChar   bluetooth.DeviceCharacteristic
	flowChar bluetooth.DeviceCharacteristic

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

	// credit is the most recent flow-control credit advertised by the
	// firmware via the FlowCtrl characteristic — the maximum number of
	// bytes the host may have outstanding before pausing. Each Write
	// decrements credit by the number of bytes successfully sent;
	// every flow-control notification overwrites credit with the new
	// per-update value (firmware refreshes its inbound fifo
	// periodically). Guarded by mu; creditCond signals waiters when
	// the value increases or close flips.
	credit uint32

	// creditReady is true once the firmware has delivered the initial
	// flow-control credit notification. Dial waits for this before
	// returning to ensure the upper layer doesn't try to write before
	// we know how big the firmware buffer is. Cleared on Reconnect.
	creditReady bool

	// creditCond signals goroutines parked in Write that credit has
	// increased (a fresh flow-control notification arrived) or that
	// the transport is closing.
	creditCond *sync.Cond
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

	// DiscoverServices(nil) — enumerate every advertised service rather
	// than asking for one specific UUID. CoreBluetooth on darwin
	// occasionally fails the filtered form when the GATT cache hasn't
	// been primed (post-reconnect via retrievePeripherals), and the
	// unfiltered call also gives a useful diagnostic when the firmware
	// has rev'd the service UUID — we log what was actually discovered.
	allServices, err := device.DiscoverServices(nil)
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: BLE service discovery on %s: %w — is BLE enabled in Flipper Settings > Bluetooth?", t.addr, err)
	}
	services := make([]bluetooth.DeviceService, 0, 1)
	advertised := make([]string, 0, len(allServices))
	for _, s := range allServices {
		uuid := s.UUID()
		advertised = append(advertised, uuid.String())
		if uuidsMatch(uuid, flipperBLEServiceUUID) {
			services = append(services, s)
		}
	}
	slog.Debug("transport/ble: discovered services", "addr", t.addr, "services", advertised)
	if len(services) == 0 {
		_ = device.Disconnect()
		return fmt.Errorf("transport: flipper BLE service %s not found on %s; advertised services were %v — firmware rev may have changed the service UUID", flipperBLEServiceUUID.String(), t.addr, advertised)
	}

	chars, err := services[0].DiscoverCharacteristics(nil)
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: BLE characteristic discovery on %s: %w", t.addr, err)
	}
	set, err := selectFlipperCharacteristics(chars)
	if err != nil {
		_ = device.Disconnect()
		return err
	}

	// Subscribe to FlowCtrl so future credit updates land on
	// onFlowControl. The firmware's buffer-empty publisher
	// (serial_service.c:195-211) refreshes the credit each time it
	// drains its inbound fifo — that's the steady-state signal we
	// honour. The boot-time credit notification fires once during
	// ble_svc_serial_set_callbacks (line 188-192) before our
	// subscription completes, so we cannot count on it as a handshake
	// gate. Reading the characteristic instead would require an
	// authenticated GATT read, which CoreBluetooth on darwin
	// occasionally times out on freshly-connected peripherals; we
	// don't depend on it.
	//
	// Pragmatic fallback: prime credit to BLE_SVC_SERIAL_DATA_LEN_MAX
	// (486, per serial_service.h), the firmware's hardcoded inbound
	// fifo size. The Write throttler will then meter outbound chunks
	// against this until a real notification updates it. The firmware
	// only LOGS a warning if we overrun before draining — it does not
	// reject the bytes — so being a bit optimistic is safe.
	if err := set.flow.EnableNotifications(t.onFlowControl); err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: enabling flow-control notifications on %s: %w", t.addr, err)
	}

	// Subscribe to RPCStatus (informational — uint32 0=NotActive,
	// 1=Active). Some firmware revisions gate the flow-control
	// publisher behind an "all required subscriptions present" check;
	// subscribing here is cheap and matches what the official Flipper
	// Mobile app does. We only observe — never write 0, which would
	// trigger an internal BleResetRequest (serial_service.c:117-128).
	if set.status != (bluetooth.DeviceCharacteristic{}) {
		if err := set.status.EnableNotifications(t.onRPCStatus); err != nil {
			slog.Debug("transport/ble: enabling RPC status notifications failed (continuing)",
				"addr", t.addr, "err", err)
		}
	}

	// Subscribe to TX (flipper→host indications carry RPC responses).
	// tinygo's EnableNotifications writes the appropriate CCCD bit
	// based on the characteristic's properties — works for both
	// Notify-only and Indicate-only chars per upstream docs.
	if err := set.tx.EnableNotifications(t.onNotify); err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("transport: enabling TX indications on %s: %w", t.addr, err)
	}

	mtu := negotiateMTU(set.tx)

	t.mu.Lock()
	t.adapter = adapter
	t.device = &device
	t.rxChar = set.rx
	t.txChar = set.tx
	t.flowChar = set.flow
	t.mtu = mtu
	t.readErr = nil
	// Prime credit optimistically (see comment above). Real updates
	// from the firmware's buffer-empty publisher will overwrite this
	// the first time the firmware drains its fifo.
	t.credit = bleDefaultStartCredit
	t.creditReady = true
	t.readCond.Broadcast()
	t.creditCond.Broadcast()
	t.mu.Unlock()

	return nil
}

// bleDefaultStartCredit matches the firmware's BLE_SVC_SERIAL_DATA_LEN_MAX
// (serial_service.h:14 — value 486). Used as the initial credit when
// the boot-time FlowCtrl notification arrives before our subscription
// completes (it nearly always does on darwin). Lets the first Write
// proceed; subsequent FlowCtrl notifications from
// ble_svc_serial_notify_buffer_is_empty (serial_service.c:195-211)
// keep credit current after that.
const bleDefaultStartCredit = 486

// onRPCStatus is the RPC-status characteristic notification callback.
// The firmware publishes a uint32 (LE on the wire here per the
// existing ble_glue handlers — different from FlowCtrl's BE) where
// 0 means "RPC not active" and 1 means "RPC active". We only log; the
// firmware drives this autonomously and never expects the host to
// react. Body shorter than 4 bytes is ignored as malformed.
func (t *bleTransport) onRPCStatus(buf []byte) {
	if len(buf) < 4 {
		slog.Debug("transport/ble: RPC status notification too short", "len", len(buf))
		return
	}
	status := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	slog.Debug("transport/ble: RPC status", "status", status)
}

// onFlowControl is the FlowCtrl characteristic notification callback.
// Firmware sends a 4-byte big-endian uint32 indicating the *new*
// available credit (max bytes the host may have outstanding before
// the firmware drains again). serial_service.c:188-208 confirms the
// big-endian encoding via REVERSE_BYTES_U32 on the LE Cortex-M side.
//
// We replace t.credit with the new value (rather than adding) because
// the firmware publishes an absolute window, not a delta. Wakes any
// Write parked in creditCond.Wait so it can re-check the budget.
func (t *bleTransport) onFlowControl(buf []byte) {
	if len(buf) < 4 {
		slog.Warn("transport/ble: flow-control notification too short", "len", len(buf))
		return
	}
	credit := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.credit = credit
	t.creditReady = true
	t.creditCond.Broadcast()
	t.mu.Unlock()

	slog.Debug("transport/ble: flow-control credit", "credit", credit)
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
	slog.Debug("transport/ble: TX indication received", "len", len(buf), "head", hexHead(buf, 16))
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

	// SafeGo so a panic inside the bluetooth library's scan
	// callback (unexpected ScanResult shape, advert-payload edge
	// case in the upstream lib) is recovered + logged rather
	// than crashing the agent. scanDone has a buffer of 1 so the
	// caller's select unblocks even when SafeGo's recover swallows
	// the panic without forwarding an error.
	obs.SafeGo("transport/ble.scan_for_target", func() {
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
	})

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

	// SafeGo: panic inside the upstream bluetooth library's
	// callback (advert payload corner case, etc.) shouldn't take
	// down the whole agent — Discover is invoked from the
	// --ble-discover CLI flag and from the BLE transport's
	// auto-detect path. scanDone has buffer=1 so the caller's
	// select unblocks even when the recover eats the panic.
	obs.SafeGo("transport/ble.discover", func() {
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
	})

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

// hexHead renders up to maxBytes bytes of buf as space-separated hex,
// for debug logs of incoming BLE data. Used to make notification
// payloads readable in slog without blowing up the line length when
// the buffer is large.
func hexHead(buf []byte, maxBytes int) string {
	if len(buf) > maxBytes {
		buf = buf[:maxBytes]
	}
	const digits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(len(buf) * 3)
	for i, b := range buf {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte(digits[b>>4])
		sb.WriteByte(digits[b&0xf])
	}
	return sb.String()
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

// flipperBLECharSet is the resolved bundle of Serial-service
// characteristics needed for an RPC session: where to write outbound
// bytes, where to receive indications, and where to track the
// firmware's flow-control credit. The status characteristic is held for
// completeness but no traffic flows on it; we keep a zero-valued copy
// when the firmware doesn't publish it (older builds).
type flipperBLECharSet struct {
	rx     bluetooth.DeviceCharacteristic // host → flipper writes
	tx     bluetooth.DeviceCharacteristic // flipper → host indicates
	flow   bluetooth.DeviceCharacteristic // flipper → host: uint32 BE credit
	status bluetooth.DeviceCharacteristic // optional, observation only
}

// selectFlipperCharacteristics resolves the four Flipper Serial-service
// characteristics from the list returned by DiscoverCharacteristics.
// Hint-UUID matching is mandatory for RX, TX, and FlowCtrl — without
// any one of those the firmware silently drops RPC traffic, so guessing
// is worse than failing loudly. RPCStatus is optional; older firmware
// builds may omit it.
//
// Returns an error if any required characteristic is missing, naming
// every discovered UUID so the next debugging session starts informed.
func selectFlipperCharacteristics(chars []bluetooth.DeviceCharacteristic) (flipperBLECharSet, error) {
	discovered := make([]string, 0, len(chars))
	var (
		rxHit, txHit, flowHit, statusHit *bluetooth.DeviceCharacteristic
	)
	for i := range chars {
		u := chars[i].UUID()
		discovered = append(discovered, u.String())
		switch {
		case uuidsMatch(u, flipperBLERXCharUUID):
			rxHit = &chars[i]
		case uuidsMatch(u, flipperBLETXCharUUID):
			txHit = &chars[i]
		case uuidsMatch(u, flipperBLEFlowControlCharUUID):
			flowHit = &chars[i]
		case uuidsMatch(u, flipperBLERPCStatusCharUUID):
			statusHit = &chars[i]
		}
	}
	slog.Debug("transport/ble: discovered characteristics",
		"uuids", discovered,
		"expectedRX", flipperBLERXCharUUID.String(),
		"expectedTX", flipperBLETXCharUUID.String(),
		"expectedFlow", flipperBLEFlowControlCharUUID.String(),
		"expectedStatus", flipperBLERPCStatusCharUUID.String())

	missing := make([]string, 0, 3)
	if rxHit == nil {
		missing = append(missing, "RX/"+flipperBLERXCharUUID.String())
	}
	if txHit == nil {
		missing = append(missing, "TX/"+flipperBLETXCharUUID.String())
	}
	if flowHit == nil {
		missing = append(missing, "FlowCtrl/"+flipperBLEFlowControlCharUUID.String())
	}
	if len(missing) > 0 {
		return flipperBLECharSet{}, fmt.Errorf(
			"transport: missing required Flipper BLE Serial characteristic(s) %v; discovered %v — firmware rev may have changed characteristic layout",
			missing, discovered,
		)
	}

	set := flipperBLECharSet{rx: *rxHit, tx: *txHit, flow: *flowHit}
	if statusHit != nil {
		set.status = *statusHit
	}
	return set, nil
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
// payloads are bounded by both the negotiated MTU minus the 3-byte
// header AND the firmware's flow-control credit budget. Writes larger
// than the per-chunk minimum are split into consecutive
// WriteWithoutResponse calls; each chunk waits until the firmware has
// advertised at least chunkSize bytes of credit (via FlowCtrl
// notifications) before going on the wire. Skipping the credit check
// is what made earlier revisions of this transport silently lose
// outbound traffic on real Flipper hardware — see
// flipperdevices/flipperzero-firmware
// targets/f7/ble_glue/services/serial_service.c lines 188–208 for the
// publishing side.
//
// WriteWithoutResponse is preferred over Write because the Flipper's
// BLE serial service does not ACK individual writes at the GATT layer
// — the application-level RPC response (read back via TX indications)
// is what confirms delivery.
//
// The characteristic handle is snapshot under mu before the chunk
// loop so a concurrent Close or Reconnect doesn't mutate rxChar
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
	rxChar := t.rxChar
	maxChunk := t.mtu
	if maxChunk <= 0 {
		maxChunk = bleDefaultMTU - attHeaderOverhead
	}
	t.mu.Unlock()

	total := 0
	for total < len(p) {
		remaining := len(p) - total
		chunkSize := maxChunk
		if remaining < chunkSize {
			chunkSize = remaining
		}

		// Wait for enough flow-control credit. Each chunk needs
		// chunkSize bytes of headroom before the firmware will accept
		// it; running ahead of the credit would cause silent drops.
		if err := t.consumeCredit(uint32(chunkSize)); err != nil {
			return total, err
		}

		n, err := rxChar.WriteWithoutResponse(p[total : total+chunkSize])
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

// consumeCredit blocks until at least n bytes of flow-control credit
// are available, then deducts n. Returns os.ErrClosed if Close fires
// while waiting. Per serial_service.c:188-208 the firmware publishes
// the absolute window (not a delta) so we only deduct on confirmed
// successful chunks; new notifications overwrite t.credit wholesale,
// so a stalled writer naturally re-syncs after the next refresh.
func (t *bleTransport) consumeCredit(n uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		if t.closed {
			return os.ErrClosed
		}
		if t.credit >= n {
			t.credit -= n
			return nil
		}
		// Credit insufficient — wait for the next FlowCtrl notification
		// (or Close). No deadline here; the firmware refreshes credit
		// every time it drains its inbound fifo, which happens at the
		// scheduling tick of the BT service.
		t.creditCond.Wait()
	}
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
	t.rxChar = bluetooth.DeviceCharacteristic{}
	t.txChar = bluetooth.DeviceCharacteristic{}
	t.flowChar = bluetooth.DeviceCharacteristic{}
	t.readBuf.Reset()
	t.credit = 0
	t.creditReady = false
	t.creditCond.Broadcast()
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
	t.creditCond.Broadcast()
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
