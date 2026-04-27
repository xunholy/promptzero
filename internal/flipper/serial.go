package flipper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/rpc"
	"github.com/xunholy/promptzero/internal/flipper/transport"
)

// This file owns everything ABOVE the byte channel: prompt framing,
// command dispatch, per-op timeouts, hot-plug recovery, and the
// capability-aware Flipper struct. The byte channel itself lives in
// internal/flipper/transport; serial-specific concerns (DTR,
// /dev/ttyACM* scan, baud) moved with it.
//
// Phase-6 refactor preserves every method signature on *Flipper — the
// 90+ wrappers in commands.go call into f.Exec / f.ExecLong / f.StreamCtx
// / f.WriteFile / f.Capabilities unchanged.

func dbg(format string, args ...any) {
	if os.Getenv("PROMPTZERO_SERIAL_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[serial-dbg] "+format+"\n", args...)
	}
}

// ansiEscape strips ANSI color/control escape sequences from a string.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

// promptPattern matches a Flipper CLI prompt: ">:" or ">: " with an optional
// "[subshell]" prefix such as "[nfc]>: ". Anchored so the whole trimmed line
// must be the prompt, preventing false positives on output that merely ends
// in ">: ".
var promptPattern = regexp.MustCompile(`^(\[[a-z_]+\])?>:\s?$`)

// defaultMaxAccumBytes bounds how much data serial reads can buffer before
// returning ErrResponseTruncated. Large enough for any reasonable CLI
// response, small enough to contain a runaway device.
const defaultMaxAccumBytes = 8 * 1024 * 1024 // 8 MiB

// ErrResponseTruncated is returned by read paths when accumulated output
// exceeds the configured cap. Partial output is still returned alongside the
// error so callers can inspect what arrived before the overflow.
var ErrResponseTruncated = errors.New("flipper response truncated: exceeded max accumulator size")

// ErrFlipperSuspended is returned by CLI methods when the Flipper handle
// is suspended (typically because the Flipper firmware is in USB-UART
// bridge mode and the CLI is unreachable by design). The wording is
// public-facing — it surfaces in agent tool errors and the web UI banner.
var ErrFlipperSuspended = errors.New("flipper offline (UART bridge active)")

// Flipper is the command-layer handle for a connected device. It wraps a
// transport.Transport and layers prompt framing, capability detection,
// and hot-plug reconnect on top. All command wrappers (commands.go) go
// through Exec / ExecLong / StreamCtx / WriteFile — none touch the
// transport directly.
type Flipper struct {
	transport transport.Transport
	mu        sync.Mutex

	// caps holds firmware-detected capabilities. Populated by DetectCapabilities
	// shortly after Connect; nil before that. Read via Capabilities(). Using
	// atomic.Pointer so wrappers can read it concurrently without the mu lock.
	caps atomic.Pointer[Capabilities]

	// connectTimeout is remembered for reconnect attempts — the deadline
	// for the full scan+handshake cycle. The per-port open+read timeout
	// is set inside the transport implementation.
	connectTimeout time.Duration

	// disconnected is flipped by Exec/ExecLong/StreamCtx when a transport
	// read/write returns a disconnect-class error. The next call sees it,
	// takes the mutex, and attempts to reattach via transport.Reconnect.
	disconnected atomic.Bool

	// rpcMode is set true while an RPC session holds the transport.
	// CLI ops check this before acquiring f.mu so they can fail fast
	// without blocking on a mutex that may be held for the entire mirror
	// session.
	rpcMode atomic.Bool

	// bleClient holds a permanent rpc.Client when the underlying
	// transport is BLE — Flipper firmware exposes only RPC over BLE
	// Serial (applications/services/bt/bt_service/bt.c pipes inbound
	// bytes straight into rpc_session_feed; no text CLI handler is
	// wired). On BLE the client is opened at ConnectURL time and lives
	// for the entire Flipper lifetime; rpcMode is permanently true and
	// EnterRPC short-circuits to return this client. On USB the
	// existing on-demand EnterRPC pattern is preserved verbatim and
	// bleClient is nil.
	bleClient *rpc.Client

	// bridgeMode is set true when Suspend has been called — typically
	// because the firmware has been switched into USB-UART bridge mode
	// and the CLI is unreachable by design. Every CLI op short-circuits
	// with ErrFlipperSuspended once this flips.
	bridgeMode atomic.Bool
	// bridgeReason carries the operator-visible string passed to Suspend
	// (e.g. "UART bridge active") so /status and the web banner can
	// surface why the handle is offline.
	bridgeReason atomic.Pointer[string]

	// reconnectCb receives "start"/"success"/"fail" phase updates so the
	// REPL can render "● Flipper disconnected — reconnecting..." etc.
	reconnectCb atomic.Pointer[func(phase, message string)]

	// maxAccumBytes caps the size of the in-flight read buffer for
	// readUntilPromptCtx / StreamCtx. Zero means use defaultMaxAccumBytes.
	maxAccumBytes int

	// execTimeout is the per-command read deadline used by ExecCtx.
	// Zero means use the default (10 s).
	execTimeout time.Duration

	// writeFileTimeout is the post-payload read deadline used by WriteFileCtx.
	// Zero means use the default (10 s).
	writeFileTimeout time.Duration

	// state caches the most recent State() snapshot. See state.go — the
	// cache has its own mutex so state probes never contend with Exec.
	state stateCache
}

// SetMaxAccumBytes overrides the per-operation read-buffer cap. Values <= 0
// reset to the default (8 MiB). The cap applies to the next Exec/Stream call.
func (f *Flipper) SetMaxAccumBytes(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n <= 0 {
		f.maxAccumBytes = 0
		return
	}
	f.maxAccumBytes = n
}

// SetExecTimeout overrides the per-command read deadline for ExecCtx. A zero
// or negative value restores the 10 s default.
func (f *Flipper) SetExecTimeout(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d <= 0 {
		f.execTimeout = 0
		return
	}
	f.execTimeout = d
}

// SetWriteFileTimeout overrides the post-payload read deadline for
// WriteFileCtx. A zero or negative value restores the 10 s default.
func (f *Flipper) SetWriteFileTimeout(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d <= 0 {
		f.writeFileTimeout = 0
		return
	}
	f.writeFileTimeout = d
}

func (f *Flipper) accumCap() int {
	if f.maxAccumBytes > 0 {
		return f.maxAccumBytes
	}
	return defaultMaxAccumBytes
}

// Transport returns the underlying byte channel. Exposed read-only so
// /status output and telemetry can read Identity/Kind without the
// command-layer mutex.
func (f *Flipper) Transport() transport.Transport { return f.transport }

// LaunchBridge launches the Flipper's USB-UART Bridge and returns the
// firmware's response text (empty on BLE).
//
// USB transport: sends the literal command string (default
// `loader open "USB-UART Bridge"`) — preserved for older Flipper
// firmware builds where that name was a registered launchable. On
// modern Momentum the bridge cannot be entered while USB CDC is
// locked for CLI/RPC anyway (gpio_scene_start.c:109), so this path
// will surface "Application not found" via classifyBridgeRejection.
//
// BLE transport: ignores the command string and runs the canonical
// Momentum-compatible sequence directly:
//
//  1. app_start_request(name="GPIO") — opens the GPIO app (the
//     ContainingApp for the USB-UART Bridge scene per
//     applications/main/gpio/gpio_scene_start.c).
//  2. brief settle so the scene-manager renders GpioSceneStart with
//     "USB-UART Bridge" highlighted at index 0 (the default menu item).
//  3. gui_send_input_event(OK, SHORT) — fires GpioStartEventUsbUart;
//     because USB CDC isn't locked on a BLE-only session, the firmware
//     navigates to GpioSceneUsbUart whose on_enter unconditionally
//     calls usb_uart_enable() with the default config (vcp_ch=0,
//     uart_ch=0, baudrate default — Marauder's 115200 baud).
//
// This path is the only one that actually starts the bridge on
// Momentum: the loader-open shortcut "USB-UART Bridge" was never a
// registered application, only a menu label. The firmware's
// gpio_scene_usb_uart.c on_enter is what actually flips USB CDC
// into UART pass-through mode.
func (f *Flipper) LaunchBridge(ctx context.Context, command string) (string, error) {
	if !f.IsBLE() {
		return f.ExecCtx(ctx, command)
	}
	return f.launchBridgeViaGPIORPC(ctx)
}

// launchBridgeViaGPIORPC drives the BLE-only "open GPIO + select
// USB-UART Bridge" sequence. See LaunchBridge for context.
//
// Settle delays are conservative: the scene manager runs on a
// dedicated GUI thread and the input-event handler dispatches via a
// FuriEventLoop, so on a quiet BT link the round-trip is well under
// 100 ms. 250 ms gives headroom for slow links / busy CPU; the bridge
// is a one-shot setup so the extra latency is invisible to the user.
func (f *Flipper) launchBridgeViaGPIORPC(ctx context.Context) (string, error) {
	if _, err := f.LoaderOpen("GPIO", ""); err != nil {
		return "", fmt.Errorf("launching GPIO app: %w", err)
	}
	select {
	case <-time.After(250 * time.Millisecond):
	case <-ctx.Done():
		return "", ctx.Err()
	}
	// "USB-UART Bridge" is the first item in GpioSceneStart's variable
	// list (gpio_scene_start.c:62) and the start scene's selected item
	// state defaults to 0, so a single OK press selects it.
	if _, err := f.InputSend("ok", "short"); err != nil {
		return "", fmt.Errorf("selecting USB-UART Bridge: %w", err)
	}
	// One more settle so the firmware finishes the scene transition
	// before the caller tries to reopen the USB CDC port — without
	// this the reopen race-conditions against usb_uart_enable's
	// furi_hal_usb_set_config call (~50 ms on the device).
	select {
	case <-time.After(150 * time.Millisecond):
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return "", nil
}

// rpcModeError selects the right error when a CLI dispatch attempt
// finds rpcMode=true. On USB, rpcMode is a temporary "mirror session"
// state — the operator just needs to release the mirror before
// retrying — and the existing ErrInRPCMode message captures that.
// On BLE, rpcMode is permanent (the firmware exposes only RPC over
// BLE Serial; see internal/flipper/transport/ble.go for context), so
// the operator-visible meaning of "you tried a CLI command" is
// "this command has no RPC equivalent in firmware — connect via USB
// instead". usbOnlyError carries that nuance plus the offending
// operation name through errors.Is wrapping.
func (f *Flipper) rpcModeError(operation string) error {
	if f.IsBLE() {
		return usbOnlyError(operation)
	}
	return ErrInRPCMode
}

// IsBLE reports whether the underlying transport is BLE. BLE transports
// can only speak Protobuf RPC (not text CLI), so command dispatchers
// branch on this to either route through the persistent RPC client
// (f.bleClient) or — for commands without an RPC equivalent — return
// ErrCommandRequiresUSB.
func (f *Flipper) IsBLE() bool {
	return f.transport != nil && f.transport.Kind() == "ble"
}

// BLEClient returns the persistent RPC client opened at connect time
// when the transport is BLE, or nil otherwise. Callers must check
// IsBLE first; on USB the client is constructed on demand via
// EnterRPC and is not held on the Flipper handle.
func (f *Flipper) BLEClient() *rpc.Client { return f.bleClient }

// Reconnect forces a fresh reconnect cycle: closes the current transport,
// asks the transport to rescan + reopen, re-handshakes, and re-detects
// capabilities. Useful from a /reconnect slash command when the user has
// replugged and auto-detect didn't fire (e.g., the agent was idle and no
// IO error surfaced the drop).
func (f *Flipper) Reconnect(ctx context.Context) error {
	if f.bridgeMode.Load() {
		return ErrFlipperSuspended
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnected.Store(true)
	return f.reconnectIfNeededLocked(ctx)
}

// Suspend marks this handle inactive and closes the underlying transport
// so a sibling process (e.g. marauder.Connect) can open the same OS-level
// port. Subsequent CLI calls return ErrFlipperSuspended until the process
// exits. Suspend is idempotent — the first call's reason wins.
func (f *Flipper) Suspend(reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bridgeMode.Load() {
		return nil
	}
	r := reason
	f.bridgeReason.Store(&r)
	f.bridgeMode.Store(true)
	if f.transport == nil {
		return nil
	}
	return f.transport.Close()
}

// IsSuspended reports whether Suspend has been called.
func (f *Flipper) IsSuspended() bool { return f.bridgeMode.Load() }

// SuspensionReason returns the string passed to the most recent Suspend
// call, or "" when not suspended.
func (f *Flipper) SuspensionReason() string {
	if !f.bridgeMode.Load() {
		return ""
	}
	if r := f.bridgeReason.Load(); r != nil {
		return *r
	}
	return ""
}

// SetReconnectCallback registers a function invoked at each reconnect phase
// ("start", "success", "fail"). Called while f.mu is held, so keep the
// handler quick — typically a single stderr write via the output mutex.
func (f *Flipper) SetReconnectCallback(cb func(phase, message string)) {
	if cb == nil {
		f.reconnectCb.Store(nil)
		return
	}
	f.reconnectCb.Store(&cb)
}

func (f *Flipper) notifyReconnect(phase, message string) {
	if p := f.reconnectCb.Load(); p != nil {
		(*p)(phase, message)
	}
}

// markDisconnectedIfRelevant sets the disconnected flag when err looks like
// a physical-disconnect signal from the transport. Timeout reads and
// harmless errors are ignored.
func (f *Flipper) markDisconnectedIfRelevant(err error) {
	if err == nil {
		return
	}
	s := strings.ToLower(err.Error())
	for _, needle := range []string{
		"port has been closed",
		"no such device",
		"input/output error",
		"device not configured",
		"bad file descriptor",
		"file already closed",
	} {
		if strings.Contains(s, needle) {
			f.disconnected.Store(true)
			return
		}
	}
}

// reconnectIfNeededLocked is called by every op-start path. When the
// disconnected flag is set, it asks the transport to Reconnect (which
// handles the physical-layer scan), re-handshakes, and — if the original
// capabilities had a hardware_uid — verifies the replugged device is
// the same one.
func (f *Flipper) reconnectIfNeededLocked(ctx context.Context) error {
	if !f.disconnected.Load() {
		return nil
	}

	origIdent := f.transport.Identity()
	to := f.connectTimeout
	if to == 0 {
		to = 5 * time.Second
	}
	origUID := ""
	if caps := f.caps.Load(); caps != nil {
		origUID = caps.HardwareUID
	}

	f.notifyReconnect("start", fmt.Sprintf("Flipper disconnected — reconnecting (last seen on %s)…", origIdent))

	deadline := time.Now().Add(to)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			f.notifyReconnect("fail", "reconnect cancelled")
			return err
		}
		// Transport.Reconnect is responsible for the physical-layer
		// dance (close old fd, rescan candidate ports, reopen).
		if err := f.transport.Reconnect(ctx); err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		// Run the CLI handshake on the freshly reopened transport.
		hsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := f.handshake(hsCtx)
		cancel()
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		// Verify identity if we knew it before.
		if origUID != "" {
			info, ierr := f.execLocked(ctx, "device_info", 5*time.Second)
			if ierr != nil {
				time.Sleep(250 * time.Millisecond)
				continue
			}
			c := detectCapabilities(info)
			if c.HardwareUID != origUID {
				time.Sleep(250 * time.Millisecond)
				continue
			}
			f.caps.Store(&c)
		}
		f.disconnected.Store(false)
		f.notifyReconnect("success", fmt.Sprintf("Flipper reconnected on %s", f.transport.Identity()))
		return nil
	}

	f.notifyReconnect("fail", fmt.Sprintf("Flipper not found after %s — unplug/replug or run /reconnect", to))
	return fmt.Errorf("flipper reconnect timed out after %s", to)
}

// execLocked runs a single CLI command and returns the response. Must be
// called with f.mu held; does not re-acquire. Used by reconnect to verify
// identity without recursing through Exec. ctx is honoured so a Ctrl+C
// during a stuck reconnect identity-check cancels the read promptly
// instead of waiting out the full timeout.
func (f *Flipper) execLocked(ctx context.Context, command string, timeout time.Duration) (string, error) {
	f.drain()
	if err := f.sendRaw(command + "\r"); err != nil {
		return "", err
	}
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return f.readUntilPromptCtx(readCtx)
}

// Capabilities returns the detected firmware capability map. If DetectCapabilities
// has not yet been called (or failed), returns a zero-valued struct with the
// conservative defaults (power_info, nfc subshell, no subghz device arg).
func (f *Flipper) Capabilities() Capabilities {
	if p := f.caps.Load(); p != nil {
		return *p
	}
	return detectCapabilities("") // defaults
}

// DetectCapabilities queries device_info and caches the parsed capability map.
// Best-effort: on error, leaves prior caps (or defaults) in place.
func (f *Flipper) DetectCapabilities() (Capabilities, error) {
	out, err := f.DeviceInfo()
	if err != nil {
		return f.Capabilities(), err
	}
	c := detectCapabilities(out)
	f.caps.Store(&c)
	return c, nil
}

// ErrConnectTimeout is returned when the Flipper does not produce a CLI prompt
// within the connect timeout. The Flipper is likely inside an app or on a dialog
// that has taken over the CLI — press Back on the device and retry.
var ErrConnectTimeout = errors.New("timeout waiting for Flipper CLI prompt")

// Connect opens a serial port and performs the CLI handshake.
//
// Preserves the pre-Phase-6 signature — the tree has ~5 callers (cmd
// main, tests in flipper_mock_test.go / primitives_mock_test.go) that
// pass a path + baud + timeout directly. Internally, Connect builds a
// serial:// URL and hands it to ConnectURL; new callers that want to
// pick a non-serial transport should use ConnectURL directly.
func Connect(ctx context.Context, portName string, baudRate int, timeout time.Duration) (*Flipper, error) {
	url := fmt.Sprintf("serial://%s?baud=%d", portName, baudRate)
	return ConnectURL(ctx, url, timeout)
}

// ConnectURL opens the transport identified by rawURL and performs the
// CLI handshake. rawURL is any scheme registered with the transport
// package; a bare device path (e.g. "/dev/ttyACM0") is accepted as
// shorthand for serial://.
//
// The handshake is cancelable: if ctx is cancelled or timeout elapses before
// the prompt arrives, Connect closes the transport and returns ctx.Err() or
// ErrConnectTimeout respectively.
func ConnectURL(ctx context.Context, rawURL string, timeout time.Duration) (*Flipper, error) {
	dbg("ConnectURL: opening %s", rawURL)
	tx, err := transport.Open(rawURL)
	if err != nil {
		return nil, fmt.Errorf("resolving transport: %w", err)
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, timeout)
	defer cancelDial()
	if err := tx.Dial(dialCtx); err != nil {
		return nil, fmt.Errorf("opening transport %s: %w", rawURL, err)
	}
	dbg("ConnectURL: transport dialled (%s)", tx.Identity())

	f := &Flipper{
		transport:      tx,
		connectTimeout: timeout,
	}

	// BLE bypasses the text-CLI handshake entirely. The Flipper firmware
	// has no text CLI on its BLE Serial endpoint — bytes flow straight
	// into the protobuf RPC decoder — so waiting for ">: " would always
	// time out. Open a persistent rpc.Client with WithSkipStartRPCSession
	// (the firmware is already in RPC mode at connection time, no text
	// preamble needed), latch rpcMode=true for the lifetime of the handle,
	// and return. All subsequent commands route through bleClient via
	// the dispatchers in commands.go; commands without an RPC verb in
	// the firmware (Sub-GHz, NFC, IR, RFID, iButton, BadUSB) return
	// ErrCommandRequiresUSB on this transport.
	if tx.Kind() == "ble" {
		dbg("ConnectURL: BLE transport detected; entering permanent RPC mode")
		client := rpc.NewClient(tx)
		openCtx, openCancel := context.WithTimeout(ctx, timeout)
		defer openCancel()
		if err := client.Open(openCtx, rpc.WithSkipStartRPCSession()); err != nil {
			_ = tx.Close()
			return nil, fmt.Errorf("opening RPC session over BLE: %w", err)
		}
		f.bleClient = client
		f.rpcMode.Store(true)
		dbg("ConnectURL: BLE RPC session ready (Identity=%s)", tx.Identity())
		return f, nil
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		dbg("handshake goroutine: starting")
		err := f.handshake(handshakeCtx)
		dbg("handshake goroutine: returned err=%v", err)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			_ = tx.Close()
			return nil, err
		}
		return f, nil
	case <-handshakeCtx.Done():
		// Closing the transport unblocks any read pending inside
		// handshake().
		_ = tx.Close()
		<-done
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w after %v (is the Flipper on the home screen and awake?)", ErrConnectTimeout, timeout)
	}
}

// handshake breaks any running app with Ctrl+C + CR and reads until the first
// CLI prompt. We bypass bufio and read raw bytes from the transport with a
// short timeout, because the final Flipper prompt ">: " has no trailing newline —
// a line-based read would block forever waiting for one. The short
// per-read timeout also lets us poll ctx every ~500ms so Ctrl+C and the
// connect timeout take effect even if the transport doesn't unblock the
// read immediately.
func (f *Flipper) handshake(ctx context.Context) error {
	// Ctrl+C drops out of any running CLI app; the CR forces a fresh prompt
	// even if the CLI was already idle when we opened the port.
	if err := f.sendRaw("\x03\r"); err != nil {
		return fmt.Errorf("sending break: %w", err)
	}
	dbg("handshake: sent \\x03\\r, entering read loop")

	var accum []byte
	buf := make([]byte, 512)
	for {
		if err := ctx.Err(); err != nil {
			dbg("handshake: ctx done before Read: %v", err)
			return err
		}
		n, err := f.transport.Read(buf)
		dbg("handshake: Read n=%d err=%v", n, err)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("reading handshake: %w", err)
		}
		if n == 0 {
			// read timeout — loop to re-check ctx
			continue
		}
		accum = append(accum, buf[:n]...)
		dbg("handshake: accum=%q", string(accum))
		// The Flipper emits ">: " as its prompt. Seeing it anywhere in the
		// banner + post-Ctrl+C output is sufficient to know the CLI is live.
		if strings.Contains(stripANSI(string(accum)), ">: ") {
			dbg("handshake: prompt detected, returning nil")
			return nil
		}
	}
}

func (f *Flipper) Close() error {
	// On BLE the persistent RPC client owns the wire-level lifecycle —
	// closing it sends StopSession + a Ctrl+C tail and clears the
	// session flag — so we let it tear down before closing the
	// transport. On USB bleClient is nil and we skip straight to the
	// transport close as before.
	if f.bleClient != nil {
		_ = f.bleClient.Close()
		f.bleClient = nil
	}
	return f.transport.Close()
}

// Exec sends a CLI command and returns the full response. Preserved for
// backward compatibility; new callers should use ExecCtx so cancellation
// propagates through to the reconnect path.
func (f *Flipper) Exec(command string) (string, error) {
	return f.ExecCtx(context.Background(), command)
}

// ExecCtx is the context-aware variant of Exec. The ctx is honoured during
// reconnect polling and during the 10 s per-command read deadline.
func (f *Flipper) ExecCtx(ctx context.Context, command string) (string, error) {
	if f.bridgeMode.Load() {
		return "", ErrFlipperSuspended
	}
	if f.rpcMode.Load() {
		return "", f.rpcModeError(command)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.reconnectIfNeededLocked(ctx); err != nil {
		return "", err
	}

	f.drain()

	// CR only (0x0D) — the Flipper CLI processes input on carriage return.
	if err := f.sendRaw(command + "\r"); err != nil {
		f.markDisconnectedIfRelevant(err)
		return "", fmt.Errorf("sending command: %w", err)
	}

	execTO := f.execTimeout
	if execTO <= 0 {
		execTO = 10 * time.Second
	}
	readCtx, cancel := context.WithTimeout(ctx, execTO)
	defer cancel()
	out, err := f.readUntilPromptCtx(readCtx)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		// safety net fired — command hung. Stop the firmware, drain, then
		// surface a distinct error so callers can distinguish "hung" from a
		// real disconnect.
		_ = f.sendRaw("\x03")
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer drainCancel()
		_, drainErr := f.readUntilPromptCtx(drainCtx)
		if drainErr != nil && !errors.Is(drainErr, context.DeadlineExceeded) && !errors.Is(drainErr, context.Canceled) {
			f.markDisconnectedIfRelevant(drainErr)
			return out, drainErr
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, fmt.Errorf("command hung: no prompt within %s", execTO)
	}
	f.markDisconnectedIfRelevant(err)
	if err == nil {
		if cmdErr := detectUnknownCommand(command, out); cmdErr != nil {
			return out, cmdErr
		}
	}
	return out, err
}

// detectUnknownCommand scans a command's raw output for the Flipper
// firmware's "unknown command" response shape. Returns a structured
// error so callers can distinguish "command failed" from "command
// wasn't recognised at all" — the latter usually means we're stuck in
// a subshell and the shell rejected a command meant for the main
// context. Previously this case leaked through as a silent success
// (err=nil, output carries the rejection text), which let primitives
// that scraped output for fields return empty data and the agent
// layer above mark the call success=true. Surfacing it as an error
// stops that thrash at the source.
//
// The matcher is deliberately narrow: only strings that start at the
// beginning of a line with "could not find command `" (Momentum +
// Unleashed main shell) or "Unknown command" (older forks). Error
// text that happens to contain these substrings mid-line won't fire.
func detectUnknownCommand(command, raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "could not find command") ||
			strings.HasPrefix(line, "Unknown command") {
			return fmt.Errorf("cli rejected %q: %s", firstWord(command), line)
		}
	}
	return nil
}

// firstWord returns the first whitespace-separated token of s, or s
// itself if no whitespace is present. Used to quote just the verb
// (not the whole command + args) in the "cli rejected" error so the
// message stays short when args carry paths.
func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i > 0 {
		return s[:i]
	}
	return s
}

// ExecLong sends a command that may take a while (captures, brute force,
// etc). Preserved for backward compatibility; new callers should use
// ExecLongCtx so cancellation propagates through to the reconnect path.
func (f *Flipper) ExecLong(command string, timeout time.Duration) (string, error) {
	return f.ExecLongCtx(context.Background(), command, timeout)
}

// ExecLongCtx is the context-aware variant of ExecLong. A non-positive
// timeout is floored to 60 s so a caller passing a zero duration still gets
// a sane per-command deadline.
func (f *Flipper) ExecLongCtx(ctx context.Context, command string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if f.bridgeMode.Load() {
		return "", ErrFlipperSuspended
	}
	if f.rpcMode.Load() {
		return "", f.rpcModeError(command)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.reconnectIfNeededLocked(ctx); err != nil {
		return "", err
	}

	f.drain()

	if err := f.sendRaw(command + "\r"); err != nil {
		f.markDisconnectedIfRelevant(err)
		return "", fmt.Errorf("sending command: %w", err)
	}

	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := f.readUntilPromptCtx(readCtx)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		// Timeout is the caller's budget — stop the firmware command, drain the
		// in-flight response, and return accumulated output as success.
		_ = f.sendRaw("\x03")
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer drainCancel()
		_, drainErr := f.readUntilPromptCtx(drainCtx)
		if drainErr != nil && !errors.Is(drainErr, context.DeadlineExceeded) && !errors.Is(drainErr, context.Canceled) {
			f.markDisconnectedIfRelevant(drainErr)
			return out, drainErr
		}
		return out, nil
	}
	f.markDisconnectedIfRelevant(err)
	if err == nil {
		if cmdErr := detectUnknownCommand(command, out); cmdErr != nil {
			return out, cmdErr
		}
	}
	return out, err
}

// StreamCtx runs command and invokes onLine for each output line as it
// arrives. It returns when ctx is done, when onLine returns true (caller
// asks to stop), or when the Flipper emits its terminating ">: " prompt.
// A Ctrl+C is always sent to the Flipper on exit so in-flight commands
// (like `rfid read` or `subghz rx`) are halted.
func (f *Flipper) StreamCtx(ctx context.Context, command string, onLine func(line string) (stop bool)) error {
	if f.bridgeMode.Load() {
		return ErrFlipperSuspended
	}
	if f.rpcMode.Load() {
		return f.rpcModeError(command)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.reconnectIfNeededLocked(ctx); err != nil {
		return err
	}

	// Always stop the Flipper-side command on exit, even on ctx cancel.
	defer f.sendRaw("\x03")

	f.drain()
	if err := f.sendRaw(command + "\r"); err != nil {
		f.markDisconnectedIfRelevant(err)
		return fmt.Errorf("sending command: %w", err)
	}

	var accum []byte
	buf := make([]byte, 512)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := f.transport.Read(buf)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			f.markDisconnectedIfRelevant(err)
			return err
		}
		if n == 0 {
			continue
		}
		accum = append(accum, buf[:n]...)
		if len(accum) > f.accumCap() {
			return ErrResponseTruncated
		}

		// Emit every complete line (\n-terminated) currently in accum.
		for {
			idx := bytes.IndexByte(accum, '\n')
			if idx < 0 {
				break
			}
			rawLine := accum[:idx]
			accum = accum[idx+1:]
			line := strings.TrimRight(stripANSI(string(rawLine)), "\r")
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if isPrompt(line) {
				return nil
			}
			if onLine(line) {
				return nil
			}
		}

		// Unterminated final prompt ">: " (cursor sits at prompt, no \n).
		if isPrompt(strings.TrimSpace(stripANSI(string(accum)))) {
			return nil
		}
	}
}

// WriteFile writes data to a file on the Flipper using the storage write_chunk
// interactive protocol: send the command with the byte count, then send the raw
// bytes immediately after. Preserved for backward compatibility; prefer
// WriteFileCtx so cancellation and reconnect propagate a ctx.
func (f *Flipper) WriteFile(path string, data []byte) error {
	return f.WriteFileCtx(context.Background(), path, data)
}

// WriteFileCtx is the context-aware variant of WriteFile. It reconnects if
// needed, uses a cancellable sleep between command and payload, and tags
// any disconnect-class error via markDisconnectedIfRelevant so the next
// op can recover.
//
// Firmware append behaviour: some firmware builds — notably Momentum dev
// branch as of mntm-dev 430a3d50 (2026-03-09) — do NOT truncate an existing
// file when storage write_chunk is called; they append to the existing
// content instead. Callers that need truncate semantics must issue
// "storage remove <path>" before writing, or the re-written file will
// contain concatenated data.
func (f *Flipper) WriteFileCtx(ctx context.Context, path string, data []byte) error {
	if f.bridgeMode.Load() {
		return ErrFlipperSuspended
	}
	if f.rpcMode.Load() {
		return f.rpcModeError("write_file " + path)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.reconnectIfNeededLocked(ctx); err != nil {
		return err
	}

	f.drain()

	cmd := fmt.Sprintf("storage write_chunk %s %d\r", sanitizeArg(path), len(data))
	if err := f.sendRaw(cmd); err != nil {
		f.markDisconnectedIfRelevant(err)
		return fmt.Errorf("sending write_chunk command: %w", err)
	}

	// Wait for the device to acknowledge the command before sending data.
	// Cancellable so a Ctrl+C mid-write isn't stuck in Sleep.
	select {
	case <-time.After(100 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	f.drain() // drain the echo

	// Write data, ensuring all bytes are sent.
	written := 0
	for written < len(data) {
		n, err := f.transport.Write(data[written:])
		if err != nil {
			f.markDisconnectedIfRelevant(err)
			return fmt.Errorf("writing file data at offset %d: %w", written, err)
		}
		written += n
	}

	writeTO := f.writeFileTimeout
	if writeTO <= 0 {
		writeTO = 10 * time.Second
	}
	readCtx, cancel := context.WithTimeout(ctx, writeTO)
	defer cancel()
	_, err := f.readUntilPromptCtx(readCtx)
	f.markDisconnectedIfRelevant(err)
	return err
}

func (f *Flipper) sendRaw(data string) error {
	_, err := f.transport.Write([]byte(data))
	return err
}

// isPrompt reports whether line is a Flipper CLI prompt after ANSI stripping
// and whitespace trimming. The prompt format is ">:" or ">: ", optionally
// prefixed by a subsystem name such as "[nfc]>: ". Anchored with a regexp
// so output lines that merely end in ">: " don't register as prompts.
func isPrompt(line string) bool {
	clean := strings.TrimSpace(stripANSI(line))
	return promptPattern.MatchString(clean)
}

func (f *Flipper) readUntilPrompt(timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return f.readUntilPromptCtx(ctx)
}

// readUntilPromptCtx reads raw bytes until a ">: " prompt is seen or ctx is
// done. We bypass bufio because the Flipper's terminal prompt ">: " has no
// trailing newline — line-based reads (ReadString('\n')) would block forever.
// Raw reads with a short transport-level timeout also let us poll ctx
// regularly. When the accumulator exceeds the configured cap, partial output
// is returned alongside ErrResponseTruncated so the caller can still inspect
// it.
func (f *Flipper) readUntilPromptCtx(ctx context.Context) (string, error) {
	var accum []byte
	buf := make([]byte, 512)

	for {
		if err := ctx.Err(); err != nil {
			return parseResponse(accum, false), err
		}
		n, err := f.transport.Read(buf)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return parseResponse(accum, false), ctxErr
			}
			return parseResponse(accum, false), err
		}
		if n == 0 {
			continue
		}
		accum = append(accum, buf[:n]...)
		if idx := indexOfPrompt(accum); idx >= 0 {
			return parseResponse(accum[:idx], true), nil
		}
		if len(accum) > f.accumCap() {
			return parseResponse(accum, false), ErrResponseTruncated
		}
	}
}

// indexOfPrompt returns the raw byte offset of the final ">: " occurrence in
// b, or -1 if none. ANSI escape sequences never contain the '>' character
// (CSI is `\x1b[` + digits/semicolons + a letter), so a direct
// bytes.LastIndex on the raw buffer is both correct and preserves the offset
// into accum without the ANSI-stripped index drift.
//
// We only search the tail of b — the prompt is always at the end of the
// stream, never mid-output. Capping the scan window keeps the cost flat as
// captures grow into the megabyte range. The window must overlap the
// previous search by len(prompt)-1 so a prompt that straddled two reads
// is still found.
func indexOfPrompt(b []byte) int {
	const window = 1024
	if len(b) < 3 {
		return -1
	}
	searchStart := 0
	if len(b) > window {
		searchStart = len(b) - window
	}
	idx := bytes.LastIndex(b[searchStart:], []byte(">: "))
	if idx < 0 {
		return -1
	}
	return idx + searchStart
}

// parseResponse strips ANSI, normalizes line endings, drops the command echo
// (first line) when sawPrompt is true, and trims leading/trailing blanks.
func parseResponse(b []byte, sawPrompt bool) string {
	s := stripANSI(string(b))
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	if sawPrompt && len(lines) > 0 {
		// Strip command echo (the first non-empty line is the command we sent).
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

func (f *Flipper) drain() {
	drainTO := f.transport.DrainTimeout()
	_ = f.transport.SetReadTimeout(drainTO)
	buf := make([]byte, 1024)
	for {
		n, _ := f.transport.Read(buf)
		if n == 0 {
			break
		}
	}
	// Keep the same short poll interval so readUntilPromptCtx notices
	// context cancellation within one interval rather than waiting 5 s.
	_ = f.transport.SetReadTimeout(drainTO)
}
