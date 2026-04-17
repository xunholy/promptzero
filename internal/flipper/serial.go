package flipper

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.bug.st/serial"
)

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

type Flipper struct {
	port   serial.Port
	mu     sync.Mutex
	reader *bufio.Reader

	// caps holds firmware-detected capabilities. Populated by DetectCapabilities
	// shortly after Connect; nil before that. Read via Capabilities(). Using
	// atomic.Pointer so wrappers can read it concurrently without the mu lock.
	caps atomic.Pointer[Capabilities]

	// Connection parameters remembered for hot-plug reconnect. Populated by
	// Connect; used by reconnectIfNeededLocked when the device disappears.
	portName       string
	baudRate       int
	connectTimeout time.Duration

	// disconnected is flipped by Exec/ExecLong/StreamCtx when a port
	// read/write returns a disconnect-class error. The next call sees it,
	// takes the mutex, and attempts to reattach.
	disconnected atomic.Bool

	// reconnectCb receives "start"/"success"/"fail" phase updates so the
	// REPL can render "● Flipper disconnected — reconnecting..." etc.
	reconnectCb atomic.Pointer[func(phase, message string)]

	// maxAccumBytes caps the size of the in-flight read buffer for
	// readUntilPromptCtx / StreamCtx. Zero means use defaultMaxAccumBytes.
	maxAccumBytes int
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

func (f *Flipper) accumCap() int {
	if f.maxAccumBytes > 0 {
		return f.maxAccumBytes
	}
	return defaultMaxAccumBytes
}

// Reconnect forces a fresh reconnect cycle: closes the current port, then
// scans for the Flipper (original path first, then /dev/ttyACM*), re-opens,
// re-handshakes, and re-detects capabilities. Useful from a /reconnect slash
// command when the user has replugged and auto-detect didn't fire (e.g., the
// agent was idle and no IO error surfaced the drop).
func (f *Flipper) Reconnect(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnected.Store(true)
	return f.reconnectIfNeededLocked(ctx)
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
// a physical-disconnect signal from the serial driver. Timeout reads and
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
	} {
		if strings.Contains(s, needle) {
			f.disconnected.Store(true)
			return
		}
	}
}

// reconnectIfNeededLocked is called by every op-start path. When the
// disconnected flag is set, it closes the dead port, scans for the Flipper
// (preferring its original path and verifying hardware_uid when possible),
// reopens + re-handshakes, and restores capabilities. Caller must hold f.mu.
func (f *Flipper) reconnectIfNeededLocked(ctx context.Context) error {
	if !f.disconnected.Load() {
		return nil
	}

	origPath := f.portName
	baud := f.baudRate
	to := f.connectTimeout
	if to == 0 {
		to = 5 * time.Second
	}
	origUID := ""
	if caps := f.caps.Load(); caps != nil {
		origUID = caps.HardwareUID
	}

	f.notifyReconnect("start", fmt.Sprintf("Flipper disconnected — reconnecting (last seen on %s)…", origPath))

	// Tear down the old port. Any blocked read was already unblocked by the
	// disconnect; this just releases the fd cleanly.
	if f.port != nil {
		_ = f.port.Close()
		f.port = nil
		f.reader = nil
	}

	// Candidate list: original path first, then other ttyACM* nodes. Keeps
	// the common case (same port re-appears) fast.
	candidates := []string{origPath}
	if matches, _ := filepath.Glob("/dev/ttyACM*"); matches != nil {
		seen := map[string]bool{origPath: true}
		for _, m := range matches {
			if !seen[m] {
				candidates = append(candidates, m)
				seen[m] = true
			}
		}
	}

	// Poll: give each candidate up to the connect timeout; retry every 250ms
	// in case the kernel hasn't finished re-enumeration yet.
	deadline := time.Now().Add(to)
	for time.Now().Before(deadline) {
		for _, path := range candidates {
			if err := ctx.Err(); err != nil {
				f.notifyReconnect("fail", "reconnect cancelled")
				return err
			}
			if err := f.openAndHandshakeLocked(ctx, path, baud, 2*time.Second); err != nil {
				continue
			}
			// If we knew the original UID, verify this is the same device.
			// Parse inline to avoid recursing through DetectCapabilities
			// (which re-takes the CLI path and is fine, but this is simpler).
			if origUID != "" {
				info, ierr := f.execLocked("device_info", 5*time.Second)
				if ierr != nil {
					_ = f.port.Close()
					f.port = nil
					f.reader = nil
					continue
				}
				c := detectCapabilities(info)
				if c.HardwareUID != origUID {
					_ = f.port.Close()
					f.port = nil
					f.reader = nil
					continue
				}
				f.caps.Store(&c)
				f.portName = path
				f.disconnected.Store(false)
				f.notifyReconnect("success", fmt.Sprintf("Flipper reconnected on %s (%s)", path, c.HardwareName))
				return nil
			}
			// No original UID — trust the handshake + accept.
			f.portName = path
			f.disconnected.Store(false)
			f.notifyReconnect("success", fmt.Sprintf("Flipper reconnected on %s", path))
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}

	f.notifyReconnect("fail", fmt.Sprintf("Flipper not found after %s — unplug/replug or run /reconnect", to))
	return fmt.Errorf("flipper reconnect timed out after %s", to)
}

// openAndHandshakeLocked opens portName, sets DTR + short read timeout, and
// runs the CLI handshake. Stores the port + new bufio reader on f. Caller
// must hold f.mu. Used by both initial Connect and reconnectIfNeededLocked.
func (f *Flipper) openAndHandshakeLocked(ctx context.Context, portName string, baudRate int, timeout time.Duration) error {
	port, err := serial.Open(portName, &serial.Mode{
		BaudRate: baudRate,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	})
	if err != nil {
		return err
	}
	// SetDTR is required on real Flipper hardware (CLI is gated on DTR
	// asserting), but it ioctl-fails on pseudo-terminals which the mock
	// test harness relies on. Log + continue — on real hardware the
	// handshake will just time out if DTR really is needed.
	if err := port.SetDTR(true); err != nil {
		dbg("openAndHandshakeLocked: SetDTR failed (likely pty, continuing): %v", err)
	}
	if err := port.SetReadTimeout(500 * time.Millisecond); err != nil {
		port.Close()
		return err
	}

	f.port = port
	f.reader = bufio.NewReader(port)

	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.handshake(hsCtx) }()
	select {
	case err := <-done:
		if err != nil {
			port.Close()
			f.port = nil
			f.reader = nil
			return err
		}
		return nil
	case <-hsCtx.Done():
		port.Close()
		<-done
		f.port = nil
		f.reader = nil
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrConnectTimeout
	}
}

// execLocked runs a single CLI command and returns the response. Must be
// called with f.mu held; does not re-acquire. Used by reconnect to verify
// identity without recursing through Exec.
func (f *Flipper) execLocked(command string, timeout time.Duration) (string, error) {
	f.drain()
	if err := f.sendRaw(command + "\r"); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return f.readUntilPromptCtx(ctx)
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

// Connect opens the serial port and performs the CLI handshake.
//
// The handshake is cancelable: if ctx is cancelled or timeout elapses before
// the prompt arrives, Connect closes the port (which unblocks any pending read)
// and returns ctx.Err() or ErrConnectTimeout respectively.
func Connect(ctx context.Context, portName string, baudRate int, timeout time.Duration) (*Flipper, error) {
	dbg("Connect: opening %s @ %d", portName, baudRate)
	mode := &serial.Mode{
		BaudRate: baudRate,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}

	port, err := serial.Open(portName, mode)
	if err != nil {
		return nil, fmt.Errorf("opening serial port %s: %w", portName, err)
	}
	dbg("Connect: port opened")

	// DTR must be asserted — the Flipper shell only activates when DTR goes
	// high. Best-effort: pseudo-terminals (used by the mock test harness)
	// don't support the TIOCM* ioctls, and failing here would make the code
	// path untestable without hardware. On real hardware the subsequent
	// handshake will time out if DTR was actually needed, so the failure
	// mode is still observable.
	if err := port.SetDTR(true); err != nil {
		dbg("Connect: SetDTR failed (likely pty, continuing): %v", err)
	}
	dbg("Connect: DTR set")

	// Short per-read timeout so the handshake loop polls rather than blocks
	// indefinitely. The overall deadline is enforced by the watcher below.
	if err := port.SetReadTimeout(500 * time.Millisecond); err != nil {
		port.Close()
		return nil, fmt.Errorf("setting read timeout: %w", err)
	}
	dbg("Connect: ReadTimeout set")

	f := &Flipper{
		port:           port,
		reader:         bufio.NewReader(port),
		portName:       portName,
		baudRate:       baudRate,
		connectTimeout: timeout,
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
		dbg("Connect: got from done, err=%v", err)
		if err != nil {
			port.Close()
			return nil, err
		}
		return f, nil
	case <-handshakeCtx.Done():
		dbg("Connect: handshakeCtx fired, closing port")
		// Closing the port unblocks any read pending inside handshake().
		port.Close()
		<-done
		dbg("Connect: handshake goroutine drained")
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w after %v (is the Flipper on the home screen and awake?)", ErrConnectTimeout, timeout)
	}
}

// handshake breaks any running app with Ctrl+C + CR and reads until the first
// CLI prompt. We bypass bufio and read raw bytes from the port with a short
// timeout, because the final Flipper prompt ">: " has no trailing newline —
// bufio.ReadString('\n') would block forever waiting for one. The short
// per-read timeout also lets us poll ctx every ~500ms so Ctrl+C and the
// connect timeout take effect even if port.Close doesn't unblock the read.
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
		n, err := f.port.Read(buf)
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
	return f.port.Close()
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

	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := f.readUntilPromptCtx(readCtx)
	f.markDisconnectedIfRelevant(err)
	return out, err
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
	f.markDisconnectedIfRelevant(err)
	return out, err
}

// StreamCtx runs command and invokes onLine for each output line as it
// arrives. It returns when ctx is done, when onLine returns true (caller
// asks to stop), or when the Flipper emits its terminating ">: " prompt.
// A Ctrl+C is always sent to the Flipper on exit so in-flight commands
// (like `rfid read` or `subghz rx`) are halted.
func (f *Flipper) StreamCtx(ctx context.Context, command string, onLine func(line string) (stop bool)) error {
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
		n, err := f.port.Read(buf)
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
func (f *Flipper) WriteFileCtx(ctx context.Context, path string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.reconnectIfNeededLocked(ctx); err != nil {
		return err
	}

	f.drain()

	cmd := fmt.Sprintf("storage write_chunk %s %d\r", path, len(data))
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
		n, err := f.port.Write(data[written:])
		if err != nil {
			f.markDisconnectedIfRelevant(err)
			return fmt.Errorf("writing file data at offset %d: %w", written, err)
		}
		written += n
	}

	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := f.readUntilPromptCtx(readCtx)
	f.markDisconnectedIfRelevant(err)
	return err
}

func (f *Flipper) sendRaw(data string) error {
	_, err := f.port.Write([]byte(data))
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
// Raw reads with a short port-level timeout also let us poll ctx regularly.
// When the accumulator exceeds the configured cap, partial output is returned
// alongside ErrResponseTruncated so the caller can still inspect it.
func (f *Flipper) readUntilPromptCtx(ctx context.Context) (string, error) {
	var accum []byte
	buf := make([]byte, 512)

	for {
		if err := ctx.Err(); err != nil {
			return parseResponse(accum, false), err
		}
		n, err := f.port.Read(buf)
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
func indexOfPrompt(b []byte) int {
	return bytes.LastIndex(b, []byte(">: "))
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
	f.port.SetReadTimeout(100 * time.Millisecond)
	buf := make([]byte, 1024)
	for {
		n, _ := f.port.Read(buf)
		if n == 0 {
			break
		}
	}
	f.port.SetReadTimeout(5 * time.Second)
}
