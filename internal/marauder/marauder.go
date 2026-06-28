package marauder

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"go.bug.st/serial"

	"github.com/xunholy/promptzero/internal/obs"
)

// defaultMaxAccumBytes bounds how much data a single Marauder read can buffer
// before it is treated as a runaway. The Marauder reports attacker-influenced
// data (SSIDs / BSSIDs / BLE names from the surrounding RF environment, which
// an adversary can flood with thousands of forged beacons) over a link that
// could also be a malfunctioning or malicious board, so an unbounded read
// accumulator is a memory-DoS vector. 8 MiB matches the Flipper serial cap
// (internal/flipper.defaultMaxAccumBytes) so both transports share one bound.
const defaultMaxAccumBytes = 8 * 1024 * 1024 // 8 MiB

// ErrResponseTruncated is returned (alongside the partial output) when a read
// exceeds the accumulator cap before the prompt arrives. Mirrors
// flipper.ErrResponseTruncated.
var ErrResponseTruncated = errors.New("marauder response truncated: exceeded max accumulator size")

// Port is the subset of go.bug.st/serial.Port the package actually uses.
// Exported so sibling test packages (internal/testmocks) can inject a
// fake backend via NewWithPort. serial.Port satisfies this interface
// today — production Connect still returns one.
type Port interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadTimeout(time.Duration) error
}

// portIface is an internal alias retained so the package-local test
// harness reads the same way it used to.
type portIface = Port

// Marauder interfaces with the ESP32 Marauder firmware over serial.
// Default port is /dev/ttyACM1 for the official Flipper WiFi devboard (ESP32-S2 USB CDC).
// Default baud rate is 115200.
//
// Protocol:
//   - Commands are terminated with '\n' (Marauder uses Serial.readStringUntil('\n')).
//   - After a command is sent, Marauder echoes the command prefixed with '#' on the first line.
//   - Output lines follow, terminated by a '> ' prompt (greater-than + space).
//   - The '> ' prompt has NO trailing newline; line-based reads would block forever.
type Marauder struct {
	port portIface
	mu   sync.Mutex
	// streamBackpressure bounds how long Stream waits to deliver a line
	// before giving up on a stalled consumer. Zero means the 2s default;
	// tests set it small. On expiry Stream stops the device scan (stopscan)
	// just like an explicit done, so the marauder is never left scanning.
	streamBackpressure time.Duration
	// maxAccumBytes caps the in-flight read buffer for readUntilPromptCtx and
	// Stream. Zero means defaultMaxAccumBytes. See SetMaxAccumBytes.
	maxAccumBytes int
}

// SetMaxAccumBytes overrides the per-read accumulator cap. Values <= 0 reset
// to the default. Mirrors flipper.(*Flipper).SetMaxAccumBytes.
func (m *Marauder) SetMaxAccumBytes(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n <= 0 {
		m.maxAccumBytes = 0
		return
	}
	m.maxAccumBytes = n
}

// accumCap returns the effective accumulator cap. Reads m.maxAccumBytes
// without locking — callers (readUntilPromptCtx, the Stream goroutine) already
// hold m.mu for the duration of a read.
func (m *Marauder) accumCap() int {
	if m.maxAccumBytes > 0 {
		return m.maxAccumBytes
	}
	return defaultMaxAccumBytes
}

// NewWithPort wires a Marauder around a caller-supplied Port. Production
// code should call Connect; this constructor exists for tests (including
// the sibling internal/testmocks harness) that need to inject a fake
// serial backend without opening a real device.
func NewWithPort(p Port) *Marauder {
	return &Marauder{port: p}
}

// newMarauderWithPort is a package-local alias that preserves the
// unexported spelling used by the in-package test harness.
func newMarauderWithPort(p portIface) *Marauder { return NewWithPort(p) }

func Connect(portName string, baudRate int) (*Marauder, error) {
	if baudRate == 0 {
		baudRate = 115200
	}

	mode := &serial.Mode{
		BaudRate: baudRate,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}

	port, err := serial.Open(portName, mode)
	if err != nil {
		return nil, fmt.Errorf("opening marauder serial port %s: %w", portName, err)
	}

	if err := port.SetReadTimeout(5 * time.Second); err != nil {
		port.Close()
		return nil, fmt.Errorf("setting read timeout: %w", err)
	}

	m := &Marauder{port: port}

	// Drain any pending output before issuing commands.
	m.drain()

	return m, nil
}

// ConnectBLE establishes a direct BLE serial link to a standalone ESP32-Marauder
// devboard exposing the standard Nordic-UART-style serial GATT layout
// (service 4fafc201-1fb5-459e-8fcc-c5c9c331914b, TX/RX beb5483e-…). This path
// bypasses the Flipper UART bridge entirely — wire it up when the Marauder
// devboard is reachable directly over Bluetooth and the operator wants both
// devices on independent transports.
//
// addr accepts the same forms as the Flipper BLE transport: a hardware MAC
// (Linux/Windows), a CoreBluetooth peripheral UUID (macOS), or a bare
// LocalName matched at scan time. May be passed with or without the ble://
// scheme prefix.
//
// The returned *Marauder shares all post-connect machinery (Exec / Stream /
// drain / readUntilPrompt) with the serial path; the underlying transport is
// the only thing that differs. Honours ctx for the scan + connect phase only
// — once dialled, BLE notifications drive Read independently of ctx.
func ConnectBLE(ctx context.Context, addr string) (*Marauder, error) {
	port, err := dialMarauderBLE(ctx, addr)
	if err != nil {
		return nil, err
	}
	m := NewWithPort(port)
	// Drain any startup banner the firmware emitted between subscribing to
	// notifications and the first Exec. Mirrors the serial path.
	m.drain()
	return m, nil
}

func (m *Marauder) Close() error {
	return m.port.Close()
}

// Exec sends a command and reads the response until the '> ' prompt appears or idle timeout.
// The echo line (prefixed with '#') is stripped from the returned output.
//
// Preserved for backward compatibility — 95 callers across the
// codebase don't have a meaningful context to thread (most are
// short blocking calls under their own timeout). New callers that
// DO have a context (especially streaming wrappers, agent
// dispatch, REPL turn cancellation) should use [ExecCtx] so a
// turn-level cancel cleanly aborts in-flight Marauder calls
// rather than blocking until the timeout fires.
func (m *Marauder) Exec(command string, timeout time.Duration) (string, error) {
	return m.ExecCtx(context.Background(), command, timeout)
}

// ExecCtx is the context-aware variant of Exec. ctx cancellation
// terminates the read loop promptly (via readUntilPromptCtx's
// 100 ms SetReadTimeout poll cadence) and returns ctx.Err
// alongside whatever partial output was accumulated. timeout is
// applied as a sub-deadline of ctx. Mirrors
// [github.com/xunholy/promptzero/internal/flipper.Flipper.ExecLongCtx]
// so transports share the same cancellation contract.
func (m *Marauder) ExecCtx(ctx context.Context, command string, timeout time.Duration) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.drain()

	if _, err := m.port.Write([]byte(command + "\n")); err != nil {
		return "", fmt.Errorf("sending command: %w", err)
	}

	return m.readUntilPromptCtx(ctx, timeout)
}

// StreamLines is the callback-based wrapper around Stream that mirrors
// the Flipper.streamLines shape: each emitted line is delivered to
// onLine; returning stop=true ends the stream early and triggers a
// stopscan via the underlying done channel. timeout bounds the call
// (via context.WithTimeout); ctx cancellation also ends the stream.
//
// Treats budget/cancel as success and returns the accumulated raw
// output regardless of exit reason — same convention as
// Flipper.streamLines + ExecLong, so streaming and blocking callers
// see identical "no error on a clean stream-end" semantics.
//
// The done-close + stopscan dispatch is handled inside Stream's
// goroutine; this wrapper is responsible for closing done exactly
// once on every exit path so the goroutine releases its mutex.
func (m *Marauder) StreamLines(ctx context.Context, command string, timeout time.Duration, onLine func(line string) (stop bool)) (string, error) {
	streamCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	lines, done, err := m.Stream(command)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	var closeOnce sync.Once
	closeDone := func() {
		closeOnce.Do(func() { close(done) })
	}
	defer closeDone()

	for {
		select {
		case <-streamCtx.Done():
			closeDone()
			// Drain remaining buffered lines so the goroutine exits
			// cleanly + we capture any final output.
			for line := range lines {
				sb.WriteString(line)
				sb.WriteByte('\n')
			}
			return sb.String(), nil
		case line, ok := <-lines:
			if !ok {
				return sb.String(), nil
			}
			sb.WriteString(line)
			sb.WriteByte('\n')
			if onLine != nil && onLine(line) {
				return sb.String(), nil
			}
		}
	}
}

// Stream sends a command and streams output lines to the returned channel.
// Close the done channel to stop streaming; stopscan is sent automatically.
func (m *Marauder) Stream(command string) (<-chan string, chan<- struct{}, error) {
	m.mu.Lock()

	m.drain()

	if _, err := m.port.Write([]byte(command + "\n")); err != nil {
		m.mu.Unlock()
		return nil, nil, fmt.Errorf("sending command: %w", err)
	}

	lines := make(chan string, 128)
	done := make(chan struct{})

	backpressure := m.streamBackpressure
	if backpressure <= 0 {
		backpressure = 2 * time.Second
	}

	obs.SafeGo("marauder.stream", func() {
		defer m.mu.Unlock()
		defer close(lines)

		var accum []byte
		buf := make([]byte, 512)
		firstLine := true
		consecutiveErrors := 0

		for {
			select {
			case <-done:
				// Best-effort: we're already tearing down the stream, so a
				// failed stopscan write is logged-only-if-the-caller-cares.
				// Swallow the error here; if the board is wedged the next
				// Exec will surface it.
				_, _ = m.port.Write([]byte("stopscan\n"))
				return
			default:
			}

			_ = m.port.SetReadTimeout(100 * time.Millisecond)
			n, err := m.port.Read(buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				consecutiveErrors++
				if consecutiveErrors > 10 {
					return
				}
				continue
			}
			if n == 0 {
				continue
			}
			consecutiveErrors = 0
			accum = append(accum, buf[:n]...)

			// Emit every complete newline-terminated line in accum.
			for {
				idx := bytes.IndexByte(accum, '\n')
				if idx < 0 {
					break
				}
				rawLine := accum[:idx]
				accum = accum[idx+1:]
				line := strings.TrimRight(string(rawLine), "\r")
				line = strings.TrimSpace(line)

				if firstLine && strings.HasPrefix(line, "#") {
					firstLine = false
					continue
				}
				firstLine = false

				if line == ">" || line == "> " {
					return
				}
				if line != "" {
					select {
					case lines <- line:
					case <-done:
						_, _ = m.port.Write([]byte("stopscan\n"))
						return
					case <-time.After(backpressure):
						// Consumer stalled: give up — but stop the device scan
						// first, exactly like the done path. Without this the
						// marauder keeps scanning into a buffer nobody reads,
						// corrupting the next command's response.
						obs.Default().Warn("marauder_stream_backpressure", "cmd", command)
						_, _ = m.port.Write([]byte("stopscan\n"))
						return
					}
				}
			}

			// Check if the unterminated suffix is the '> ' prompt.
			if suffix := strings.TrimSpace(string(accum)); suffix == ">" || suffix == "> " {
				return
			}

			// Bound the incomplete-line buffer: accum normally holds only the
			// current unterminated line (it is trimmed at every '\n' above), so
			// exceeding the cap means a single line with no newline is flooding
			// memory — a malfunctioning or hostile board. Stop the scan and end
			// the stream cleanly rather than grow without limit.
			if len(accum) > m.accumCap() {
				obs.Default().Warn("marauder_stream_accum_overflow", "cmd", command, "bytes", len(accum))
				_, _ = m.port.Write([]byte("stopscan\n"))
				return
			}
		}
	})

	return lines, done, nil
}

// readUntilPromptCtx accumulates raw bytes from the port until the '> ' prompt
// is seen or the context deadline/timeout fires. This variant is
// context-aware: the deadline is tracked via ctx rather than wall-clock
// time.Now() comparisons, which avoids false-early or false-never expiries
// under host suspend or NTP clock jumps.
//
// SetReadTimeout is set to 100 ms per iteration so ctx.Done() is polled
// frequently even when the CP210x driver's SetReadTimeout is unreliable.
func (m *Marauder) readUntilPromptCtx(ctx context.Context, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var accum []byte
	buf := make([]byte, 512)

	for {
		select {
		case <-ctx.Done():
			return parseMarauderResponse(accum), fmt.Errorf("timeout waiting for prompt after %v", timeout)
		default:
		}

		_ = m.port.SetReadTimeout(100 * time.Millisecond)
		n, err := m.port.Read(buf)
		if err != nil {
			return parseMarauderResponse(accum), fmt.Errorf("reading from port: %w", err)
		}
		if n == 0 {
			continue
		}
		accum = append(accum, buf[:n]...)
		if idx := marauderPromptIndex(accum); idx >= 0 {
			return parseMarauderResponse(accum[:idx]), nil
		}
		// Bound the accumulator: a runaway or hostile board that never sends
		// the prompt must not grow this buffer without limit. Return the
		// partial output with ErrResponseTruncated, matching the Flipper path.
		if len(accum) > m.accumCap() {
			return parseMarauderResponse(accum), ErrResponseTruncated
		}
	}
}

// marauderPromptIndex returns the byte offset of the last '> ' in b, or -1.
// Using bytes.LastIndex is safe because the prompt always appears at the end
// of the response; taking everything before the last occurrence is correct.
func marauderPromptIndex(b []byte) int {
	return bytes.LastIndex(b, []byte("> "))
}

// parseMarauderResponse normalizes line endings, strips the command echo line
// (the first line prefixed with '#'), removes blank lines, and joins the rest.
func parseMarauderResponse(b []byte) string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[0]), "#") {
		lines = lines[1:]
	}
	var result []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		result = append(result, l)
	}
	return strings.Join(result, "\n")
}

func (m *Marauder) drain() {
	// Bail on SetReadTimeout failure: a half-open port that rejects the
	// short timeout would leave the subsequent Read blocking on the
	// previous (potentially infinite) deadline.
	if err := m.port.SetReadTimeout(100 * time.Millisecond); err != nil {
		return
	}
	buf := make([]byte, 1024)
	for {
		n, _ := m.port.Read(buf)
		if n == 0 {
			break
		}
	}
	_ = m.port.SetReadTimeout(5 * time.Second)
}
