package marauder

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"go.bug.st/serial"
)

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

func (m *Marauder) Close() error {
	return m.port.Close()
}

// Exec sends a command and reads the response until the '> ' prompt appears or idle timeout.
// The echo line (prefixed with '#') is stripped from the returned output.
func (m *Marauder) Exec(command string, timeout time.Duration) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.drain()

	if _, err := m.port.Write([]byte(command + "\n")); err != nil {
		return "", fmt.Errorf("sending command: %w", err)
	}

	return m.readUntilPrompt(timeout)
}

// ExecLong is a deprecated alias for Exec; callers supply the timeout
// themselves, so there is no behavioural difference between the two.
// Prefer Exec in new code. Retained to avoid breaking external callers.
//
// Deprecated: use Exec.
func (m *Marauder) ExecLong(command string, timeout time.Duration) (string, error) {
	return m.Exec(command, timeout)
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

	go func() {
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
					lines <- line
				}
			}

			// Check if the unterminated suffix is the '> ' prompt.
			if suffix := strings.TrimSpace(string(accum)); suffix == ">" || suffix == "> " {
				return
			}
		}
	}()

	return lines, done, nil
}

// readUntilPrompt accumulates raw bytes from the port until the '> ' prompt is
// seen or the wall-clock deadline expires. Unlike bufio.ReadString('\n'), this
// approach does not block waiting for a newline — Marauder's '> ' prompt has
// none. SetReadTimeout is set to 100 ms per read so the deadline is polled
// regularly even when the CP210x driver's SetReadTimeout is unreliable under WSL.
func (m *Marauder) readUntilPrompt(timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var accum []byte
	buf := make([]byte, 512)

	for time.Now().Before(deadline) {
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
	}

	return parseMarauderResponse(accum), fmt.Errorf("timeout waiting for prompt after %v", timeout)
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
	m.port.SetReadTimeout(100 * time.Millisecond)
	buf := make([]byte, 1024)
	for {
		n, _ := m.port.Read(buf)
		if n == 0 {
			break
		}
	}
	m.port.SetReadTimeout(5 * time.Second)
}
