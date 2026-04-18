package marauder

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"go.bug.st/serial"
)

// portIface is the subset of go.bug.st/serial.Port the package actually
// uses. Defined as an interface so tests can inject a fake (see
// fake_port_test.go) without opening a real serial device. serial.Port
// satisfies this interface today — Connect still returns one.
type portIface interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadTimeout(time.Duration) error
}

// Marauder interfaces with the ESP32 Marauder firmware over serial.
// Default port is /dev/ttyACM1 for the official Flipper WiFi devboard (ESP32-S2 USB CDC).
// Default baud rate is 115200.
//
// Protocol:
//   - Commands are terminated with '\n' (Marauder uses Serial.readStringUntil('\n')).
//   - After a command is sent, Marauder echoes the command prefixed with '#' on the first line.
//   - Output lines follow, terminated by a '> ' prompt (greater-than + space).
type Marauder struct {
	port   portIface
	mu     sync.Mutex
	reader *bufio.Reader
}

// newMarauderWithPort wires a Marauder around a caller-supplied portIface.
// Unexported because callers outside the package should use Connect; the
// only in-repo consumer is the fake-port test harness.
func newMarauderWithPort(p portIface) *Marauder {
	return &Marauder{
		port:   p,
		reader: bufio.NewReader(p),
	}
}

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

	m := &Marauder{
		port:   port,
		reader: bufio.NewReader(port),
	}

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

// ExecLong is Exec with a longer default timeout for slow operations.
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

		firstLine := true
		consecutiveErrors := 0

		for {
			select {
			case <-done:
				m.port.Write([]byte("stopscan\n"))
				return
			default:
			}

			line, err := m.reader.ReadString('\n')
			if err != nil {
				consecutiveErrors++
				if consecutiveErrors > 10 {
					return // device likely disconnected
				}
				continue
			}
			consecutiveErrors = 0
			line = strings.TrimSpace(line)

			// Skip the command echo line (e.g. "#scanap").
			if firstLine && strings.HasPrefix(line, "#") {
				firstLine = false
				continue
			}
			firstLine = false

			// Stop streaming when the prompt is received.
			if line == ">" || line == "> " {
				return
			}

			if line != "" {
				lines <- line
			}
		}
	}()

	return lines, done, nil
}

// readUntilPrompt reads lines after a command until the '> ' prompt appears or
// two consecutive idle timeouts occur, then returns the collected output.
// The command echo line (prefixed with '#') is stripped.
func (m *Marauder) readUntilPrompt(timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lines []string
	sawPrompt := false

	m.port.SetReadTimeout(2 * time.Second)
	defer m.port.SetReadTimeout(5 * time.Second)

	firstLine := true
	silenceCount := 0

	for time.Now().Before(deadline) {
		line, err := m.reader.ReadString('\n')
		if err != nil {
			silenceCount++
			if silenceCount >= 2 {
				break // Two consecutive read timeouts = command done.
			}
			continue
		}
		silenceCount = 0
		line = strings.TrimSpace(line)

		// Strip the command echo line (e.g. "#scanap").
		if firstLine && strings.HasPrefix(line, "#") {
			firstLine = false
			continue
		}
		firstLine = false

		// Stop collecting when the '> ' prompt is received.
		if line == ">" || line == "> " {
			sawPrompt = true
			break
		}

		if line != "" {
			lines = append(lines, line)
		}
	}

	if !sawPrompt {
		return strings.Join(lines, "\n"), fmt.Errorf("timeout waiting for prompt after %v", timeout)
	}
	return strings.Join(lines, "\n"), nil
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
