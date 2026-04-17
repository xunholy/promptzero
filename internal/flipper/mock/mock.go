// Package mock provides a pty-backed fake Flipper CLI so serial.go and the
// command wrappers can be exercised without real hardware.
//
// The mock opens a /dev/ptmx master, hands the caller the /dev/pts/<n>
// slave path, and runs a goroutine that reads writes from the slave (i.e.
// bytes the CLI-under-test "sends" to the Flipper), dispatches them to a
// scripted command table, and writes canned responses back. A handshake
// banner is emitted as soon as the slave is first read from.
package mock

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

// Handler renders a response body for a given command line. The returned
// string is what the mock will echo back BEFORE the closing prompt (the
// prompt is appended automatically). Commands not in the table produce a
// bare prompt (same as an unknown Flipper CLI command).
type Handler func(args []string) string

// DefaultDeviceInfo is the canned device_info output returned when no
// override is provided. It mirrors the shape of a real Xtreme-fork Flipper
// so Capabilities parses the expected fork / UID / name.
const DefaultDeviceInfo = `hardware_model                : Flipper Zero
hardware_uid                  : 4521480226E18000
hardware_name                 : MockDolphin
firmware_commit               : deadbeef
firmware_origin_fork          : Xtreme
firmware_version              : XFW-MOCK
firmware_build_date           : 01-01-2025`

// DefaultBanner is emitted once when the slave is first opened, as the
// welcome banner a real Flipper prints on DTR rising. Must end with a
// prompt so the handshake observer sees ">: ".
const DefaultBanner = "\r\nWelcome to the Mock Flipper CLI!\r\nFirmware: XFW-MOCK\r\n\r\n>: "

// Option tunes the mock at construction time.
type Option func(*Mock)

// WithHandler registers a response handler for a command token (the first
// whitespace-separated word). Overwrites any previous handler.
func WithHandler(command string, h Handler) Option {
	return func(m *Mock) {
		m.handlers[command] = h
	}
}

// WithBanner overrides the one-shot welcome banner.
func WithBanner(s string) Option {
	return func(m *Mock) { m.banner = s }
}

// Mock is a running pty-backed fake Flipper. Returned by Spawn. Call Close
// (or register as t.Cleanup) to tear down.
type Mock struct {
	master *os.File
	slave  *os.File
	path   string

	banner   string
	handlers map[string]Handler

	mu       sync.Mutex
	counted  atomic.Int64 // commands observed so far, for test assertions
	linesMu  sync.Mutex
	lines    []string // raw command lines observed (for test assertions)

	closed chan struct{}
	done   chan struct{}
}

// Lines returns a copy of every non-empty command line the mock has
// dispatched since Spawn, in order. Useful for asserting what the
// flipper-under-test actually sent on the wire.
func (m *Mock) Lines() []string {
	m.linesMu.Lock()
	defer m.linesMu.Unlock()
	out := make([]string, len(m.lines))
	copy(out, m.lines)
	return out
}

// Path returns the /dev/pts/<n> slave path the caller should pass to
// flipper.Connect.
func (m *Mock) Path() string { return m.path }

// Count returns the number of commands the mock has processed since Spawn.
func (m *Mock) Count() int64 { return m.counted.Load() }

// Close tears down the pty pair and waits for the responder goroutine to
// exit. Safe to call multiple times.
func (m *Mock) Close() error {
	m.mu.Lock()
	select {
	case <-m.closed:
		m.mu.Unlock()
		return nil
	default:
		close(m.closed)
	}
	m.mu.Unlock()
	_ = m.master.Close()
	if m.slave != nil {
		_ = m.slave.Close()
	}
	<-m.done
	return nil
}

// Spawn creates a new mock Flipper. The returned path may be passed to
// flipper.Connect. The t.Cleanup hook closes it automatically.
func Spawn(t *testing.T, opts ...Option) *Mock {
	t.Helper()
	master, slavePath, err := openPty()
	if err != nil {
		t.Fatalf("mock: open pty: %v", err)
	}

	m := &Mock{
		master:   master,
		path:     slavePath,
		banner:   DefaultBanner,
		handlers: defaultHandlers(),
		closed:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	for _, o := range opts {
		o(m)
	}

	// Emit the welcome banner immediately so a reader attaching to the
	// slave sees the prompt when handshake begins.
	if _, err := master.WriteString(m.banner); err != nil {
		t.Fatalf("mock: write banner: %v", err)
	}

	go m.serve()
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// serve reads bytes from the pty master (i.e. whatever the CLI-under-test
// writes to the slave port) and dispatches each CR-terminated command.
func (m *Mock) serve() {
	defer close(m.done)
	r := bufio.NewReader(m.master)
	var buf bytes.Buffer
	for {
		select {
		case <-m.closed:
			return
		default:
		}
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return
			}
			// Fatal error on master fd — bail quietly; tests can detect via Count.
			return
		}
		switch b {
		case '\x03':
			// Ctrl+C — emit a fresh prompt, no echo.
			_, _ = m.master.WriteString("\r\n>: ")
			buf.Reset()
		case '\r', '\n':
			line := buf.String()
			buf.Reset()
			m.dispatch(line)
		default:
			buf.WriteByte(b)
		}
	}
}

func (m *Mock) dispatch(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		_, _ = m.master.WriteString("\r\n>: ")
		return
	}
	m.counted.Add(1)
	m.linesMu.Lock()
	m.lines = append(m.lines, line)
	m.linesMu.Unlock()
	// Echo the command (a real Flipper CLI echoes what the user typed).
	_, _ = fmt.Fprintf(m.master, "%s\r\n", line)

	fields := strings.Fields(line)
	head := fields[0]
	body := ""
	if h, ok := m.handlers[head]; ok {
		body = h(fields[1:])
	}
	if body != "" {
		_, _ = m.master.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			_, _ = m.master.WriteString("\r\n")
		}
	}
	_, _ = m.master.WriteString("\r\n>: ")
}

// openPty allocates a (master, slavePath) pair via the standard Unix
// ptmx+grantpt+unlockpt+ptsname dance. Linux-only; tests using this package
// must build-tag themselves appropriately if cross-platform support is ever
// needed.
//
// The slave is transiently opened and put into raw mode (ECHO off, ICANON
// off, OPOST off). Without this, the slave's tty driver would echo every
// byte written to master back to master, and the mock's reader would see
// its own banner bytes as incoming "commands".
func openPty() (*os.File, string, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open ptmx: %w", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, "", fmt.Errorf("unlockpt: %w", err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, "", fmt.Errorf("ptsname: %w", err)
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", n)

	// Open the slave briefly, disable echo + canonical processing. Termios
	// settings persist for the tty, so the subsequent serial.Open on the
	// same slavePath inherits raw state (though the serial library sets its
	// own flags too — disabling ECHO here covers the window between Spawn
	// and serial.Open).
	slave, err := os.OpenFile(slavePath, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, "", fmt.Errorf("open slave: %w", err)
	}
	if attr, gerr := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS); gerr == nil {
		attr.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
		attr.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
		attr.Oflag &^= unix.OPOST
		_ = unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, attr)
	}
	_ = slave.Close()
	return master, slavePath, nil
}

func defaultHandlers() map[string]Handler {
	return map[string]Handler{
		"device_info": func(args []string) string { return DefaultDeviceInfo },
		"info": func(args []string) string {
			if len(args) >= 1 && args[0] == "power" {
				return "charge.level                  : 82\nbattery.voltage               : 4100"
			}
			return ""
		},
		"power_info": func(args []string) string {
			return "charge_level                  : 82"
		},
		"storage": func(args []string) string {
			if len(args) >= 2 && args[0] == "info" {
				return "Label: MOCK\nType: EXFAT\n1024KiB total\n512KiB free"
			}
			return ""
		},
		"loader": func(args []string) string {
			if len(args) >= 1 && args[0] == "list" {
				return "Apps:\n\tSubGHz\n\tNFC\n\tRFID\nSettings:\n\tBluetooth\n\tSystem"
			}
			return ""
		},
		"rfid": func(args []string) string {
			if len(args) >= 1 && args[0] == "read" {
				return "Reading 125 kHz RFID...\nEM4100 0812A3C5D6\nData: 08 12 A3 C5 D6"
			}
			return ""
		},
		"led":   func(args []string) string { return "" },
		"vibro": func(args []string) string { return "" },
	}
}
