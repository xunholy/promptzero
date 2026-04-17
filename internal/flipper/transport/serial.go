package transport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"go.bug.st/serial"
)

// defaultSerialBaud is used when a serial:// URL omits the baud query
// parameter. Matches the long-standing default configured in
// internal/config.SerialConfig.
const defaultSerialBaud = 230400

// defaultReadTimeout is the per-Read timeout configured on the serial
// port so the CLI layer can poll ctx rather than block forever waiting
// for the Flipper's promptless ">: " banner. Matches the value that
// lived inline in serial.go before the transport extraction.
const defaultReadTimeout = 500 * time.Millisecond

// serialDrainTimeout is the post-command "has the device gone quiet?"
// window. 100 ms is enough on real hardware for a fresh CLI response
// chunk to arrive and cheap enough to keep command latency low. BLE
// will likely want a larger value.
const serialDrainTimeout = 100 * time.Millisecond

func init() { Register("serial", serialDialer) }

// serialDialer parses a serial://<path>?baud=<int> URL and returns an
// undialled transport. Accepts omitted baud (falls back to
// defaultSerialBaud) so a bare "serial:///dev/ttyACM0" URL is legal.
func serialDialer(rawURL string) (Transport, error) {
	path, q, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	baud := defaultSerialBaud
	if s := q.Get("baud"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("transport: invalid baud %q in URL %q", s, rawURL)
		}
		baud = v
	}
	return &serialTransport{path: path, baud: baud}, nil
}

// serialTransport is the USB CDC-ACM implementation of Transport.
//
// This type is the direct descendant of the old *serial.Port field on
// *flipper.Flipper — all the DTR/timeout/hot-plug-scan logic moved here
// unchanged. The flipper command layer above it sees only the Transport
// interface.
type serialTransport struct {
	mu   sync.Mutex
	port serial.Port
	path string
	baud int

	// originalPath is what the caller asked to open; preserved across
	// Reconnect because the kernel may re-enumerate a replugged Flipper
	// under a different /dev/ttyACM* node, in which case Reconnect's
	// scan will update path but we still want to try the original
	// first the next time around.
	originalPath string
}

// Dial opens the serial port, asserts DTR, and sets a short read
// timeout. The CLI handshake (reading until ">: ") is the flipper
// layer's job — it lives above the transport because the prompt string
// is a protocol concern, not an I/O concern.
func (t *serialTransport) Dial(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.port != nil {
		return fmt.Errorf("transport: serial already dialled (%s)", t.path)
	}
	if t.originalPath == "" {
		t.originalPath = t.path
	}
	p, err := openSerialPort(t.path, t.baud)
	if err != nil {
		return err
	}
	t.port = p
	return nil
}

// Reconnect closes the current port and re-scans /dev/ttyACM* for a
// re-enumerated device. The original path is tried first; remaining
// candidates are probed in discovery order. Identity verification
// (matching hardware_uid) stays in the flipper layer above because it
// requires running a CLI command.
func (t *serialTransport) Reconnect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.port != nil {
		_ = t.port.Close()
		t.port = nil
	}

	orig := t.originalPath
	if orig == "" {
		orig = t.path
	}
	candidates := []string{orig}
	if matches, _ := filepath.Glob("/dev/ttyACM*"); len(matches) > 0 {
		seen := map[string]bool{orig: true}
		for _, m := range matches {
			if !seen[m] {
				candidates = append(candidates, m)
				seen[m] = true
			}
		}
	}

	for _, path := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		p, err := openSerialPort(path, t.baud)
		if err != nil {
			continue
		}
		t.port = p
		t.path = path
		return nil
	}
	return fmt.Errorf("transport: no serial port responded after scan (original=%s)", orig)
}

// openSerialPort runs the open + DTR + read-timeout dance that both
// Dial and Reconnect need. DTR is asserted because the Flipper shell
// only activates when DTR goes high; on a pty slave (used by the mock
// harness in internal/flipper/mock) the TIOCM* ioctls are unsupported
// and we swallow the error — the mock drives a canned banner directly.
func openSerialPort(path string, baud int) (serial.Port, error) {
	mode := &serial.Mode{
		BaudRate: baud,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}
	p, err := serial.Open(path, mode)
	if err != nil {
		return nil, fmt.Errorf("transport: opening %s: %w", path, err)
	}
	// SetDTR best-effort — pty slaves don't support the ioctl.
	_ = p.SetDTR(true)
	if err := p.SetReadTimeout(defaultReadTimeout); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("transport: setting read timeout on %s: %w", path, err)
	}
	return p, nil
}

func (t *serialTransport) Read(p []byte) (int, error) {
	t.mu.Lock()
	port := t.port
	t.mu.Unlock()
	if port == nil {
		return 0, os.ErrClosed
	}
	return port.Read(p)
}

func (t *serialTransport) Write(p []byte) (int, error) {
	t.mu.Lock()
	port := t.port
	t.mu.Unlock()
	if port == nil {
		return 0, os.ErrClosed
	}
	return port.Write(p)
}

func (t *serialTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.port == nil {
		return nil
	}
	err := t.port.Close()
	t.port = nil
	return err
}

func (t *serialTransport) SetReadTimeout(d time.Duration) error {
	t.mu.Lock()
	port := t.port
	t.mu.Unlock()
	if port == nil {
		return os.ErrClosed
	}
	return port.SetReadTimeout(d)
}

func (t *serialTransport) Identity() string           { return t.path }
func (t *serialTransport) DrainTimeout() time.Duration { return serialDrainTimeout }
func (t *serialTransport) Kind() string               { return "serial" }
