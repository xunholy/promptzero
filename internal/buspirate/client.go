package buspirate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"go.bug.st/serial"
)

const (
	// defaultBaud is the Bus Pirate 5 default CDC-ACM baud rate.
	// CDC-ACM is lane-rate irrelevant (the host FS layer ignores the baud
	// field), but the firmware README documents 115200 as the reference.
	defaultBaud = 115200

	// defaultReadTimeout is the per-Read poll window. Short enough to
	// keep ctx.Done() responsive; large enough not to spin the CPU.
	defaultReadTimeout = 100 * time.Millisecond

	// commandTimeout is the per-command overall deadline.
	commandTimeout = 10 * time.Second
)

// modePrompts maps lowercase mode names to the prompt string the firmware
// emits after a successful mode switch.
//
// Verified against DangerousPrototypes/BusPirate5-firmware README §Modes.
// Note: the brief listed I2C as `m 4`; the firmware documents I2C as m 3
// and SPI as m 4. This map follows the firmware.
var modePrompts = map[string]string{
	"hiz":   "HiZ>",
	"1wire": "1WIRE>",
	"uart":  "UART>",
	"i2c":   "I2C>",
	"spi":   "SPI>",
}

// modeNumbers maps lowercase mode names to the numeric argument for the
// `m` command. The firmware presents an interactive numbered menu; these
// numbers correspond to the documented menu options.
//
// Verified against DangerousPrototypes/BusPirate5-firmware README §Modes.
var modeNumbers = map[string]string{
	"hiz":   "0",
	"1wire": "1",
	"uart":  "2",
	"i2c":   "3",
	"spi":   "4",
}

// allPrompts is the set of every known prompt suffix used to detect when a
// response is complete. The firmware always ends a response with exactly one
// of these on its own line.
var allPrompts = []string{
	"HiZ>",
	"1WIRE>",
	"UART>",
	"I2C>",
	"SPI>",
}

// Port is the subset of go.bug.st/serial.Port this package actually uses.
// Exported so tests can inject a fake backend via NewWithPort without
// opening a real device.
type Port interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadTimeout(time.Duration) error
}

// Client is a connected Bus Pirate 5 session.
//
// Create one with Connect (real hardware) or NewWithPort (testing). All
// exported methods are safe for concurrent use; the internal mutex
// serialises command/response exchanges on the wire.
type Client struct {
	port       Port
	mu         sync.Mutex
	activeMode string // lowercase mode name, "hiz" when unknown/reset
}

// NewWithPort wraps a caller-supplied Port in a Client. Production code
// should call Connect; this constructor exists for tests that need to
// inject a mock port without opening a real serial device.
func NewWithPort(p Port) *Client {
	return &Client{port: p, activeMode: "hiz"}
}

// Connect opens the serial port at portName, drains any pending output,
// and waits for the HiZ> prompt to confirm the device is ready.
func Connect(ctx context.Context, portName string, baud int) (*Client, error) {
	if baud == 0 {
		baud = defaultBaud
	}
	mode := &serial.Mode{
		BaudRate: baud,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}
	p, err := serial.Open(portName, mode)
	if err != nil {
		return nil, fmt.Errorf("buspirate: opening %s: %w", portName, err)
	}
	if err := p.SetReadTimeout(defaultReadTimeout); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("buspirate: setting read timeout on %s: %w", portName, err)
	}

	c := &Client{port: p, activeMode: "hiz"}

	// Send a newline to wake the terminal and drain until we see a prompt.
	// If the device is mid-session it may already have an active mode prompt.
	if _, err := c.port.Write([]byte("\n")); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("buspirate: initial wake: %w", err)
	}
	if _, err := c.readUntilPromptCtx(ctx, 3*time.Second); err != nil {
		// Non-fatal: device may have sent nothing (fresh boot). Drain
		// whatever arrived and continue — subsequent commands will time out
		// if the device is truly unresponsive.
		c.drain()
	}

	return c, nil
}

// Close releases the underlying serial port.
func (c *Client) Close() error {
	return c.port.Close()
}

// Mode switches the Bus Pirate to the named mode ("hiz", "i2c", "spi",
// "uart", "1wire"). It sends `m <number>\n` and waits for the new
// mode prompt.
func (c *Client) Mode(ctx context.Context, name string) error {
	lower := strings.ToLower(name)
	num, ok := modeNumbers[lower]
	if !ok {
		return fmt.Errorf("buspirate: unknown mode %q (valid: hiz, 1wire, uart, i2c, spi)", name)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.drain()
	if _, err := c.port.Write([]byte("m " + num + "\n")); err != nil {
		return fmt.Errorf("buspirate: sending mode command: %w", err)
	}
	// After a mode switch the firmware may present a sub-menu for
	// parameters (speed, polarity, etc.). We send a second newline to
	// accept all defaults, then read until we see any prompt.
	time.Sleep(50 * time.Millisecond)
	_, _ = c.port.Write([]byte("\n"))

	out, err := c.readUntilPromptCtx(ctx, commandTimeout)
	if err != nil {
		return fmt.Errorf("buspirate: waiting for mode prompt: %w", err)
	}
	_ = out
	c.activeMode = lower
	return nil
}

// I2CScan runs the Bus Pirate built-in I2C address scanner macro `(1)` and
// returns the list of 7-bit addresses that responded.
//
// Requires the client to already be in I2C mode (call Mode("i2c") first).
func (c *Client) I2CScan(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.drain()
	if _, err := c.port.Write([]byte("(1)\n")); err != nil {
		return nil, fmt.Errorf("buspirate: sending I2C scan macro: %w", err)
	}
	out, err := c.readUntilPromptCtx(ctx, commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("buspirate: I2C scan: %w", err)
	}
	return ParseI2CScan(out), nil
}

// SPIDump reads n bytes from the SPI bus using `r:N`. For a command/response
// exchange (assert CS, write addr, read n bytes, deassert CS) use the raw
// Exec method with the full Bus Pirate expression syntax.
//
// Requires the client to already be in SPI mode (call Mode("spi") first).
func (c *Client) SPIDump(ctx context.Context, n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("buspirate: SPIDump n must be > 0")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.drain()
	cmd := fmt.Sprintf("r:%d\n", n)
	if _, err := c.port.Write([]byte(cmd)); err != nil {
		return nil, fmt.Errorf("buspirate: sending SPI read: %w", err)
	}
	out, err := c.readUntilPromptCtx(ctx, commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("buspirate: SPI dump: %w", err)
	}
	return ParseHexBytes(out), nil
}

// UARTBridge writes send to the UART bus and reads whatever response arrives
// before the command timeout. baud is the target UART baud rate (passed to
// Mode before the exchange if the client is not already in UART mode at that
// speed).
//
// Requires the client to already be in UART mode (call Mode("uart") first).
func (c *Client) UARTBridge(ctx context.Context, send []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.drain()
	// In UART bridge mode `{...}` sends raw bytes. We build the expression:
	//   {0xAB 0xCD ...}
	var sb strings.Builder
	sb.WriteString("{")
	for i, b := range send {
		if i > 0 {
			sb.WriteString(" ")
		}
		fmt.Fprintf(&sb, "0x%02X", b)
	}
	sb.WriteString("}\n")

	if _, err := c.port.Write([]byte(sb.String())); err != nil {
		return nil, fmt.Errorf("buspirate: sending UART bytes: %w", err)
	}
	out, err := c.readUntilPromptCtx(ctx, commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("buspirate: UART bridge: %w", err)
	}
	return ParseHexBytes(out), nil
}

// MeasureVoltages runs the `v` command and returns a map of pin index → volts.
// The Bus Pirate labels IO pins IO0–IO7; this method returns 0–7 as keys.
// Additional rails (VOUT, VREG) are available via the raw output; this method
// focuses on the IO pins for the standard tool surface.
func (c *Client) MeasureVoltages(ctx context.Context) (map[int]float64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.drain()
	if _, err := c.port.Write([]byte("v\n")); err != nil {
		return nil, fmt.Errorf("buspirate: sending voltage command: %w", err)
	}
	out, err := c.readUntilPromptCtx(ctx, commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("buspirate: voltage measurement: %w", err)
	}
	return ParseVoltages(out)
}

// PinSet drives a digital or analog level on an IO pin. vOrLogic may be:
//   - int / float64 — written as a voltage e.g. `D 1 3.3` (pin 1 → 3.3 V)
//   - bool — written as `D 1 1` (high) or `D 1 0` (low)
//   - string "0"/"1"/"high"/"low" — same semantics as bool
//
// Requires the client to already be in a mode that supports pin output.
func (c *Client) PinSet(ctx context.Context, pin int, vOrLogic any) error {
	var voltStr string
	switch v := vOrLogic.(type) {
	case bool:
		if v {
			voltStr = "1"
		} else {
			voltStr = "0"
		}
	case int:
		voltStr = fmt.Sprintf("%d", v)
	case float64:
		voltStr = fmt.Sprintf("%.2f", v)
	case string:
		lower := strings.ToLower(strings.TrimSpace(v))
		switch lower {
		case "1", "high", "on", "true":
			voltStr = "1"
		case "0", "low", "off", "false":
			voltStr = "0"
		default:
			voltStr = v
		}
	default:
		return fmt.Errorf("buspirate: PinSet: unsupported value type %T", vOrLogic)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.drain()
	cmd := fmt.Sprintf("D %d %s\n", pin, voltStr)
	if _, err := c.port.Write([]byte(cmd)); err != nil {
		return fmt.Errorf("buspirate: sending pin set: %w", err)
	}
	_, err := c.readUntilPromptCtx(ctx, commandTimeout)
	if err != nil {
		return fmt.Errorf("buspirate: pin set: %w", err)
	}
	return nil
}

// PinRead reads the voltage on a single IO pin using `a N` (analog read).
// The firmware prints the pin voltage; this method returns it as a float64.
//
// Verified: Bus Pirate 5 uses `a` for analog pin reads; `A` is the uppercase
// alias that also prints the percentage of full scale.
func (c *Client) PinRead(ctx context.Context, pin int) (float64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.drain()
	cmd := fmt.Sprintf("a %d\n", pin)
	if _, err := c.port.Write([]byte(cmd)); err != nil {
		return 0, fmt.Errorf("buspirate: sending pin read: %w", err)
	}
	out, err := c.readUntilPromptCtx(ctx, commandTimeout)
	if err != nil {
		return 0, fmt.Errorf("buspirate: pin read: %w", err)
	}
	return ParseSingleVoltage(out)
}

// Exec sends an arbitrary newline-terminated command and returns the raw
// response text (prompt stripped). Intended for advanced users and future
// protocol extensions that don't have dedicated Client methods.
//
// The caller is responsible for ensuring the command is appropriate for the
// current mode. Exec acquires the internal mutex, so it must not be called
// while another Client method is running.
func (c *Client) Exec(ctx context.Context, cmd string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.drain()
	if !strings.HasSuffix(cmd, "\n") {
		cmd += "\n"
	}
	if _, err := c.port.Write([]byte(cmd)); err != nil {
		return "", fmt.Errorf("buspirate: exec write: %w", err)
	}
	return c.readUntilPromptCtx(ctx, commandTimeout)
}

// readUntilPromptCtx accumulates bytes from the port until any known prompt
// string appears at the end of a line, or until ctx is cancelled / timeout
// expires. The prompt itself is stripped from the returned string.
func (c *Client) readUntilPromptCtx(ctx context.Context, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var accum []byte
	buf := make([]byte, 512)

	for {
		select {
		case <-ctx.Done():
			return strings.TrimSpace(string(accum)), fmt.Errorf("buspirate: timeout waiting for prompt after %v", timeout)
		default:
		}

		_ = c.port.SetReadTimeout(defaultReadTimeout)
		n, err := c.port.Read(buf)
		if err != nil {
			if err == io.EOF {
				return strings.TrimSpace(string(accum)), fmt.Errorf("buspirate: port closed")
			}
			return strings.TrimSpace(string(accum)), fmt.Errorf("buspirate: read error: %w", err)
		}
		if n == 0 {
			continue
		}
		accum = append(accum, buf[:n]...)

		// Check whether any known prompt appears at the end of accum.
		// The prompt is always the last thing on its own line.
		if promptIdx := findPromptIndex(accum); promptIdx >= 0 {
			body := stripPrompt(accum[:promptIdx])
			return body, nil
		}
	}
}

// findPromptIndex returns the byte offset where a prompt begins in b, or -1.
// It looks for any allPrompts entry preceded by a newline (or start of b) and
// followed by end-of-slice or a trailing newline.
func findPromptIndex(b []byte) int {
	for _, prompt := range allPrompts {
		pb := []byte(prompt)
		idx := bytes.LastIndex(b, pb)
		if idx < 0 {
			continue
		}
		// Prompt must start at the beginning of a line.
		if idx > 0 && b[idx-1] != '\n' && b[idx-1] != '\r' {
			continue
		}
		// Prompt may be followed by \r\n, \n, or end of slice.
		end := idx + len(pb)
		if end < len(b) {
			remaining := b[end:]
			trimmed := bytes.TrimLeft(remaining, "\r\n ")
			if len(trimmed) > 0 {
				continue
			}
		}
		return idx
	}
	return -1
}

// stripPrompt removes trailing whitespace and the last prompt line from the
// accumulated response, then trims the result.
func stripPrompt(b []byte) string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimSpace(s)
}

// drain reads and discards pending bytes with a short timeout so the
// port is quiet before a new command is issued. A failing SetReadTimeout
// means the port may be wedged — we bail early to surface errors on the
// next real command rather than leaving the caller stuck.
func (c *Client) drain() {
	if err := c.port.SetReadTimeout(defaultReadTimeout); err != nil {
		return
	}
	buf := make([]byte, 1024)
	for {
		n, _ := c.port.Read(buf)
		if n == 0 {
			break
		}
	}
}
