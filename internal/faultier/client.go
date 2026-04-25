package faultier

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"go.bug.st/serial"
)

// Port is the subset of go.bug.st/serial.Port the package uses.
// Defined as an interface so tests can inject a Mock without opening hardware.
type Port interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadTimeout(time.Duration) error
}

// Client drives a Faultier USB voltage-glitcher over its secondary CDC-ACM
// serial bridge.
//
// Concurrency: Client is NOT safe for concurrent use.  The Faultier protocol
// is a strict request–response exchange; interleaving commands from multiple
// goroutines would corrupt framing.  Callers that share a Client across
// goroutines must serialize access externally (e.g. with a sync.Mutex).
//
// The primary USB bulk channel (used by faultier-python) is not accessed here;
// see doc.go for the rationale.
type Client struct {
	port   Port
	closed bool
}

// DefaultBaud is the baud rate for the Faultier serial bridge.
const DefaultBaud = 115200

// Connect opens the serial bridge at portName and returns a ready Client.
// baud is the serial baud rate; pass 0 to use DefaultBaud (115200).
func Connect(portName string, baud int) (*Client, error) {
	if baud == 0 {
		baud = DefaultBaud
	}
	mode := &serial.Mode{
		BaudRate: baud,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}
	p, err := serial.Open(portName, mode)
	if err != nil {
		return nil, fmt.Errorf("faultier: opening serial port %q: %w", portName, err)
	}
	if err := p.SetReadTimeout(5 * time.Second); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("faultier: setting read timeout: %w", err)
	}
	return &Client{port: p}, nil
}

// newWithPort creates a Client backed by an already-open Port.  Used in tests
// and by the Mock factory.
func newWithPort(p Port) *Client {
	return &Client{port: p}
}

// Close closes the underlying serial port.  Calling Close more than once is
// safe — subsequent calls return nil without touching the port.
func (c *Client) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.port.Close()
}

// --- High-level API ----------------------------------------------------------

// GlitcherConfig holds the parameters sent with OpConfigure.
// Zero values are safe defaults (no trigger, crowbar output, zero delay/pulse).
type GlitcherConfig struct {
	TriggerType    TriggerType
	TriggerSource  TriggerSource
	GlitchOutput   GlitchOutput
	DelayUS        uint32
	PulseUS        uint32
	PowerCycle     bool
	PowerCycleLen  uint8 // cycles/10 — 0–255 encodes 0–2550 hardware cycles
}

// SetPulse configures the glitch delay and pulse width before the next Arm or
// Fire.  Both values are in microseconds.  Maps to the upstream Python
// configure_glitcher(delay=..., pulse=...) call.
func (c *Client) SetPulse(delayUS, pulseUS uint32) error {
	cfg := GlitcherConfig{
		TriggerType:   TriggerNone,
		TriggerSource: TriggerSrcNone,
		GlitchOutput:  OutCrowbar,
		DelayUS:       delayUS,
		PulseUS:       pulseUS,
	}
	return c.Configure(cfg)
}

// Configure sends a full GlitcherConfig to the device (OpConfigure).
// Call this before Arm or Fire when you need more than just delay/pulse.
func (c *Client) Configure(cfg GlitcherConfig) error {
	payload := encodeConfigPayload(cfg)
	if err := c.sendFrame(OpConfigure, payload); err != nil {
		return fmt.Errorf("faultier.Configure: %w", err)
	}
	return c.expectOK("Configure")
}

// Arm arms the trigger. The device waits for the configured trigger condition
// before firing the glitch pulse.  Maps to glitch_non_blocking() in the
// upstream Python library.
func (c *Client) Arm() error {
	if err := c.sendFrame(OpArm, nil); err != nil {
		return fmt.Errorf("faultier.Arm: %w", err)
	}
	return c.expectOK("Arm")
}

// Fire fires a glitch immediately without waiting for a hardware trigger.
// Maps to Faultier.glitch() with TRIGGER_NONE in the upstream Python library.
func (c *Client) Fire() error {
	if err := c.sendFrame(OpFire, nil); err != nil {
		return fmt.Errorf("faultier.Fire: %w", err)
	}
	return c.expectOK("Fire")
}

// Disarm cancels an armed trigger.  The upstream Python library achieves the
// same effect via default_settings() (resetting all outputs to OUT_NONE/
// TRIGGER_NONE).
func (c *Client) Disarm() error {
	if err := c.sendFrame(OpDisarm, nil); err != nil {
		return fmt.Errorf("faultier.Disarm: %w", err)
	}
	return c.expectOK("Disarm")
}

// Sweep arms the device and iterates delay from startUS to endUS in stepUS
// increments, calling Fire on each step.  It is a host-side sweep loop that
// re-configures and re-fires the device; there is no sweep opcode in the wire
// protocol.
//
// Sweep aborts on the first device error and returns it.
func (c *Client) Sweep(startUS, endUS, stepUS uint32) error {
	if stepUS == 0 {
		return fmt.Errorf("faultier.Sweep: step_us must be > 0")
	}
	if startUS > endUS {
		return fmt.Errorf("faultier.Sweep: start_us (%d) > end_us (%d)", startUS, endUS)
	}
	for delay := startUS; delay <= endUS; delay += stepUS {
		if err := c.SetPulse(delay, 0); err != nil {
			return fmt.Errorf("faultier.Sweep at delay=%d: configure: %w", delay, err)
		}
		if err := c.Fire(); err != nil {
			return fmt.Errorf("faultier.Sweep at delay=%d: fire: %w", delay, err)
		}
		// Prevent delay from wrapping around if endUS is MaxUint32.
		if delay == endUS {
			break
		}
	}
	return nil
}

// Status queries the device for its current armed state and last glitch
// outcome.  Maps to reading the Python Faultier's internal state after a call.
func (c *Client) Status() (StatusBlock, error) {
	if err := c.sendFrame(OpStatus, nil); err != nil {
		return StatusBlock{}, fmt.Errorf("faultier.Status: %w", err)
	}
	return c.readStatus()
}

// --- Frame encode / decode ---------------------------------------------------

// encodeConfigPayload serialises a GlitcherConfig into the 13-byte
// OpConfigure payload.
func encodeConfigPayload(cfg GlitcherConfig) []byte {
	p := make([]byte, ConfigurePayloadLen)
	p[0] = byte(cfg.TriggerType)
	p[1] = byte(cfg.TriggerSource)
	p[2] = byte(cfg.GlitchOutput)
	binary.LittleEndian.PutUint32(p[3:7], cfg.DelayUS)
	binary.LittleEndian.PutUint32(p[7:11], cfg.PulseUS)
	if cfg.PowerCycle {
		p[11] = 0x01
	}
	p[12] = cfg.PowerCycleLen
	return p
}

// decodeConfigPayload parses the 13-byte OpConfigure payload into a
// GlitcherConfig.  Returns an error when p is too short.
func decodeConfigPayload(p []byte) (GlitcherConfig, error) {
	if len(p) < ConfigurePayloadLen {
		return GlitcherConfig{}, fmt.Errorf("configure payload too short: %d < %d", len(p), ConfigurePayloadLen)
	}
	return GlitcherConfig{
		TriggerType:   TriggerType(p[0]),
		TriggerSource: TriggerSource(p[1]),
		GlitchOutput:  GlitchOutput(p[2]),
		DelayUS:       binary.LittleEndian.Uint32(p[3:7]),
		PulseUS:       binary.LittleEndian.Uint32(p[7:11]),
		PowerCycle:    p[11] != 0,
		PowerCycleLen: p[12],
	}, nil
}

// frameChecksum returns the XOR of all bytes from opcode through end of payload.
func frameChecksum(opcode byte, payload []byte) byte {
	cs := opcode
	for _, b := range payload {
		cs ^= b
	}
	return cs
}

// sendFrame encodes and writes a complete frame to the port.
func (c *Client) sendFrame(opcode byte, payload []byte) error {
	payLen := len(payload)
	frame := make([]byte, FrameHeaderLen+payLen+FrameChecksumLen)
	frame[0] = FrameMagic0
	frame[1] = FrameMagic1
	frame[2] = opcode
	binary.LittleEndian.PutUint16(frame[3:5], uint16(payLen))
	copy(frame[5:], payload)
	frame[FrameHeaderLen+payLen] = frameChecksum(opcode, payload)
	_, err := c.port.Write(frame)
	return err
}

// readByte reads exactly one byte from the port.
func (c *Client) readByte() (byte, error) {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c.port, buf); err != nil {
		return 0, err
	}
	return buf[0], nil
}

// readExact reads exactly n bytes from the port.
func (c *Client) readExact(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(c.port, buf)
	return buf, err
}

// readResponseMagic reads and validates the two-byte frame magic prefix.
func (c *Client) readResponseMagic() error {
	m0, err := c.readByte()
	if err != nil {
		return fmt.Errorf("reading response magic[0]: %w", err)
	}
	if m0 != FrameMagic0 {
		return fmt.Errorf("bad response magic[0]: got 0x%02X want 0x%02X", m0, FrameMagic0)
	}
	m1, err := c.readByte()
	if err != nil {
		return fmt.Errorf("reading response magic[1]: %w", err)
	}
	if m1 != FrameMagic1 {
		return fmt.Errorf("bad response magic[1]: got 0x%02X want 0x%02X", m1, FrameMagic1)
	}
	return nil
}

// expectOK reads a response frame and returns nil on RespOK, or a descriptive
// error on RespError or unexpected code.
func (c *Client) expectOK(op string) error {
	if err := c.readResponseMagic(); err != nil {
		return fmt.Errorf("faultier.%s: %w", op, err)
	}
	code, err := c.readByte()
	if err != nil {
		return fmt.Errorf("faultier.%s: reading response code: %w", op, err)
	}
	switch code {
	case RespOK:
		return nil
	case RespError:
		ec, err := c.readByte()
		if err != nil {
			return fmt.Errorf("faultier.%s: reading error code: %w", op, err)
		}
		return fmt.Errorf("faultier.%s: device error: %s", op, ErrCodeString(ec))
	default:
		return fmt.Errorf("faultier.%s: unexpected response code 0x%02X", op, code)
	}
}

// readStatus reads and parses a RespStatus response frame.
func (c *Client) readStatus() (StatusBlock, error) {
	if err := c.readResponseMagic(); err != nil {
		return StatusBlock{}, fmt.Errorf("faultier.Status: %w", err)
	}
	code, err := c.readByte()
	if err != nil {
		return StatusBlock{}, fmt.Errorf("faultier.Status: reading response code: %w", err)
	}
	if code == RespError {
		ec, err := c.readByte()
		if err != nil {
			return StatusBlock{}, fmt.Errorf("faultier.Status: reading error code: %w", err)
		}
		return StatusBlock{}, fmt.Errorf("faultier.Status: device error: %s", ErrCodeString(ec))
	}
	if code != RespStatus {
		return StatusBlock{}, fmt.Errorf("faultier.Status: unexpected response code 0x%02X", code)
	}
	raw, err := c.readExact(StatusBlockLen)
	if err != nil {
		return StatusBlock{}, fmt.Errorf("faultier.Status: reading status block: %w", err)
	}
	sb := StatusBlock{
		Armed:       raw[0] != 0,
		LastDelayUS: binary.LittleEndian.Uint32(raw[1:5]),
		LastOutcome: raw[5],
		Reserved:    raw[6],
	}
	return sb, nil
}
