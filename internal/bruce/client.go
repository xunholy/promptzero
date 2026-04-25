package bruce

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

// defaultBaud is the Bruce firmware default baud rate (USB CDC-ACM).
const defaultBaud = 115200

// defaultReadTimeout is the per-iteration read poll interval.
// Short enough that ctx.Done() is checked frequently.
const defaultReadTimeout = 100 * time.Millisecond

// defaultCmdTimeout is used when a caller does not supply an explicit timeout.
const defaultCmdTimeout = 15 * time.Second

// ErrCapabilityNotAvailable is returned by capability-gated methods (e.g.
// Scan5GHz) when the connected board does not support that feature.
var ErrCapabilityNotAvailable = fmt.Errorf("bruce: capability not available on this board")

// ErrNotConnected is returned when a Client method is called before Connect.
var ErrNotConnected = fmt.Errorf("bruce: not connected")

// Port is the subset of go.bug.st/serial.Port the package actually uses.
// Exported so tests can inject a fake backend via NewWithPort without opening
// a real device.
type Port interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadTimeout(time.Duration) error
}

// AP is a discovered Wi-Fi access point.
type AP struct {
	SSID    string `json:"ssid,omitempty"`
	BSSID   string `json:"bssid,omitempty"`
	RSSI    int    `json:"rssi,omitempty"`
	Channel int    `json:"channel,omitempty"`
	Band    string `json:"band,omitempty"` // "2.4GHz" or "5GHz"
	RawLine string `json:"raw,omitempty"`
}

// ZigbeePeer is a device observed during an IEEE 802.15.4 passive scan.
type ZigbeePeer struct {
	PANID    string `json:"pan_id,omitempty"`
	ShortAddr string `json:"short_addr,omitempty"`
	Channel  int    `json:"channel,omitempty"`
	RawLine  string `json:"raw,omitempty"`
}

// Capture is the result of an IR receive operation.
type Capture struct {
	Protocol string `json:"protocol,omitempty"`
	Code     string `json:"code,omitempty"`
	RawData  string `json:"raw_data,omitempty"`
}

// NFCCard holds the data read from an NFC tag via PN532.
type NFCCard struct {
	UID      string `json:"uid,omitempty"`
	ATQ      string `json:"atq,omitempty"`
	SAK      string `json:"sak,omitempty"`
	RawLines []string `json:"raw_lines,omitempty"`
}

// Capabilities is the feature set detected from the Bruce boot banner.
// All fields are derived from banner parsing — no runtime probing.
type Capabilities struct {
	// HasFiveGHz is true when the board supports 5 GHz Wi-Fi (ESP32-C5).
	HasFiveGHz bool `json:"has_5ghz"`

	// HasZigbee is true when the banner indicates Zigbee/IEEE 802.15.4 support.
	HasZigbee bool `json:"has_zigbee"`

	// HasLoRa is true when the banner or board type indicates LoRa support.
	HasLoRa bool `json:"has_lora"`

	// HasNFC is true when the board has a PN532 NFC module.
	HasNFC bool `json:"has_nfc"`

	// HasIR is true when the board has an IR blaster/receiver.
	HasIR bool `json:"has_ir"`

	// BoardType is the normalized lowercase board identifier, e.g.
	// "cardputer", "m5stickc", "t-display-s3", "cyd", "esp32-c5".
	BoardType string `json:"board_type,omitempty"`

	// FirmwareVersion is the semver string extracted from the boot banner.
	FirmwareVersion string `json:"firmware_version,omitempty"`
}

// Client manages communication with Bruce firmware over a serial port.
// Construct with Connect (production) or NewWithPort (testing).
type Client struct {
	port  Port
	mu    sync.Mutex
	caps  Capabilities
}

// NewWithPort wires a Client around a caller-supplied Port. Used by tests that
// inject a fake serial backend; production code should call Connect.
func NewWithPort(p Port) *Client {
	return &Client{port: p}
}

// Connect opens portName at baudRate (default 115 200), drains any pending
// bytes, sends a newline to surface the Bruce menu banner, and reads back the
// version/board line to populate Capabilities.
//
// ctx controls the initial banner-read deadline.
func Connect(ctx context.Context, portName string, baudRate int) (*Client, error) {
	if baudRate == 0 {
		baudRate = defaultBaud
	}
	mode := &serial.Mode{
		BaudRate: baudRate,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}
	p, err := serial.Open(portName, mode)
	if err != nil {
		return nil, fmt.Errorf("bruce: opening %s: %w", portName, err)
	}
	if err := p.SetReadTimeout(defaultReadTimeout); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("bruce: setting read timeout on %s: %w", portName, err)
	}
	c := &Client{port: p}
	c.drain()

	// Nudge the firmware to emit its banner.
	_, _ = c.port.Write([]byte("\n"))
	bannerCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	banner, _ := c.readUntilIdle(bannerCtx, 3*time.Second)
	c.caps = ParseBanner(banner)

	return c, nil
}

// Close releases the underlying serial port.
func (c *Client) Close() error {
	return c.port.Close()
}

// Capabilities returns the capability set populated during Connect. When the
// Client was constructed with NewWithPort the caller may set capabilities via
// [SetCapabilities] before calling any capability-gated method.
func (c *Client) Capabilities() Capabilities {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.caps
}

// SetCapabilities overwrites the stored capability set. Used by tests and by
// callers that want to hint capabilities discovered out-of-band.
func (c *Client) SetCapabilities(caps Capabilities) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.caps = caps
}

// ScanWiFi triggers a 2.4 GHz Wi-Fi AP scan and returns the parsed results.
// The scan runs for approximately scanDuration (or the firmware's built-in
// dwell time if shorter). Pass 0 to use defaultCmdTimeout.
func (c *Client) ScanWiFi(ctx context.Context) ([]AP, error) {
	raw, err := c.RawCommand(ctx, "wifi scan")
	if err != nil {
		return nil, err
	}
	return ParseAPList(raw, "2.4GHz"), nil
}

// Scan5GHz triggers a 5 GHz Wi-Fi AP scan. Returns ErrCapabilityNotAvailable
// when the board does not have HasFiveGHz set.
func (c *Client) Scan5GHz(ctx context.Context) ([]AP, error) {
	c.mu.Lock()
	has5g := c.caps.HasFiveGHz
	c.mu.Unlock()
	if !has5g {
		return nil, ErrCapabilityNotAvailable
	}
	raw, err := c.RawCommand(ctx, "wifi 5g scan")
	if err != nil {
		return nil, err
	}
	return ParseAPList(raw, "5GHz"), nil
}

// Deauth sends a deauthentication attack against the specified BSSID on the
// given channel. AUTHORIZED PENTEST / LAB USE ONLY.
func (c *Client) Deauth(ctx context.Context, bssid string, channel int) error {
	cmd := fmt.Sprintf("wifi deauth %s %d", bssid, channel)
	_, err := c.RawCommand(ctx, cmd)
	return err
}

// EvilTwin starts a rogue access point cloning ssid/bssid. The fake AP uses
// the same SSID to lure clients.  AUTHORIZED PENTEST / LAB USE ONLY.
func (c *Client) EvilTwin(ctx context.Context, ssid, bssid string) error {
	cmd := fmt.Sprintf("wifi evil %s %s", ssid, bssid)
	_, err := c.RawCommand(ctx, cmd)
	return err
}

// ZigbeeScan performs a passive IEEE 802.15.4 scan and returns any overheard
// PAN beacons. Returns ErrCapabilityNotAvailable when HasZigbee is false.
func (c *Client) ZigbeeScan(ctx context.Context) ([]ZigbeePeer, error) {
	c.mu.Lock()
	hasZ := c.caps.HasZigbee
	c.mu.Unlock()
	if !hasZ {
		return nil, ErrCapabilityNotAvailable
	}
	raw, err := c.RawCommand(ctx, "rf zigbee scan")
	if err != nil {
		return nil, err
	}
	return ParseZigbeeList(raw), nil
}

// LoRaScan passively listens on freq (MHz) for LoRa packets.
// Returns ErrCapabilityNotAvailable when HasLoRa is false.
func (c *Client) LoRaScan(ctx context.Context, freq float64) error {
	c.mu.Lock()
	hasL := c.caps.HasLoRa
	c.mu.Unlock()
	if !hasL {
		return ErrCapabilityNotAvailable
	}
	cmd := fmt.Sprintf("rf lora scan %.3f", freq)
	_, err := c.RawCommand(ctx, cmd)
	return err
}

// IRSend transmits an IR signal using the specified protocol and code string.
// Returns ErrCapabilityNotAvailable when HasIR is false.
func (c *Client) IRSend(ctx context.Context, protocol, code string) error {
	c.mu.Lock()
	hasIR := c.caps.HasIR
	c.mu.Unlock()
	if !hasIR {
		return ErrCapabilityNotAvailable
	}
	cmd := fmt.Sprintf("ir send %s %s", protocol, code)
	_, err := c.RawCommand(ctx, cmd)
	return err
}

// IRReceive opens the IR receiver and waits for a signal. Returns a Capture
// or ErrCapabilityNotAvailable when HasIR is false.
func (c *Client) IRReceive(ctx context.Context) (Capture, error) {
	c.mu.Lock()
	hasIR := c.caps.HasIR
	c.mu.Unlock()
	if !hasIR {
		return Capture{}, ErrCapabilityNotAvailable
	}
	raw, err := c.RawCommand(ctx, "ir receive")
	if err != nil {
		return Capture{}, err
	}
	return ParseCapture(raw), nil
}

// BadUSBRun executes a Ducky Script payload from Bruce's SD card.
// ducky is the filename (without leading path) on the Bruce SD card.
// AUTHORIZED PENTEST / LAB USE ONLY.
func (c *Client) BadUSBRun(ctx context.Context, ducky string) error {
	cmd := fmt.Sprintf("badusb run %s", ducky)
	_, err := c.RawCommand(ctx, cmd)
	return err
}

// NFCRead reads an NFC card/tag via the attached PN532 module.
// Returns ErrCapabilityNotAvailable when HasNFC is false.
func (c *Client) NFCRead(ctx context.Context) (NFCCard, error) {
	c.mu.Lock()
	hasNFC := c.caps.HasNFC
	c.mu.Unlock()
	if !hasNFC {
		return NFCCard{}, ErrCapabilityNotAvailable
	}
	raw, err := c.RawCommand(ctx, "nfc read")
	if err != nil {
		return NFCCard{}, err
	}
	return ParseNFCCard(raw), nil
}

// RawCommand sends cmd followed by '\n', reads until the port goes idle for
// one poll cycle or ctx expires, and returns the response as a trimmed string.
// This is the escape hatch for any Bruce command not yet wrapped by a typed
// method.
func (c *Client) RawCommand(ctx context.Context, cmd string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.port == nil {
		return "", ErrNotConnected
	}

	c.drain()

	if _, err := c.port.Write([]byte(cmd + "\n")); err != nil {
		return "", fmt.Errorf("bruce: sending command %q: %w", cmd, err)
	}

	timeout := defaultCmdTimeout
	raw, err := c.readUntilIdle(ctx, timeout)
	return raw, err
}

// readUntilIdle reads from the port until no new bytes arrive within one
// defaultReadTimeout poll cycle or ctx expires. Returns the accumulated
// text with the command echo line stripped. Must be called with mu held
// or from a section that owns the lock.
func (c *Client) readUntilIdle(ctx context.Context, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var accum []byte
	buf := make([]byte, 512)
	consecutiveEmpty := 0

	for {
		select {
		case <-ctx.Done():
			return parseBruceResponse(accum), nil
		default:
		}

		_ = c.port.SetReadTimeout(defaultReadTimeout)
		n, err := c.port.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return parseBruceResponse(accum), fmt.Errorf("bruce: reading from port: %w", err)
		}
		if n == 0 {
			consecutiveEmpty++
			// Two consecutive empty polls means the board has gone quiet.
			if consecutiveEmpty >= 2 && len(accum) > 0 {
				break
			}
			continue
		}
		consecutiveEmpty = 0
		accum = append(accum, buf[:n]...)
	}

	return parseBruceResponse(accum), nil
}

// parseBruceResponse normalizes line endings and strips any leading echo
// line (Bruce echoes the command back verbatim on the first line).
func parseBruceResponse(b []byte) string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")

	// Bruce echoes the sent command as the first non-empty line.
	// Strip it if present.
	start := 0
	if len(lines) > 0 {
		first := strings.TrimSpace(lines[0])
		if first == "" || strings.HasPrefix(first, ">") {
			start = 1
		} else {
			// Check if the first line looks like a pure command echo
			// (no spaces in middle, or matches a known command prefix).
			// We take a conservative approach and keep it — the callers
			// (Parse*) are tolerant of stray header lines.
		}
	}

	var result []string
	for _, l := range lines[start:] {
		l = strings.TrimSpace(l)
		if l == "" || l == ">" || l == "> " {
			continue
		}
		result = append(result, l)
	}
	return strings.Join(result, "\n")
}

// drain reads and discards any buffered bytes on the port to clear stale data
// before sending a command.
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

// brucePromptIndex returns the offset of the Bruce ">" prompt in b, or -1.
// Bruce's prompt is a bare ">" or "> " with optional preceding newline.
func brucePromptIndex(b []byte) int {
	return bytes.LastIndex(b, []byte("> "))
}
