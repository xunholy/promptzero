package buspirate

import (
	"context"
	"strings"
	"testing"
	"time"
)

// newTestClient returns a Client backed by a fresh MockPort and a test
// cleanup that closes the port.
func newTestClient(t *testing.T) (*Client, *MockPort) {
	t.Helper()
	mp := NewMockPort()
	c := NewWithPort(mp)
	t.Cleanup(func() { _ = c.Close() })
	return c, mp
}

// --- Connect / prompt detection ---

func TestFindPromptIndex_HiZ(t *testing.T) {
	data := []byte("some output\nHiZ>\n")
	if findPromptIndex(data) < 0 {
		t.Fatal("expected HiZ> to be detected as prompt")
	}
}

func TestFindPromptIndex_I2C(t *testing.T) {
	data := []byte("Found address 0x50\nI2C>\n")
	if findPromptIndex(data) < 0 {
		t.Fatal("expected I2C> to be detected as prompt")
	}
}

func TestFindPromptIndex_NoPrompt(t *testing.T) {
	data := []byte("intermediate output without a prompt")
	if findPromptIndex(data) >= 0 {
		t.Fatal("should not detect a prompt in intermediate output")
	}
}

func TestFindPromptIndex_PromptNotAtLineStart(t *testing.T) {
	// "xHiZ>" — the prompt is not at the start of a line; should not match.
	data := []byte("xHiZ>\n")
	if findPromptIndex(data) >= 0 {
		t.Fatal("should not detect prompt that is not at line start")
	}
}

// --- I2CScan ---

func TestI2CScan_HappyPath(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("i2c")
	mp.Respond("(1)", "I2C ADDRESS SEARCH\nFound address 0x50\nFound address 0x68\nI2C ADDRESS SEARCH COMPLETE")

	addrs, err := c.I2CScan(context.Background())
	if err != nil {
		t.Fatalf("I2CScan: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("want 2 addresses, got %d: %v", len(addrs), addrs)
	}
	if addrs[0] != 0x50 || addrs[1] != 0x68 {
		t.Errorf("unexpected addresses: 0x%02X 0x%02X", addrs[0], addrs[1])
	}
}

func TestI2CScan_NoDevices(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("i2c")
	mp.Respond("(1)", "I2C ADDRESS SEARCH\nI2C ADDRESS SEARCH COMPLETE")

	addrs, err := c.I2CScan(context.Background())
	if err != nil {
		t.Fatalf("I2CScan: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("want 0 addresses, got %d", len(addrs))
	}
}

// --- SPIDump ---

func TestSPIDump_ReadsNBytes(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("spi")
	// Fixture: 4-byte SPI read response as the firmware would emit.
	mp.Respond("r:4", "0x00 0xFF 0xAB 0x12")

	got, err := c.SPIDump(context.Background(), 4)
	if err != nil {
		t.Fatalf("SPIDump: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 bytes, got %d: %v", len(got), got)
	}
	if got[1] != 0xFF || got[2] != 0xAB {
		t.Errorf("unexpected bytes: %v", got)
	}
}

func TestSPIDump_ZeroNReturnsError(t *testing.T) {
	c, _ := newTestClient(t)
	_, err := c.SPIDump(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error for n=0")
	}
}

// --- MeasureVoltages ---

func TestMeasureVoltages_HappyPath(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("hiz")
	// Fixture: realistic `v` output.
	mp.Respond("v", "VOUT: 3.30V\nVREG: 3.30V\nIO0: 3.30V\nIO1: 3.28V\nIO2: 0.00V\nIO3: 3.29V\nIO4: 1.65V\nIO5: 3.30V\nIO6: 3.30V\nIO7: 3.29V")

	m, err := c.MeasureVoltages(context.Background())
	if err != nil {
		t.Fatalf("MeasureVoltages: %v", err)
	}
	if len(m) != 8 {
		t.Fatalf("want 8 IO readings, got %d", len(m))
	}
	if m[4] != 1.65 {
		t.Errorf("IO4 = %v, want 1.65", m[4])
	}
}

func TestMeasureVoltages_MalformedOutput(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("hiz")
	mp.Respond("v", "VOUT: 3.30V\nnot valid")

	_, err := c.MeasureVoltages(context.Background())
	if err == nil {
		t.Fatal("expected error for output with no IO pins")
	}
}

// --- PinSet ---

func TestPinSet_BoolTrue(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("hiz")
	mp.Respond("D 1 1", "")

	if err := c.PinSet(context.Background(), 1, true); err != nil {
		t.Fatalf("PinSet: %v", err)
	}
	seen := mp.LinesSeen()
	found := false
	for _, s := range seen {
		if s == "D 1 1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("command 'D 1 1' not sent; lines seen: %v", seen)
	}
}

func TestPinSet_FloatVoltage(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("hiz")
	mp.Respond("D 3 3.30", "")

	if err := c.PinSet(context.Background(), 3, 3.3); err != nil {
		t.Fatalf("PinSet: %v", err)
	}
	seen := mp.LinesSeen()
	found := false
	for _, s := range seen {
		if s == "D 3 3.30" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("command 'D 3 3.30' not sent; lines seen: %v", seen)
	}
}

func TestPinSet_StringHigh(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("hiz")
	mp.Respond("D 0 1", "")

	if err := c.PinSet(context.Background(), 0, "high"); err != nil {
		t.Fatalf("PinSet: %v", err)
	}
	seen := mp.LinesSeen()
	found := false
	for _, s := range seen {
		if s == "D 0 1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("command 'D 0 1' not sent; lines seen: %v", seen)
	}
}

func TestPinSet_UnsupportedTypeReturnsError(t *testing.T) {
	c, _ := newTestClient(t)
	err := c.PinSet(context.Background(), 0, []byte{0x01})
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

// --- PinRead ---

func TestPinRead_HappyPath(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("hiz")
	mp.Respond("a 2", "IO2 VOLTAGE: 1.65V")

	v, err := c.PinRead(context.Background(), 2)
	if err != nil {
		t.Fatalf("PinRead: %v", err)
	}
	if v != 1.65 {
		t.Errorf("got %v, want 1.65", v)
	}
}

func TestPinRead_MalformedResponse(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("hiz")
	mp.Respond("a 5", "not a voltage")

	_, err := c.PinRead(context.Background(), 5)
	if err == nil {
		t.Fatal("expected error for malformed pin read response")
	}
}

// --- Mode ---

func TestMode_ValidMode(t *testing.T) {
	c, mp := newTestClient(t)
	// m 3 is I2C; firmware may present parameter sub-menu, we handle by
	// sending a second newline. The mock will respond to both "m 3" and
	// the empty line that follows.
	mp.Respond("m 3", "I2C mode selected")
	mp.SetMode("i2c")
	mp.Respond("", "")

	if err := c.Mode(context.Background(), "i2c"); err != nil {
		t.Fatalf("Mode: %v", err)
	}
	if c.activeMode != "i2c" {
		t.Errorf("activeMode = %q, want i2c", c.activeMode)
	}
}

func TestMode_InvalidMode(t *testing.T) {
	c, _ := newTestClient(t)
	err := c.Mode(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

// --- UARTBridge ---

func TestUARTBridge_SendsBytes(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("uart")
	mp.Respond("{0x41 0x42}", "0x41 0x42")

	got, err := c.UARTBridge(context.Background(), []byte{0x41, 0x42})
	if err != nil {
		t.Fatalf("UARTBridge: %v", err)
	}
	if len(got) != 2 || got[0] != 0x41 || got[1] != 0x42 {
		t.Errorf("unexpected response bytes: %v", got)
	}
	seen := mp.LinesSeen()
	found := false
	for _, s := range seen {
		if strings.Contains(s, "0x41") && strings.Contains(s, "0x42") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("UART bytes not seen in commands: %v", seen)
	}
}

// --- Exec ---

func TestExec_ArbitraryCommand(t *testing.T) {
	c, mp := newTestClient(t)
	mp.SetMode("hiz")
	mp.Respond("?", "Bus Pirate 5 help")

	out, err := c.Exec(context.Background(), "?")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(out, "Bus Pirate 5 help") {
		t.Errorf("unexpected output: %q", out)
	}
}

// --- Concurrency ---

// TestConcurrentExec verifies that two goroutines issuing independent Exec
// calls on the same Client serialise correctly: neither call panics and both
// return valid responses. (The test does not assert ordering since the mutex
// makes it non-deterministic.)
func TestConcurrentExec(t *testing.T) {
	mp := NewMockPort()
	mp.SetMode("hiz")
	mp.Respond("cmd1", "result1")
	mp.Respond("cmd2", "result2")
	c := NewWithPort(mp)
	t.Cleanup(func() { _ = c.Close() })

	errs := make(chan error, 2)
	run := func(cmd string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := c.Exec(ctx, cmd)
		errs <- err
	}

	go run("cmd1")
	go run("cmd2")

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Exec error: %v", err)
		}
	}
}

// --- MockPort state machine: mode switch followed by command ---

func TestMockPort_ModeSwitchThenCommand(t *testing.T) {
	mp := NewMockPort()
	// Start in HiZ, respond to mode switch, switch mock to I2C, then scan.
	mp.Respond("m 3", "I2C mode")
	mp.Respond("", "")
	mp.SetMode("i2c")
	mp.Respond("(1)", "Found address 0x50\nI2C ADDRESS SEARCH COMPLETE")

	c := NewWithPort(mp)
	t.Cleanup(func() { _ = c.Close() })

	ctx := context.Background()
	if err := c.Mode(ctx, "i2c"); err != nil {
		t.Fatalf("Mode: %v", err)
	}
	addrs, err := c.I2CScan(ctx)
	if err != nil {
		t.Fatalf("I2CScan: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != 0x50 {
		t.Errorf("unexpected addresses: %v", addrs)
	}
}
