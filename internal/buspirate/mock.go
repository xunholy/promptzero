package buspirate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// MockPort is an in-memory Port implementation for tests. It approximates
// the Bus Pirate 5 text-mode protocol: scripted commands produce canned
// response bodies followed by the current-mode prompt.
//
// Usage:
//
//	mp := NewMockPort()
//	mp.SetMode("hiz")                       // initial prompt mode
//	mp.Respond("(1)", "Found address 0x50\nI2C ADDRESS SEARCH COMPLETE")
//	c := NewWithPort(mp)
//
// All methods are goroutine-safe.
type MockPort struct {
	mu        sync.Mutex
	inBuf     bytes.Buffer      // bytes written by the Client (commands)
	outBuf    bytes.Buffer      // bytes to return on Read (responses)
	responses map[string]string // command → response body
	prompt    string            // current mode prompt, e.g. "HiZ>"
	readWait  time.Duration     // poll interval when outBuf is empty
	timeout   time.Duration     // simulated read timeout
	closed    bool
	seen      []string // ordered list of commands received
}

// NewMockPort returns an initialised MockPort in HiZ mode with sane defaults.
func NewMockPort() *MockPort {
	return &MockPort{
		responses: make(map[string]string),
		prompt:    "HiZ>",
		readWait:  5 * time.Millisecond,
		timeout:   5 * time.Second,
	}
}

// SetMode updates the prompt string that is appended to every response.
// Use the lowercase mode name ("hiz", "i2c", "spi", "uart", "1wire").
func (mp *MockPort) SetMode(name string) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if p, ok := modePrompts[strings.ToLower(name)]; ok {
		mp.prompt = p
	}
}

// Respond registers a canned response body for cmd. When the MockPort sees
// cmd written to it, it emits the body followed by the current-mode prompt.
// A subsequent SetMode changes the prompt for all future responses, including
// ones already registered. The body should not include a trailing prompt —
// MockPort appends it automatically.
func (mp *MockPort) Respond(cmd, body string) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.responses[cmd] = body
}

// LinesSeen returns an ordered copy of every command line received.
func (mp *MockPort) LinesSeen() []string {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	out := make([]string, len(mp.seen))
	copy(out, mp.seen)
	return out
}

// Read implements Port. Blocks (polling at readWait intervals) until data
// is available or the simulated timeout fires.
func (mp *MockPort) Read(p []byte) (int, error) {
	deadline := time.Now().Add(mp.timeout)
	for {
		mp.mu.Lock()
		if mp.closed {
			mp.mu.Unlock()
			return 0, io.EOF
		}
		if mp.outBuf.Len() > 0 {
			n, err := mp.outBuf.Read(p)
			mp.mu.Unlock()
			return n, err
		}
		mp.mu.Unlock()
		if time.Now().After(deadline) {
			// Simulate go.bug.st/serial read-timeout: (0, nil) means "no data
			// in the window, but the port is still open."
			return 0, nil
		}
		time.Sleep(mp.readWait)
	}
}

// Write implements Port. Accumulates bytes until a newline arrives, then
// dispatches the line to the scripted responder.
func (mp *MockPort) Write(p []byte) (int, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if mp.closed {
		return 0, errors.New("buspirate mock: port closed")
	}
	mp.inBuf.Write(p)

	// Dispatch all complete newline-terminated lines in the input buffer.
	for {
		idx := bytes.IndexByte(mp.inBuf.Bytes(), '\n')
		if idx < 0 {
			break
		}
		lineBytes := make([]byte, idx)
		copy(lineBytes, mp.inBuf.Bytes()[:idx])
		mp.inBuf.Next(idx + 1)
		line := strings.TrimSpace(string(lineBytes))
		mp.seen = append(mp.seen, line)
		mp.dispatchLocked(line)
	}
	return len(p), nil
}

// dispatchLocked writes the canned response (or a bare prompt for unknown
// commands) to outBuf. Must be called with mp.mu held.
func (mp *MockPort) dispatchLocked(line string) {
	body, ok := mp.responses[line]
	if !ok {
		// Unknown command: emit the prompt so readUntilPromptCtx unblocks.
		fmt.Fprintf(&mp.outBuf, "\n%s\n", mp.prompt)
		return
	}
	if body != "" {
		mp.outBuf.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			mp.outBuf.WriteByte('\n')
		}
	}
	fmt.Fprintf(&mp.outBuf, "%s\n", mp.prompt)
}

// Close implements Port.
func (mp *MockPort) Close() error {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.closed = true
	return nil
}

// SetReadTimeout implements Port. Updates the simulated read timeout so
// the mock respects the same contract as a real serial port.
func (mp *MockPort) SetReadTimeout(d time.Duration) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if mp.closed {
		return errors.New("buspirate mock: port closed")
	}
	if d > 0 {
		mp.timeout = d
	}
	return nil
}
