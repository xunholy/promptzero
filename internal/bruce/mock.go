package bruce

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// MockPort is an in-memory implementation of Port for unit tests.
//
// Writes feed into a command dispatcher: each complete "\n"-terminated line is
// matched against a scripted-response table and the response bytes are made
// available for subsequent Read calls. Unscripted commands receive an empty
// response so callers don't block.
type MockPort struct {
	mu        sync.Mutex
	in        bytes.Buffer // bytes received from the Client (commands)
	out       bytes.Buffer // bytes returned to the Client (responses)
	responses map[string]string
	readWait  time.Duration
	timeout   time.Duration
	closed    bool
	lineQueue []string // all command lines observed (for assertions)
}

// NewMockPort returns an initialised MockPort.
func NewMockPort() *MockPort {
	return &MockPort{
		responses: make(map[string]string),
		readWait:  5 * time.Millisecond,
		timeout:   2 * time.Second,
	}
}

// Respond registers a canned response body for cmd. The body is returned
// verbatim (with a trailing "\n" appended if absent) when the MockPort
// receives that command.
func (m *MockPort) Respond(cmd, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[cmd] = body
}

// LinesSeen returns a copy of every command line received so far.
func (m *MockPort) LinesSeen() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.lineQueue))
	copy(out, m.lineQueue)
	return out
}

func (m *MockPort) Read(p []byte) (int, error) {
	deadline := time.Now().Add(m.timeout)
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return 0, io.EOF
		}
		if m.out.Len() > 0 {
			n, err := m.out.Read(p)
			m.mu.Unlock()
			return n, err
		}
		m.mu.Unlock()
		if time.Now().After(deadline) {
			return 0, nil // simulate read timeout
		}
		time.Sleep(m.readWait)
	}
}

func (m *MockPort) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, errors.New("bruce mock: port closed")
	}
	m.in.Write(p)
	// Dispatch each complete newline-terminated command line.
	for {
		idx := bytes.IndexByte(m.in.Bytes(), '\n')
		if idx < 0 {
			break
		}
		lineBytes := make([]byte, idx)
		copy(lineBytes, m.in.Bytes()[:idx])
		m.in.Next(idx + 1)
		line := strings.TrimSpace(string(lineBytes))
		m.lineQueue = append(m.lineQueue, line)

		body, ok := m.responses[line]
		if !ok {
			// Unscripted: emit empty response so readUntilIdle terminates.
			body = ""
		}
		if body != "" {
			fmt.Fprintf(&m.out, "%s\n", body)
		} else {
			// Still emit a newline so the idle-detection fires.
			m.out.WriteString("\n")
		}
	}
	return len(p), nil
}

func (m *MockPort) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *MockPort) SetReadTimeout(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d > 0 {
		m.timeout = d
	}
	return nil
}
