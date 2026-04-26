package faultier

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

// Mock is an in-memory Port implementation that speaks the Faultier serial
// bridge wire protocol.  Tests instantiate a Mock, create a Client via
// NewMockClient, and inspect Mock.State to verify round-trip behaviour without
// any hardware.
//
// The Mock executes the same decode + response logic that real firmware would,
// so unit tests exercise both the Client's encoder and the protocol's response
// decoder.
type Mock struct {
	mu sync.Mutex

	// Input buffer: bytes the Client has written.
	in bytes.Buffer
	// Output buffer: bytes the Client will read back.
	out bytes.Buffer

	closed  bool
	timeout time.Duration

	// State is the simulated device state, exposed for test assertions.
	State MockState

	// InjectError, when non-zero, causes the next command to return a
	// RespError frame with this error code.
	InjectError byte
}

// MockState holds the simulated device state managed by the Mock.
type MockState struct {
	Armed       bool
	Config      GlitcherConfig
	LastOutcome byte
}

// NewMock returns a fresh Mock in its default (reset) state.
func NewMock() *Mock {
	return &Mock{
		timeout: 5 * time.Second,
	}
}

// NewMockClient returns a Client backed by a new Mock.  Both are returned so
// tests can inspect Mock.State and inject errors.
func NewMockClient() (*Client, *Mock) {
	m := NewMock()
	return newWithPort(m), m
}

// Read implements Port.  Blocks until data is available or the timeout fires.
func (m *Mock) Read(p []byte) (int, error) {
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
			return 0, nil // simulate read-timeout (same as go.bug.st/serial)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Write implements Port.  Each complete frame received is decoded and a
// response frame is appended to the output buffer.
func (m *Mock) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, fmt.Errorf("mock port closed")
	}
	m.in.Write(p)
	m.processFrames()
	return len(p), nil
}

// Close implements Port.
func (m *Mock) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// SetReadTimeout implements Port.
func (m *Mock) SetReadTimeout(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d > 0 {
		m.timeout = d
	}
	return nil
}

// processFrames drains complete frames from m.in and generates responses.
// Must be called with m.mu held.
func (m *Mock) processFrames() {
	for {
		b := m.in.Bytes()
		if len(b) < FrameHeaderLen+FrameChecksumLen {
			return
		}
		if b[0] != FrameMagic0 || b[1] != FrameMagic1 {
			// Out-of-sync — discard one byte and retry.
			m.in.Next(1)
			continue
		}
		opcode := b[2]
		payLen := int(binary.LittleEndian.Uint16(b[3:5]))
		totalLen := FrameHeaderLen + payLen + FrameChecksumLen
		if len(b) < totalLen {
			return // wait for more bytes
		}
		payload := make([]byte, payLen)
		copy(payload, b[5:5+payLen])
		gotCS := b[FrameHeaderLen+payLen]
		m.in.Next(totalLen)

		wantCS := frameChecksum(opcode, payload)
		if gotCS != wantCS {
			m.writeErrorResp(ErrInvalidParam)
			continue
		}

		if m.InjectError != 0 {
			m.writeErrorResp(m.InjectError)
			m.InjectError = 0
			continue
		}

		m.dispatch(opcode, payload)
	}
}

// dispatch executes a decoded command and writes the appropriate response.
// Must be called with m.mu held.
func (m *Mock) dispatch(opcode byte, payload []byte) {
	switch opcode {
	case OpConfigure:
		cfg, err := decodeConfigPayload(payload)
		if err != nil {
			m.writeErrorResp(ErrInvalidParam)
			return
		}
		m.State.Config = cfg
		m.writeOKResp()

	case OpArm:
		m.State.Armed = true
		m.writeOKResp()

	case OpFire:
		m.State.LastOutcome = OutcomeGlitch
		m.State.Armed = false
		m.writeOKResp()

	case OpDisarm:
		m.State.Armed = false
		if m.State.LastOutcome == OutcomeNone {
			m.State.LastOutcome = OutcomeSkip
		}
		m.writeOKResp()

	case OpStatus:
		m.writeStatusResp()

	default:
		m.writeErrorResp(ErrInvalidParam)
	}
}

// writeOKResp appends a RespOK frame to the output buffer.
// Must be called with m.mu held.
func (m *Mock) writeOKResp() {
	m.out.WriteByte(FrameMagic0)
	m.out.WriteByte(FrameMagic1)
	m.out.WriteByte(RespOK)
}

// writeErrorResp appends a RespError frame with the given error code.
// Must be called with m.mu held.
func (m *Mock) writeErrorResp(code byte) {
	m.out.WriteByte(FrameMagic0)
	m.out.WriteByte(FrameMagic1)
	m.out.WriteByte(RespError)
	m.out.WriteByte(code)
}

// writeStatusResp appends a RespStatus frame reflecting m.State.
// Must be called with m.mu held.
func (m *Mock) writeStatusResp() {
	m.out.WriteByte(FrameMagic0)
	m.out.WriteByte(FrameMagic1)
	m.out.WriteByte(RespStatus)

	block := make([]byte, StatusBlockLen)
	if m.State.Armed {
		block[0] = 0x01
	}
	binary.LittleEndian.PutUint32(block[1:5], m.State.Config.DelayUS)
	block[5] = m.State.LastOutcome
	block[6] = 0x00 // reserved
	m.out.Write(block)
}
