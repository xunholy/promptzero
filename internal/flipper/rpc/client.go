package rpc

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
	"github.com/xunholy/promptzero/internal/flipper/transport"
)

// Client is a typed RPC client over a Flipper transport. The transport must
// already be dialled; Client takes exclusive ownership of it for the session.
//
// Call sequence: NewClient → Open → (Ping / StartScreenStream) → Close.
// A Client is not safe for concurrent use across Open/Close; Ping and
// StartScreenStream may not be called concurrently with each other.
type Client struct {
	tx     transport.Transport
	open   atomic.Bool
	mu     sync.Mutex
	nextID atomic.Uint32
}

// NewClient wraps tx. The transport must be dialled and in CLI mode.
// Open sends the start_rpc_session handshake.
func NewClient(tx transport.Transport) *Client {
	return &Client{tx: tx}
}

// Open transitions the Flipper from CLI mode to RPC mode by writing
// "start_rpc_session\r\n" to the transport. After this call, the byte
// stream is framed protobuf and the transport must not be used for CLI.
//
// The firmware echoes the command back as CLI bytes before switching to
// RPC mode; Open drains those bytes and verifies the transition with a
// Ping so callers see a clean error instead of a misparsed first frame.
func (c *Client) Open(ctx context.Context) error {
	if c.open.Swap(true) {
		return ErrAlreadyOpen
	}
	if _, err := c.tx.Write([]byte("start_rpc_session\r")); err != nil {
		c.open.Store(false)
		return fmt.Errorf("rpc: open: %w", err)
	}
	c.drainCLIEcho()

	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := c.Ping(pingCtx); err != nil {
		c.open.Store(false)
		return fmt.Errorf("rpc: handshake ping failed: %w", err)
	}
	return nil
}

// drainCLIEcho consumes bytes for ~300 ms after the start_rpc_session write
// so the firmware's CLI echo of the command doesn't poison the first
// protobuf read. The drain uses a short transport read deadline so we exit
// promptly when the wire goes silent.
func (c *Client) drainCLIEcho() {
	_ = c.tx.SetReadTimeout(50 * time.Millisecond)
	defer func() { _ = c.tx.SetReadTimeout(500 * time.Millisecond) }()

	deadline := time.Now().Add(300 * time.Millisecond)
	buf := make([]byte, 256)
	for time.Now().Before(deadline) {
		n, err := c.tx.Read(buf)
		if err != nil || n == 0 {
			return
		}
	}
}

// Close ends the RPC session by sending a StopSession message followed by
// a Ctrl+C byte so the firmware returns to CLI mode.
func (c *Client) Close() error {
	if !c.open.Swap(false) {
		return nil // already closed
	}
	id := c.commandID()
	_ = writeFramed(c.tx, &pb.Main{
		CommandId: id,
		Content:   &pb.Main_StopSession{StopSession: &pb.StopSession{}},
	})
	// Ctrl+C breaks out of RPC mode on the firmware side if StopSession
	// was not acknowledged in time.
	_, _ = c.tx.Write([]byte("\x03"))
	return nil
}

// Ping sends a PingRequest and waits for the matching PingResponse.
func (c *Client) Ping(ctx context.Context) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_SystemPingRequest{
			SystemPingRequest: &pb.PingRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return err
		}
		if m.CommandId == id {
			if _, ok := m.Content.(*pb.Main_SystemPingResponse); ok {
				return nil
			}
			return fmt.Errorf("rpc: ping: unexpected response type %T", m.Content)
		}
	}
}

// StartScreenStream sends a StartScreenStreamRequest and returns a channel on
// which ScreenFrame values are delivered as they arrive. The goroutine driving
// the channel exits when ctx is cancelled or the transport returns a disconnect
// error, at which point the channel is closed.
//
// Call StopScreenStream to cleanly terminate the stream.
func (c *Client) StartScreenStream(ctx context.Context) (<-chan ScreenFrame, error) {
	if !c.open.Load() {
		return nil, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_GuiStartScreenStreamRequest{
			GuiStartScreenStreamRequest: &pb.StartScreenStreamRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return nil, err
	}

	ch := make(chan ScreenFrame)
	go c.readScreenFrames(ctx, ch)
	return ch, nil
}

// readScreenFrames is the goroutine that reads framed messages and delivers
// ScreenFrame values. Non-ScreenFrame messages (such as the initial ack) are
// dropped. The channel is closed when ctx is done or a transport error occurs.
func (c *Client) readScreenFrames(ctx context.Context, ch chan ScreenFrame) {
	defer close(ch)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		m, err := readFramed(c.tx)
		if err != nil {
			// io.EOF or disconnect — close cleanly.
			return
		}
		sf, ok := m.Content.(*pb.Main_GuiScreenFrame)
		if !ok {
			continue
		}
		frame := decodeFrame(sf.GuiScreenFrame)
		select {
		case ch <- frame:
		case <-ctx.Done():
			return
		}
	}
}

// StopScreenStream sends a StopScreenStreamRequest. The channel returned by
// StartScreenStream will be closed once the firmware acknowledges.
func (c *Client) StopScreenStream(ctx context.Context) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_GuiStopScreenStreamRequest{
			GuiStopScreenStreamRequest: &pb.StopScreenStreamRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeFramed(c.tx, req)
}

func (c *Client) commandID() uint32 {
	return c.nextID.Add(1)
}

// ensure Client satisfies io.Closer.
var _ io.Closer = (*Client)(nil)
