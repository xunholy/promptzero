package rpc

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
	"google.golang.org/protobuf/encoding/protowire"
	proto "google.golang.org/protobuf/proto"
)

// chanTransport is a mock transport backed by two channels.
// One channel carries bytes from client→server; the other server→client.
// It is safe for concurrent use across goroutines.
type chanTransport struct {
	// rx is what this end reads (filled by the other side's Write).
	rx chan []byte
	// tx is what the other side reads (filled by this end's Write).
	tx chan []byte

	readBuf []byte // partial carry-over from previous Read
	mu      sync.Mutex
	closed  bool
}

func newChanTransportPair() (*chanTransport, *chanTransport) {
	ab := make(chan []byte, 256)
	ba := make(chan []byte, 256)
	client := &chanTransport{rx: ba, tx: ab}
	server := &chanTransport{rx: ab, tx: ba}
	return client, server
}

func (t *chanTransport) Read(p []byte) (int, error) {
	for {
		t.mu.Lock()
		if len(t.readBuf) > 0 {
			n := copy(p, t.readBuf)
			t.readBuf = t.readBuf[n:]
			t.mu.Unlock()
			return n, nil
		}
		closed := t.closed
		t.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		select {
		case chunk, ok := <-t.rx:
			if !ok {
				return 0, io.EOF
			}
			t.mu.Lock()
			t.readBuf = append(t.readBuf, chunk...)
			t.mu.Unlock()
		case <-time.After(time.Millisecond):
			// yield — let the caller loop
			return 0, nil
		}
	}
}

func (t *chanTransport) Write(p []byte) (int, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	chunk := make([]byte, len(p))
	copy(chunk, p)
	t.tx <- chunk
	return len(p), nil
}

func (t *chanTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

func (t *chanTransport) Dial(_ context.Context) error         { return nil }
func (t *chanTransport) Reconnect(_ context.Context) error    { return nil }
func (t *chanTransport) Identity() string                     { return "test-chan" }
func (t *chanTransport) DrainTimeout() time.Duration          { return 0 }
func (t *chanTransport) Kind() string                         { return "test" }
func (t *chanTransport) SetReadTimeout(_ time.Duration) error { return nil }

// writeFramedTo marshals m and writes framed bytes into the server's Write.
func writeFramedTo(srv *chanTransport, m *pb.Main) {
	body, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	prefix := protowire.AppendVarint(nil, uint64(len(body)))
	srv.tx <- prefix
	srv.tx <- body
}

// drainClientWrite reads bytes the client wrote (from the server's rx).
// Returns nil on timeout.
func drainClientWrite(srv *chanTransport, timeout time.Duration) []byte {
	deadline := time.Now().Add(timeout)
	var out []byte
	for time.Now().Before(deadline) {
		select {
		case chunk := <-srv.rx:
			out = append(out, chunk...)
		default:
			if len(out) > 0 {
				return out
			}
			time.Sleep(time.Millisecond)
		}
	}
	return out
}

// openClient performs the Open handshake: it runs Open in a goroutine,
// waits for the start_rpc_session bytes plus the framed PingRequest,
// then echoes a matching PingResponse so Open returns. Subsequent test
// code can issue further commands without re-handling the handshake.
func openClient(t *testing.T, c *Client, srv *chanTransport) {
	t.Helper()
	ctx := context.Background()
	openErr := make(chan error, 1)
	go func() { openErr <- c.Open(ctx) }()

	var collected []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		more := drainClientWrite(srv, 200*time.Millisecond)
		collected = append(collected, more...)
		// Look for a complete framed message after the CLI handshake.
		cliEnd := bytes.IndexByte(collected, '\r') + 1
		if cliEnd == 0 {
			continue
		}
		framed := collected[cliEnd:]
		msgLen, n := protowire.ConsumeVarint(framed)
		if n <= 0 || len(framed) < n+int(msgLen) {
			continue
		}
		var req pb.Main
		if err := proto.Unmarshal(framed[n:n+int(msgLen)], &req); err != nil {
			t.Fatalf("openClient: unmarshal PingRequest: %v", err)
		}
		writeFramedTo(srv, &pb.Main{
			CommandId: req.CommandId,
			Content:   &pb.Main_SystemPingResponse{SystemPingResponse: &pb.PingResponse{}},
		})
		break
	}

	select {
	case err := <-openErr:
		if err != nil {
			t.Fatalf("openClient: Open: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("openClient: Open timed out")
	}
}

// drainAll collects everything in srv.rx until the channel is empty.
func drainAll(srv *chanTransport) []byte {
	var out []byte
	for {
		select {
		case chunk := <-srv.rx:
			out = append(out, chunk...)
		default:
			return out
		}
	}
}

func TestClientOpen(t *testing.T) {
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)

	ctx := context.Background()
	openErr := make(chan error, 1)
	go func() { openErr <- c.Open(ctx) }()

	// First write is the CLI handshake. After that the client drains for
	// ~300ms then issues a framed PingRequest; collect both into one buffer.
	data := drainClientWrite(srv, 2*time.Second)
	if !strings.HasPrefix(string(data), "start_rpc_session\r") {
		t.Errorf("Open wrote %q, want prefix %q", data, "start_rpc_session\r")
	}

	// Find the framed Ping after the CLI handshake bytes.
	cliEnd := bytes.IndexByte(data, '\r') + 1
	pingBytes := data[cliEnd:]
	for len(pingBytes) == 0 {
		more := drainClientWrite(srv, 2*time.Second)
		if len(more) == 0 {
			t.Fatal("timeout waiting for Ping after start_rpc_session")
		}
		pingBytes = append(pingBytes, more...)
	}
	msgLen, n := protowire.ConsumeVarint(pingBytes)
	if n <= 0 {
		t.Fatalf("bad varint in PingRequest bytes")
	}
	var req pb.Main
	if err := proto.Unmarshal(pingBytes[n:n+int(msgLen)], &req); err != nil {
		t.Fatalf("unmarshal PingRequest: %v", err)
	}
	writeFramedTo(srv, &pb.Main{
		CommandId: req.CommandId,
		Content:   &pb.Main_SystemPingResponse{SystemPingResponse: &pb.PingResponse{}},
	})

	if err := <-openErr; err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := c.Open(ctx); err != ErrAlreadyOpen {
		t.Errorf("second Open: got %v, want ErrAlreadyOpen", err)
	}

	_ = c.Close()
}

func TestClientPing(t *testing.T) {
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)
	ctx := context.Background()

	openClient(t, c, srv) // consume start_rpc_session

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Ping(ctx)
	}()

	// Collect the PingRequest bytes.
	raw := drainClientWrite(srv, 2*time.Second)
	if len(raw) == 0 {
		t.Fatal("timeout waiting for PingRequest from client")
	}

	// Decode to extract command_id.
	msgLen, n := protowire.ConsumeVarint(raw)
	if n <= 0 {
		t.Fatalf("bad varint in PingRequest bytes")
	}
	var req pb.Main
	if err := proto.Unmarshal(raw[n:n+int(msgLen)], &req); err != nil {
		t.Fatalf("unmarshal PingRequest: %v", err)
	}

	// Feed matching PingResponse into client's read pipe.
	writeFramedTo(srv, &pb.Main{
		CommandId: req.CommandId,
		Content: &pb.Main_SystemPingResponse{
			SystemPingResponse: &pb.PingResponse{},
		},
	})

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Ping returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Ping timed out")
	}

	_ = c.Close()
}

func TestClientStartScreenStream(t *testing.T) {
	const frameCount = 3

	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	openClient(t, c, srv)

	ch, err := c.StartScreenStream(ctx)
	if err != nil {
		t.Fatalf("StartScreenStream: %v", err)
	}
	drainAll(srv) // consume StartScreenStreamRequest bytes

	// Feed frames.
	go func() {
		pixels := make([]byte, 1024)
		for i := 0; i < frameCount; i++ {
			pixels[i] = byte(i + 1)
			writeFramedTo(srv, &pb.Main{
				Content: &pb.Main_GuiScreenFrame{
					GuiScreenFrame: &pb.ScreenFrame{
						Data:        append([]byte(nil), pixels...),
						Orientation: pb.ScreenOrientation_HORIZONTAL,
					},
				},
			})
			time.Sleep(5 * time.Millisecond)
		}
	}()

	received := 0
	for frame := range ch {
		if frame.Width != 128 || frame.Height != 64 {
			t.Errorf("frame %d: unexpected dimensions %dx%d", received, frame.Width, frame.Height)
		}
		received++
		if received == frameCount {
			cancel()
		}
	}

	if received < frameCount {
		t.Errorf("received %d frames, want %d", received, frameCount)
	}
}

func TestClientClosedSession(t *testing.T) {
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)

	if err := c.Ping(context.Background()); err != ErrSessionClosed {
		t.Errorf("Ping before Open: got %v, want ErrSessionClosed", err)
	}
	if _, err := c.StartScreenStream(context.Background()); err != ErrSessionClosed {
		t.Errorf("StartScreenStream before Open: got %v, want ErrSessionClosed", err)
	}

	openClient(t, c, srv)
	_ = c.Close()

	if err := c.Ping(context.Background()); err != ErrSessionClosed {
		t.Errorf("Ping after Close: got %v, want ErrSessionClosed", err)
	}
}

func TestClientLongStreamFrames(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long stream test in short mode")
	}

	const frameCount = 100
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	openClient(t, c, srv)

	ch, err := c.StartScreenStream(ctx)
	if err != nil {
		t.Fatalf("StartScreenStream: %v", err)
	}
	drainAll(srv)

	go func() {
		pixels := make([]byte, 1024)
		for i := 0; i < frameCount; i++ {
			pixels[i%1024] = byte(i)
			writeFramedTo(srv, &pb.Main{
				Content: &pb.Main_GuiScreenFrame{
					GuiScreenFrame: &pb.ScreenFrame{
						Data: append([]byte(nil), pixels...),
					},
				},
			})
		}
	}()

	var received int
	for range ch {
		received++
		if received == frameCount {
			cancel()
		}
	}

	if received < frameCount {
		t.Errorf("received %d frames, want %d", received, frameCount)
	}
}

// Compile-time assertion: chanTransport satisfies io.ReadWriteCloser.
var _ io.ReadWriteCloser = (*chanTransport)(nil)
