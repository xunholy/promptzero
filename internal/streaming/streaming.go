// Package streaming provides the partial-frame sink used by tools
// that opt into streaming dispatch (roadmap P3-28 first half).
//
// The motivating problem: long-running tools (`subghz_receive`,
// `wifi_wardrive_start`, `subghz_rx_raw`) run for tens of seconds
// or minutes and currently block dispatch until they finish.
// Operators get no live feedback; the agent can't surface
// intermediate findings ("got a handshake — operator may want to
// stop early"); a wedged tool is indistinguishable from one
// making slow progress.
//
// The Sink type is the contract a streaming tool emits frames
// against. Each Frame is one quantum of partial output — a parsed
// scan-line, a periodic progress tick, a structured event. The
// host (agent / MCP server / test harness) attaches a consumer
// that forwards frames to operator-facing channels (CLI status
// line, web UI, SSE stream) without affecting the LLM-facing
// tool_result, which is the tool's final return value.
//
// Design notes:
//
//   - Channel-backed. A bounded buffer drops frames on overflow
//     rather than blocking the tool — operator-facing live feedback
//     is best-effort, not load-bearing.
//   - Frames carry a sequence number so consumers can detect drops.
//   - Close is idempotent. Tools defer Close on the sink; consumers
//     range over Frames() and exit when the channel closes.
//   - Nil-safe sentinel. A nil *Sink's Send is a no-op so streaming
//     handlers can run unconditionally — falling back to a normal
//     non-streaming dispatch is just "pass nil here".
package streaming

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultBufferSize is the channel capacity used by NewSink when
// the caller passes 0. Sized so a chatty parser (one frame per
// scanned AP, ~100 APs in a 30-second window) can run without
// dropping anything against a slow consumer that drains every
// 0.5s.
const DefaultBufferSize = 256

// Frame is one quantum of partial tool output. Tool is the canonical
// tool name; Seq is a 1-based monotonically-increasing per-sink
// counter so consumers can detect drops. Bytes is the payload
// (caller-defined shape — JSON for structured tools, plain text for
// progress lines). Time is the moment the tool emitted the frame
// in UTC.
type Frame struct {
	Tool  string
	Seq   uint64
	Bytes []byte
	Time  time.Time
}

// Sink is the per-call frame channel a streaming tool writes to.
// Construct with NewSink. A nil *Sink is a usable "no-op" sentinel
// — every method short-circuits — so dispatch code can pass nil
// for non-streaming tools without an "if sink != nil" wrapper at
// every emission point.
type Sink struct {
	tool   string
	frames chan Frame
	seq    atomic.Uint64
	closed atomic.Bool
	drops  atomic.Uint64

	aborted   chan struct{}
	abortOnce sync.Once
	closeOnce sync.Once

	// sendMu serialises Send against Close so a concurrent Send that
	// races past the s.closed.Load() check can't try to send on the
	// just-closed frames channel — the panic the docstring's
	// "safe for use from multiple goroutines" promise would otherwise
	// expose. Send is non-blocking inside the lock (select has a
	// default branch) so the lock is held for microseconds.
	sendMu sync.Mutex
}

// NewSink constructs a Sink for the given tool name. buffer ≤0 falls
// back to DefaultBufferSize. The returned Sink is ready for Send
// calls immediately; callers should defer Close.
func NewSink(tool string, buffer int) *Sink {
	if buffer <= 0 {
		buffer = DefaultBufferSize
	}
	return &Sink{
		tool:    tool,
		frames:  make(chan Frame, buffer),
		aborted: make(chan struct{}),
	}
}

// Send pushes a frame onto the sink. Returns false when the sink is
// nil, already closed, or its buffer is full (in which case the
// frame is dropped and the internal Drops counter advances). Send
// never blocks — operator-facing live feedback must NOT slow the
// tool's actual work.
//
// Concurrency: safe for use from multiple goroutines on the same
// sink, but the typical pattern is one producer goroutine per Sink.
// sendMu serialises against Close so a Send racing past the
// s.closed.Load() check cannot panic on a just-closed channel.
func (s *Sink) Send(payload []byte) bool {
	if s == nil {
		return false
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed.Load() {
		return false
	}
	frame := Frame{
		Tool:  s.tool,
		Seq:   s.seq.Add(1),
		Bytes: append([]byte(nil), payload...), // copy so caller can reuse the buffer
		Time:  time.Now().UTC(),
	}
	select {
	case s.frames <- frame:
		return true
	default:
		s.drops.Add(1)
		return false
	}
}

// Close stops accepting new frames and closes the underlying
// channel so consumers `range`-looping over Frames() exit. Idempotent
// — safe to defer.
//
// sendMu is held during the closed-flag store and the channel close
// so a concurrent Send is guaranteed to either complete before the
// close (frame delivered) or observe closed=true after the lock
// hands off (frame rejected). Without this pairing a Send that
// passed s.closed.Load()==false could race the close and panic.
func (s *Sink) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.sendMu.Lock()
		defer s.sendMu.Unlock()
		s.closed.Store(true)
		close(s.frames)
	})
}

// Frames returns the receive-only channel consumers range over.
// Closing happens via Sink.Close. A nil *Sink returns a nil channel
// (a `range` over nil blocks forever — callers should guard with a
// nil-sink check before installing a consumer).
func (s *Sink) Frames() <-chan Frame {
	if s == nil {
		return nil
	}
	return s.frames
}

// Drops reports how many Send calls were rejected because the
// buffer was full. Zero on a healthy stream; non-zero indicates
// the consumer is slower than the producer and the operator may
// want to attach a faster sink.
func (s *Sink) Drops() uint64 {
	if s == nil {
		return 0
	}
	return s.drops.Load()
}

// Sequence returns the highest Seq number sent so far, or 0 when
// nothing has been sent. Test-helper; production consumers should
// read seq numbers off the Frame they receive.
func (s *Sink) Sequence() uint64 {
	if s == nil {
		return 0
	}
	return s.seq.Load()
}

// Abort signals the producer to wrap up early. The channel returned
// by Aborted() is closed; idempotent and nil-safe. A producer
// honouring abort polls Aborted() in its select loop (or relies on
// the per-call context that dispatch cancels in tandem) and returns
// promptly with whatever partial result it can summarise. Send is
// NOT short-circuited — producers may still emit a final summary
// frame between observing Aborted() and calling Close.
func (s *Sink) Abort() {
	if s == nil {
		return
	}
	s.abortOnce.Do(func() {
		close(s.aborted)
	})
}

// Aborted returns a channel that is closed when Abort has been
// called. Producers should select on this alongside ctx.Done() so
// abort fires regardless of whether dispatch cancels the context.
// A nil *Sink returns a nil channel — selecting on a nil channel
// never receives, so non-streaming dispatch (sink=nil) naturally
// has no abort signal.
func (s *Sink) Aborted() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.aborted
}

// IsAborted is a non-blocking convenience for producers that prefer
// a periodic poll over a select. nil-safe; returns false on a nil
// sink.
func (s *Sink) IsAborted() bool {
	if s == nil {
		return false
	}
	select {
	case <-s.aborted:
		return true
	default:
		return false
	}
}

// Handler is the streaming-handler signature: a function that
// pumps frames at a Sink while computing a final string return
// value (the LLM-facing tool_result). Mirrors tools.Handler with
// one extra parameter so opt-in tools don't need to break the
// non-streaming contract.
//
// The handler MUST defer sink.Close() so consumers can exit cleanly
// even on early returns / panics. The host wires the consumer
// (operator-facing live UI, SSE forwarder, audit observer) before
// calling the handler.
type Handler func(ctx context.Context, sink *Sink) (string, error)
