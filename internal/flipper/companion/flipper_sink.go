package companion

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FlipperIO is the subset of *flipper.Flipper the sink actually
// uses. Defining it here (rather than importing the full Flipper
// type) keeps the companion package free of cycles and lets tests
// substitute an in-memory fake.
type FlipperIO interface {
	WriteFile(path string, data []byte) error
	StorageRead(path string) (string, error)
	StorageRemove(path string) (string, error)
}

// DefaultTruncateEvery is how many writes happen before the sink
// removes the status file before the next write. Momentum's
// `storage write_chunk` appends rather than truncates (see the
// FAP-side seek-to-tail handling), so the file grows unbounded
// without periodic resets. The FAP tolerates large files via
// seek-to-tail; this just keeps SD usage and read time bounded.
const DefaultTruncateEvery = 50

// FileWriter is the legacy single-method form retained as an alias
// for callers that only need writes (rare; prefer FlipperIO).
type FileWriter interface {
	WriteFile(path string, data []byte) error
}

// responsePollInterval is how often the sink reads the FAP's
// response file while polling is enabled. Chosen so a typical
// operator button-press lands within ~1 round-trip; faster than
// 250 ms saturates the USB CDC link with no UX gain.
const responsePollInterval = 250 * time.Millisecond

// FlipperSink writes events to a status file on the Flipper SD
// card and (when polling is enabled) reads operator decisions
// back from a separate response file. The FAP is the renderer for
// status and the producer of responses; we are blind to whether
// the operator is actually looking at the screen.
//
// Writes are coalesced through a single background goroutine: each
// caller-facing Sink method updates an in-memory "latest" slot and
// signals a wake-up. The worker drains the slot at most once per
// wake-up, so a flurry of events (start → finish → start in tens of
// milliseconds) collapses into one or two USB transactions instead
// of three.
//
// Response polling is opt-in (see PollResponses) so the USB link
// stays quiet between confirm prompts. The poll loop dedups by
// file content — a stable response.json never re-pushes — and
// silently skips read errors so a missing file isn't an event.
type FlipperSink struct {
	io           FlipperIO
	statusPath   string
	responsePath string
	log          *slog.Logger

	mu     sync.Mutex
	latest *Event
	wake   chan struct{}
	quit   chan struct{}
	done   chan struct{}
	errCnt atomic.Uint64

	respCh   chan Response
	pollOn   atomic.Bool
	lastResp atomic.Pointer[string]
	respDone chan struct{}

	// TruncateEvery is the cadence (in writes) at which flush()
	// removes the status file before the next write. Defaults to
	// DefaultTruncateEvery. Set to 0 to disable truncation
	// entirely. Read once at construction; mutate before any
	// writes happen.
	TruncateEvery int
	writeCount    atomic.Uint64
}

// NewFlipperSink wires a sink to the given Flipper. statusPath
// defaults to DefaultStatusPath when empty; responsePath defaults
// to DefaultResponsePath. Logger may be nil; a no-op logger is
// substituted.
//
// Two background goroutines start immediately: the write coalescer
// (always active) and the response poller (gated by PollResponses).
// Call Close before the process exits so the final status lands on
// the device.
func NewFlipperSink(io FlipperIO, statusPath string, log *slog.Logger) *FlipperSink {
	if statusPath == "" {
		statusPath = DefaultStatusPath
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	s := &FlipperSink{
		io:            io,
		statusPath:    statusPath,
		responsePath:  DefaultResponsePath,
		log:           log,
		TruncateEvery: DefaultTruncateEvery,
		wake:          make(chan struct{}, 1),
		quit:          make(chan struct{}),
		done:          make(chan struct{}),
		respCh:        make(chan Response, 4),
		respDone:      make(chan struct{}),
	}
	go s.runWriter()
	go s.runResponsePoller()
	return s
}

// SetResponsePath overrides the SD path the response poller reads.
// Callers usually leave this at the default; exposed for tests.
func (s *FlipperSink) SetResponsePath(p string) {
	if p != "" {
		s.responsePath = p
	}
}

// Idle pushes an idle event. Coalesced with any pending update.
func (s *FlipperSink) Idle() {
	s.push(newEvent(EventIdle))
}

// Busy pushes a busy event with the supplied label/detail/risk.
func (s *FlipperSink) Busy(label, detail, riskLevel string) {
	e := newEvent(EventBusy)
	e.Label = label
	e.Detail = detail
	e.Risk = riskLevel
	s.push(e)
}

// Done pushes a done event. ok=false marks the tool as errored so
// the FAP renders a cross instead of a check.
func (s *FlipperSink) Done(label string, ok bool) {
	e := newEvent(EventDone)
	e.Label = label
	e.OK = &ok
	s.push(e)
}

// Confirm pushes a confirm event. id is the per-request token the
// FAP will echo in its response so the wiring layer can match the
// answer to this prompt and ignore stale ones.
func (s *FlipperSink) Confirm(id, label, riskLevel string) {
	e := newEvent(EventConfirm)
	e.ID = id
	e.Label = label
	e.Risk = riskLevel
	s.push(e)
}

// Responses returns the channel the response poller pushes
// operator decisions into. The channel is alive for the sink's
// lifetime; consumers must filter by ID and discard responses with
// no matching outstanding request.
func (s *FlipperSink) Responses() <-chan Response { return s.respCh }

// PollResponses enables (true) or disables (false) the response
// read loop. Idempotent — calling enable twice in a row is the
// same as calling once. Safe under contention.
func (s *FlipperSink) PollResponses(enable bool) {
	s.pollOn.Store(enable)
}

// Close stops both background workers and waits for them to
// drain. Safe to call multiple times; subsequent calls return nil.
func (s *FlipperSink) Close() error {
	select {
	case <-s.quit:
		return nil
	default:
	}
	close(s.quit)
	<-s.done
	<-s.respDone
	return nil
}

func (s *FlipperSink) push(e Event) {
	s.mu.Lock()
	cp := e
	s.latest = &cp
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
		// already pending; the worker will pick up the latest
		// value on its next cycle.
	}
}

func (s *FlipperSink) runWriter() {
	defer close(s.done)
	for {
		select {
		case <-s.quit:
			s.flush()
			return
		case <-s.wake:
			s.flush()
		}
	}
}

func (s *FlipperSink) flush() {
	s.mu.Lock()
	ev := s.latest
	s.latest = nil
	s.mu.Unlock()
	if ev == nil {
		return
	}
	data, err := EncodeEvent(*ev)
	if err != nil {
		s.logErr("encode event", err)
		return
	}
	// Periodic truncation: every TruncateEvery-th write, remove the
	// status file first so Momentum's append-mode write_chunk can't
	// grow it unbounded. The FAP's seek-to-tail handles any size,
	// but bounded files keep SD wear and poll latency predictable.
	n := s.writeCount.Add(1)
	if s.TruncateEvery > 0 && n%uint64(s.TruncateEvery) == 0 {
		if _, rmErr := s.io.StorageRemove(s.statusPath); rmErr != nil {
			s.logErr("truncate status", rmErr)
			// Carry on — write below will recreate or append; the
			// FAP tolerates either.
		}
	}
	if err := s.io.WriteFile(s.statusPath, data); err != nil {
		s.logErr("write status", err)
	}
}

// runResponsePoller is the response-read worker. Sleeps cheaply
// when polling is disabled; reads + dedups when enabled. Pushes
// fresh responses onto respCh non-blockingly so a stalled consumer
// never wedges the poller — the FAP can re-press if the channel
// was full.
func (s *FlipperSink) runResponsePoller() {
	defer close(s.respDone)
	t := time.NewTicker(responsePollInterval)
	defer t.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-t.C:
			if !s.pollOn.Load() {
				continue
			}
			s.tryReadResponse()
		}
	}
}

func (s *FlipperSink) tryReadResponse() {
	raw, err := s.io.StorageRead(s.responsePath)
	if err != nil {
		// Most common case: file doesn't exist yet because the
		// operator hasn't pressed anything. Don't log per-poll;
		// rate-limit at the same factor as write errors.
		s.logErr("read response", err)
		return
	}
	body := strings.TrimSpace(raw)
	if body == "" {
		return
	}
	if prev := s.lastResp.Load(); prev != nil && *prev == body {
		return // unchanged since last poll → already delivered
	}
	resp, ok := parseResponse(body)
	if !ok {
		// Stash the raw body anyway so we don't try to parse the
		// same garbage every tick.
		s.lastResp.Store(&body)
		return
	}
	s.lastResp.Store(&body)
	select {
	case s.respCh <- resp:
	default:
		// Consumer is slow or absent — drop. The FAP can re-press
		// or the wiring layer will time out and fall back to the
		// terminal answer.
		s.log.WarnContext(context.Background(),
			"companion response channel full; dropping", "id", resp.ID)
	}
}

// parseResponse extracts a Response from a raw file body. Tolerant
// of leading whitespace, trailing newlines, and any prefix the
// Flipper CLI's `storage read` may prepend before the JSON object.
func parseResponse(body string) (Response, bool) {
	idx := strings.Index(body, "{")
	if idx < 0 {
		return Response{}, false
	}
	end := strings.LastIndex(body, "}")
	if end < idx {
		return Response{}, false
	}
	var r Response
	if err := json.Unmarshal([]byte(body[idx:end+1]), &r); err != nil {
		return Response{}, false
	}
	if r.ID == "" {
		return Response{}, false
	}
	return r, true
}

// logErr rate-limits noisy error chains (e.g. Flipper unplugged
// mid-session) by only logging on the first failure of every
// power-of-two-th retry.
func (s *FlipperSink) logErr(op string, err error) {
	n := s.errCnt.Add(1)
	if n == 1 || n&(n-1) == 0 {
		s.log.WarnContext(context.Background(),
			"companion sink "+op+" failed",
			"error", err, "occurrences", n)
	}
}

// discardWriter is the io.Writer the no-op slog handler writes to
// when the caller passes a nil logger.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
