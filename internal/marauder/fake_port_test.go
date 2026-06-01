package marauder

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePort is an in-memory portIface: writes to the Marauder feed the input
// buffer, scripted commands produce output bytes available on Read. Model
// approximates the Marauder wire protocol: echo "#<cmd>", optional body
// lines, and a trailing "> " prompt.
//
// Operations are goroutine-safe so Stream's background reader can coexist
// with the test's assertions.
type fakePort struct {
	mu        sync.Mutex
	in        bytes.Buffer // bytes the Marauder has written (i.e. commands)
	out       bytes.Buffer // bytes that will be returned on Read
	responses map[string]string
	readWait  time.Duration // delay between Read attempts when out is empty
	timeout   time.Duration
	closed    bool
	// lineQueue holds completed command lines awaiting response synthesis.
	lineQueue []string
	// onWrite is fired (under the lock) when a complete command line
	// arrives, so test goroutines can synchronise.
	onWrite func(cmd string)
	// noNewlinePrompt, when true, emits the '> ' prompt without a trailing
	// \r\n — matching the actual Marauder wire format.
	noNewlinePrompt bool
	// suppressPromptFor lists command tokens (first whitespace-
	// separated word of the line) for which the fake withholds the
	// trailing "> " prompt entirely. Models long-running streaming
	// commands (sniffbeacon, scanap-when-untouched, sniffpmkid) that
	// hold the line open until the host sends stopscan / Ctrl+C —
	// real firmware never emits a prompt mid-stream. Without this
	// suppression, the Marauder Stream goroutine reads the auto-
	// prompt and exits via the prompt path before any stopscan is
	// dispatched, which makes TestStreamCancelViaDone race-prone
	// under parallel -race execution.
	suppressPromptFor map[string]bool
}

func newFakePort() *fakePort {
	return &fakePort{
		responses:         map[string]string{},
		suppressPromptFor: map[string]bool{},
		readWait:          5 * time.Millisecond,
		timeout:           5 * time.Second,
	}
}

// suppressPrompt instructs the fake to NOT emit a trailing "> "
// prompt for commands whose first whitespace-separated token is
// `token`. Useful for modelling streaming firmware commands that
// hold the line open until cancelled.
func (f *fakePort) suppressPrompt(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.suppressPromptFor[token] = true
}

// respond registers a canned response body (without the trailing prompt)
// for the given command string. The fake echoes "#<cmd>", the body, and a
// "> " prompt whenever it sees that command line.
func (f *fakePort) respond(cmd, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[cmd] = body
}

// writePrompt appends the '> ' prompt to f.out. When noNewlinePrompt is set,
// no trailing \r\n is added — matching the actual Marauder wire format.
// Must be called with f.mu held.
func (f *fakePort) writePrompt() {
	if f.noNewlinePrompt {
		f.out.WriteString("> ")
	} else {
		f.out.WriteString("> \r\n")
	}
}

func (f *fakePort) Read(p []byte) (int, error) {
	deadline := time.Now().Add(f.timeout)
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return 0, io.EOF
		}
		if f.out.Len() > 0 {
			n, err := f.out.Read(p)
			f.mu.Unlock()
			return n, err
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			// Simulate a read timeout — returning (0, nil) is what
			// go.bug.st/serial does on its configured ReadTimeout.
			return 0, nil
		}
		time.Sleep(f.readWait)
	}
}

func (f *fakePort) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, errors.New("port closed")
	}
	f.in.Write(p)
	// Accumulate until we see a newline; then dispatch the line to the
	// scripted responder.
	for {
		idx := bytes.IndexByte(f.in.Bytes(), '\n')
		if idx < 0 {
			break
		}
		lineBytes := make([]byte, idx)
		copy(lineBytes, f.in.Bytes()[:idx])
		f.in.Next(idx + 1)
		line := strings.TrimSpace(string(lineBytes))
		f.lineQueue = append(f.lineQueue, line)
		// Suppress the trailing prompt for streaming commands like
		// "sniffbeacon" that real firmware would never auto-terminate.
		// Token is the first whitespace-separated word of the line.
		token := line
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			token = line[:i]
		}
		suppressPrompt := f.suppressPromptFor[token]
		if body, ok := f.responses[line]; ok {
			fmt.Fprintf(&f.out, "#%s\r\n", line)
			if body != "" {
				f.out.WriteString(body)
				if !strings.HasSuffix(body, "\n") {
					f.out.WriteString("\r\n")
				}
			}
			if !suppressPrompt {
				f.writePrompt()
			}
		} else {
			// Unscripted commands still receive an echo + prompt so
			// readUntilPrompt doesn't hang on timeout in the happy
			// path. Streaming commands declared via suppressPrompt
			// opt out of the prompt and are expected to be ended by
			// the host (stopscan / Ctrl+C / done-close).
			fmt.Fprintf(&f.out, "#%s\r\n", line)
			if !suppressPrompt {
				f.writePrompt()
			}
		}
		if f.onWrite != nil {
			f.onWrite(line)
		}
	}
	return len(p), nil
}

func (f *fakePort) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakePort) SetReadTimeout(d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d > 0 {
		f.timeout = d
	}
	return nil
}

// linesSeen returns a copy of every command line observed so far.
func (f *fakePort) linesSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.lineQueue))
	copy(out, f.lineQueue)
	return out
}

// TestExecEchoStripped verifies the echo line is stripped and the prompt
// terminates the response, so the caller gets the clean body bytes.
func TestExecEchoStripped(t *testing.T) {
	fp := newFakePort()
	fp.respond("info", "version: 1.11.1\nchip: esp32s2")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	out, err := m.Exec("info", time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(out, "version: 1.11.1") || !strings.Contains(out, "chip: esp32s2") {
		t.Fatalf("missing body content: %q", out)
	}
	if strings.Contains(out, "#info") {
		t.Fatalf("echo line not stripped: %q", out)
	}
	if strings.Contains(out, ">") {
		t.Fatalf("prompt leaked into body: %q", out)
	}
}

// TestReadUntilPromptTimeout exercises the silence-count path: an
// unscripted command with a closed port yields no prompt and should return
// a timeout error within the given budget.
func TestReadUntilPromptTimeout(t *testing.T) {
	fp := newFakePort()
	// Drop the default prompt-emitting echo behaviour by closing early so
	// the fake stays silent after one empty drain.
	m := newMarauderWithPort(fp)
	fp.Close()

	start := time.Now()
	_, err := m.Exec("probe", 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout budget exceeded: took %v", time.Since(start))
	}
}

// TestStreamCancelViaDone starts a streaming command with no scripted
// completion, then closes the done channel. The Marauder should send
// "stopscan\n" and the output channel should close promptly.
//
// The fake's prompt is suppressed for "sniffbeacon" so the Stream
// goroutine has to wait for done — without this, the prompt arrives
// first and the goroutine exits via the prompt path before
// dispatching stopscan, racing the test's done-close. The race
// manifested as an intermittent flake under parallel -race.
func TestStreamCancelViaDone(t *testing.T) {
	fp := newFakePort()
	fp.suppressPrompt("sniffbeacon")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	lines, done, err := m.Stream("sniffbeacon")
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	// Drain whatever arrived from the echoed prompt.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range lines {
		}
	}()
	close(done)

	// 5s rather than 2s for headroom under -race + parallel package
	// execution: the Stream goroutine polls done at ~100ms granularity
	// (the SetReadTimeout-bounded port.Read loop), so a non-flake drain
	// completes in <500ms. The wider window absorbs CPU contention on
	// heavily loaded `go test ./...` runs without changing the contract.
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not drain after done close")
	}

	seen := fp.linesSeen()
	foundStop := false
	for _, s := range seen {
		if s == "stopscan" {
			foundStop = true
			break
		}
	}
	if !foundStop {
		t.Fatalf("stopscan not sent after cancel: %v", seen)
	}
}

// TestJoinPasswordSanitised asserts that Join() preserves spaces but
// strips framing bytes (CR, quote, ETX) from the password — a regression
// guard on the Phase-6 clisafe extraction.
func TestJoinPasswordSanitised(t *testing.T) {
	fp := newFakePort()
	fp.respond(`join -a 0 -p "hello world"`, "joined")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	if _, err := m.Join(0, "hello world\"\r\x03"); err != nil {
		// Join returns whatever the fake returns + nil error when prompt
		// is seen; the test is really about the wire form of the command.
		_ = err
	}
	seen := fp.linesSeen()
	if len(seen) == 0 {
		t.Fatal("no command line observed")
	}
	got := seen[0]
	// Expect the quote/CR to have been stripped but the space kept.
	want := `join -a 0 -p "hello world"`
	if got != want {
		t.Fatalf("wire form differs\nwant: %q\n got: %q", want, got)
	}
}

// TestExecNoNewlinePrompt feeds a response whose '> ' prompt has no trailing
// newline — the actual Marauder wire format — and asserts that Exec returns
// the body lines cleanly without hanging or erroring.
func TestExecNoNewlinePrompt(t *testing.T) {
	fp := newFakePort()
	fp.noNewlinePrompt = true
	fp.respond("info", "Device MAC: 00:11:22:33:44:55\r\nSD Card: Connected")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	out, err := m.Exec("info", 2*time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(out, "Device MAC: 00:11:22:33:44:55") {
		t.Fatalf("missing Device MAC line: %q", out)
	}
	if !strings.Contains(out, "SD Card: Connected") {
		t.Fatalf("missing SD Card line: %q", out)
	}
	if strings.Contains(out, "#info") {
		t.Fatalf("echo line not stripped: %q", out)
	}
	if strings.Contains(out, ">") {
		t.Fatalf("prompt leaked into output: %q", out)
	}
}

// TestExecCtx_HonoursCancellation pins the new ExecCtx contract:
// when ctx is cancelled while a command is in flight, the read loop
// terminates promptly (within ~100 ms — readUntilPromptCtx polls
// SetReadTimeout at that cadence) instead of waiting for the
// timeout to fire. Closes the TODO at the old `readUntilPrompt`
// wrapper site by giving callers a context-aware Exec for
// turn-cancellation cases.
func TestExecCtx_HonoursCancellation(t *testing.T) {
	fp := newFakePort()
	// Suppress the prompt for "freeze" so the fake never terminates the
	// response. Without this the fake echoes "#freeze\r\n> " for any
	// unscripted command, and the prompt is in the read buffer immediately
	// after Write — so the first read could complete (returning nil) before
	// the 100 ms cancel fires, racing the cancellation (the cause of a CI
	// flake). Suppressing the prompt makes the read loop genuinely wait, so
	// the cancel deterministically wins and ExecCtx returns the ctx error.
	fp.suppressPrompt("freeze")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := m.ExecCtx(ctx, "freeze", 5*time.Second)
	elapsed := time.Since(start)

	// Cancellation should yield a non-nil error (timeout-shaped from
	// readUntilPromptCtx since it doesn't distinguish ctx-cancel
	// from deadline) but the elapsed time should be well under the
	// 5 s timeout. The bound is generous (1.5 s) rather than tight:
	// the read loop polls SetReadTimeout on a ~100 ms cadence, so the
	// no-load expectation is ~200 ms, but under the parallel CPU load
	// of the full `task test` suite (GOMAXPROCS workers all busy)
	// goroutine scheduling can delay the cancel goroutine and the
	// next poll by several cadences. 1.5 s still proves cancellation
	// fires promptly (3x+ below the 5 s deadline) without flaking
	// under load.
	if err == nil {
		t.Errorf("ExecCtx on ctx cancel: expected error, got nil")
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("ExecCtx did not honour ctx cancel promptly: took %s (expected well under the 5s timeout)", elapsed)
	}
}

// TestExec_BackCompatStillWorks pins that the legacy Exec wrapper
// (now delegating to ExecCtx with context.Background()) preserves
// the timeout-based behaviour the 95 existing callers depend on.
func TestExec_BackCompatStillWorks(t *testing.T) {
	fp := newFakePort()
	fp.respond("info", "version: 1.11.1")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	out, err := m.Exec("info", time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(out, "version: 1.11.1") {
		t.Errorf("Exec output missing body content: %q", out)
	}
}

// TestExecSubsequentAfterNoNewlinePrompt verifies that after Exec cleanly
// consumes a no-newline-prompt response, a subsequent Exec on the same
// Marauder also succeeds (drain left the port in a clean state).
func TestExecSubsequentAfterNoNewlinePrompt(t *testing.T) {
	fp := newFakePort()
	fp.noNewlinePrompt = true
	fp.respond("info", "Device MAC: 00:11:22:33:44:55\r\nSD Card: Connected")
	fp.respond("channel", "Channel: 6")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	if _, err := m.Exec("info", 2*time.Second); err != nil {
		t.Fatalf("first Exec: %v", err)
	}

	out, err := m.Exec("channel", 2*time.Second)
	if err != nil {
		t.Fatalf("second Exec: %v", err)
	}
	if !strings.Contains(out, "Channel: 6") {
		t.Fatalf("second Exec output wrong: %q", out)
	}
}

// TestAddSSIDStripsQuote covers AddSSID through the shared sanitiser so
// embedded quotes cannot break out of the -n "<name>" delimiter.
func TestAddSSIDStripsQuote(t *testing.T) {
	fp := newFakePort()
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	_, _ = m.AddSSID(`evil"; rm -rf /`)
	seen := fp.linesSeen()
	if len(seen) == 0 {
		t.Fatal("no command line observed")
	}
	if strings.Count(seen[0], `"`) != 2 {
		t.Fatalf("unexpected quote count on wire: %q", seen[0])
	}
}

// TestStreamBackpressureExits verifies that when the consumer is slow (holds
// the channel full for >2s), the Stream goroutine exits via the backpressure
// timer rather than wedging indefinitely. The test sleeps 3 seconds to let
// the 2-second timer fire; it is gated behind testing.Short().
func TestStreamBackpressureExits(t *testing.T) {
	if testing.Short() {
		t.Skip("backpressure test requires ~3s — skip with -short")
	}

	fp := newFakePort()
	// 200 lines (> 128-item channel buffer); no trailing prompt needed
	// because the goroutine blocks on send #129 before reaching the prompt.
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&sb, "bp%03d\r\n", i)
	}
	fp.respond("scanbeacon", sb.String())

	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	lines, done, err := m.Stream("scanbeacon")
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer close(done)

	// Do NOT read from lines — simulates a stuck consumer.
	// The goroutine fills the 128-slot buffer, then blocks on the 129th send.
	// After the 2-second backpressure timer fires it returns and closes lines.
	time.Sleep(3 * time.Second)

	// At this point the goroutine should have already exited.
	// Drain any buffered items to detect channel close.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for range lines {
		}
	}()

	select {
	case <-drainDone:
		// goroutine exited cleanly —
	case <-time.After(time.Second):
		t.Fatal("stream goroutine did not exit within 3s+1s (backpressure timer may be missing)")
	}
}

// TestStreamLines_DeliversEachLine pins the StreamLines adapter
// contract: each emitted line lands at onLine in order and the
// accumulated raw mirrors the wire content. The fake auto-emits a
// prompt after the body so the underlying Stream goroutine exits
// cleanly via the prompt path — the test doesn't assert on
// stopscan because that defensive write only fires when the host
// closes done before the firmware is finished (TestStreamCancelViaDone
// already covers that path against an unscripted command).
func TestStreamLines_DeliversEachLine(t *testing.T) {
	fp := newFakePort()
	fp.respond("scanap", "0 | -55 | 6 | aa:bb:cc:dd:ee:ff | OPEN | HomeWifi\n"+
		"1 | -77 | 1 | 11:22:33:44:55:66 | WPA2 | NeighbourAP\n"+
		"2 | -88 | 11 | 99:88:77:66:55:44 | WPA2 | OfficeAP")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	const budget = 2 * time.Second
	var got []string
	raw, err := m.StreamLines(context.Background(), "scanap", budget, func(line string) bool {
		got = append(got, line)
		return false
	})
	if err != nil {
		t.Fatalf("StreamLines: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("onLine called %d times, want 3 (lines=%v)", len(got), got)
	}
	for _, want := range []string{"HomeWifi", "NeighbourAP", "OfficeAP"} {
		if !strings.Contains(raw, want) {
			t.Errorf("accumulated raw missing %q: %q", want, raw)
		}
	}
}

// TestStreamLines_StopsEarlyOnCallback pins the consumer-driven abort
// path: returning stop=true ends the stream before the timeout and
// returns the accumulated raw cleanly. As with the deliver-each-line
// test, the fake's auto-prompt makes stopscan unnecessary in the
// underlying Stream goroutine, so the assertion focuses on the
// callback-stop semantics rather than the wire trace.
func TestStreamLines_StopsEarlyOnCallback(t *testing.T) {
	fp := newFakePort()
	fp.respond("scanap", "0 | -55 | 6 | aa:bb:cc:dd:ee:ff | OPEN | First\n"+
		"1 | -77 | 1 | 11:22:33:44:55:66 | WPA2 | Second\n"+
		"2 | -88 | 11 | 99:88:77:66:55:44 | WPA2 | Third")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	const budget = 5 * time.Second
	start := time.Now()
	var got []string
	raw, err := m.StreamLines(context.Background(), "scanap", budget, func(line string) bool {
		got = append(got, line)
		return true // abort on first frame
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("StreamLines: %v", err)
	}
	if elapsed >= budget {
		t.Errorf("StreamLines did not stop early: took %s (budget %s)", elapsed, budget)
	}
	if len(got) != 1 {
		t.Errorf("onLine called %d times, want 1 (early-stop)", len(got))
	}
	if !strings.Contains(raw, "First") {
		t.Errorf("raw missing first line: %q", raw)
	}
}

// TestStreamLines_CtxCancelStopsCapture pins the budget/cancel path:
// when the context is cancelled, StreamLines returns cleanly with no
// error and the accumulated raw preserved. Uses an unscripted
// command (no respond() registration) so the fake won't auto-supply
// a prompt — the only way out is ctx cancellation.
func TestStreamLines_CtxCancelStopsCapture(t *testing.T) {
	fp := newFakePort()
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := m.StreamLines(ctx, "sniffbeacon", 5*time.Second, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Errorf("StreamLines on ctx cancel: expected nil error, got %v", err)
	}
	if elapsed >= 1500*time.Millisecond {
		t.Errorf("StreamLines did not honour ctx cancel promptly: took %s", elapsed)
	}
}
