package marauder

import (
	"bytes"
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
}

func newFakePort() *fakePort {
	return &fakePort{
		responses: map[string]string{},
		readWait:  5 * time.Millisecond,
		timeout:   5 * time.Second,
	}
}

// respond registers a canned response body (without the trailing prompt)
// for the given command string. The fake echoes "#<cmd>", the body, and a
// "> " prompt whenever it sees that command line.
func (f *fakePort) respond(cmd, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[cmd] = body
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
		if body, ok := f.responses[line]; ok {
			fmt.Fprintf(&f.out, "#%s\r\n", line)
			if body != "" {
				f.out.WriteString(body)
				if !strings.HasSuffix(body, "\n") {
					f.out.WriteString("\r\n")
				}
			}
			f.out.WriteString("> \r\n")
		} else {
			// Unscripted commands still receive an echo + prompt so
			// readUntilPrompt doesn't hang on timeout in the happy path.
			fmt.Fprintf(&f.out, "#%s\r\n> \r\n", line)
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

// setBlocking disables the Read timeout so the port returns only when real
// data is available; used to prove the Stream cancelation path.
func (f *fakePort) setBlocking() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.timeout = time.Hour
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
func TestStreamCancelViaDone(t *testing.T) {
	fp := newFakePort()
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

	select {
	case <-drained:
	case <-time.After(2 * time.Second):
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
