// Mirrors the build constraint on transport_ble.go so the test references to
// marauderBLEPort / bleDefaultMTU / etc. only compile when the real BLE
// implementation is included. On darwin without CGO the stub in
// transport_ble_darwin.go is the only file built and these symbols don't
// exist.

//go:build !darwin || (darwin && cgo)

package marauder

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests exercise the parts of the Marauder BLE transport that don't
// require real hardware: URL parsing, the address shape classifier, the
// onNotify→Read buffer bridge, read-timeout semantics, Close idempotency,
// and the "write before dial" guard. The full scan/connect/MTU path is
// covered by hardware-only contract tests gated on an env var (deferred —
// not required by spec).

func TestMarauderBLEURLParsing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantOut string
		errSub  string
	}{
		{
			name:    "lowercase MAC normalised to uppercase",
			input:   "ble://aa:bb:cc:dd:ee:ff",
			wantOut: "AA:BB:CC:DD:EE:FF",
		},
		{
			name:    "uppercase MAC round-trips unchanged",
			input:   "ble://AA:BB:CC:DD:EE:FF",
			wantOut: "AA:BB:CC:DD:EE:FF",
		},
		{
			name:    "uppercase UUID normalised to lowercase",
			input:   "ble://E127EFC1-05EC-CE53-014E-B79FEE9117FA",
			wantOut: "e127efc1-05ec-ce53-014e-b79fee9117fa",
		},
		{
			name:    "device name preserved verbatim",
			input:   "ble://Marauder",
			wantOut: "Marauder",
		},
		{
			name:    "bare MAC without scheme is accepted",
			input:   "AA:BB:CC:DD:EE:FF",
			wantOut: "AA:BB:CC:DD:EE:FF",
		},
		{
			name:    "bare UUID without scheme is accepted",
			input:   "e127efc1-05ec-ce53-014e-b79fee9117fa",
			wantOut: "e127efc1-05ec-ce53-014e-b79fee9117fa",
		},
		{
			name:   "empty path is rejected",
			input:  "ble://",
			errSub: "empty",
		},
		{
			name:   "empty bare input is rejected",
			input:  "",
			errSub: "empty",
		},
		{
			name:   "wrong scheme is rejected",
			input:  "serial://AA:BB:CC:DD:EE:FF",
			errSub: "expected ble:// scheme",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := newMarauderBLEPort(tc.input)
			if tc.errSub != "" {
				if err == nil {
					t.Fatalf("newMarauderBLEPort(%q) err = nil, want error containing %q", tc.input, tc.errSub)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("newMarauderBLEPort(%q) err = %q, want substring %q", tc.input, err.Error(), tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("newMarauderBLEPort(%q): %v", tc.input, err)
			}
			if p.addr != tc.wantOut {
				t.Errorf("addr = %q, want %q", p.addr, tc.wantOut)
			}
		})
	}
}

// TestMarauderBLEAddrClassification pins the shape-based classifier so future
// churn doesn't silently re-route a MAC into the name path (or vice versa) —
// both are valid forms but they take different runtime paths (scan-match-on-
// Address vs scan-match-on-LocalName, plus the darwin direct-connect fast
// path on UUID).
func TestMarauderBLEAddrClassification(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input    string
		wantKind bleAddrKind
		wantOut  string
	}{
		{"80:E1:26:69:6E:55", bleAddrKindMAC, "80:E1:26:69:6E:55"},
		{"80-e1-26-69-6e-55", bleAddrKindMAC, "80:E1:26:69:6E:55"},
		{"e127efc1-05ec-ce53-014e-b79fee9117fa", bleAddrKindUUID, "e127efc1-05ec-ce53-014e-b79fee9117fa"},
		{"E127EFC1-05EC-CE53-014E-B79FEE9117FA", bleAddrKindUUID, "e127efc1-05ec-ce53-014e-b79fee9117fa"},
		{"Marauder", bleAddrKindName, "Marauder"},
		{"  spaced  ", bleAddrKindName, "spaced"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			gotKind, gotOut, err := parseMarauderBLEAddress(tc.input)
			if err != nil {
				t.Fatalf("parseMarauderBLEAddress(%q): %v", tc.input, err)
			}
			if gotKind != tc.wantKind {
				t.Errorf("kind = %v, want %v", gotKind, tc.wantKind)
			}
			if gotOut != tc.wantOut {
				t.Errorf("normalised = %q, want %q", gotOut, tc.wantOut)
			}
		})
	}

	if _, _, err := parseMarauderBLEAddress(""); err == nil {
		t.Error("parseMarauderBLEAddress(\"\") expected error, got nil")
	}
}

// TestMarauderBLENotifyToReadBridge drives onNotify directly (no hardware
// required) and verifies the buffered bytes come out of Read. This is the
// unit-level equivalent of a peer.Write → tx.Read round-trip: the "peer
// write" is a notification packet delivered via the RX characteristic
// callback, and the code under test is the bytes.Buffer + sync.Cond bridge.
func TestMarauderBLENotifyToReadBridge(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)

	// Deliver two notifications before any Read. The buffered bytes should
	// stream out of a single large Read in order.
	p.onNotify([]byte("hello "))
	p.onNotify([]byte("marauder"))

	buf := make([]byte, 64)
	n, err := p.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	got := string(buf[:n])
	// bytes.Buffer.Read may return either the first chunk or the entire
	// buffered content depending on internal state; accept either but
	// require the prefix.
	if got != "hello marauder" && got != "hello " {
		t.Fatalf("Read = %q, want prefix %q", got, "hello ")
	}
}

// TestMarauderBLEReadBlocksUntilNotify verifies the cond-wait path: Read with
// no buffered data and a non-zero timeout must block, then unblock as soon
// as onNotify delivers bytes.
func TestMarauderBLEReadBlocksUntilNotify(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)
	if err := p.SetReadTimeout(500 * time.Millisecond); err != nil {
		t.Fatalf("SetReadTimeout: %v", err)
	}

	type result struct {
		n   int
		err error
		buf []byte
	}
	done := make(chan result, 1)
	go func() {
		b := make([]byte, 16)
		n, err := p.Read(b)
		done <- result{n, err, b}
	}()

	// Give the reader a moment to park in readCond.Wait.
	time.Sleep(50 * time.Millisecond)
	p.onNotify([]byte("late"))

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Read: %v", r.err)
		}
		if string(r.buf[:r.n]) != "late" {
			t.Fatalf("Read = %q, want %q", string(r.buf[:r.n]), "late")
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Read did not unblock after onNotify within 1s")
	}
}

// TestMarauderBLEReadReturnsZeroOnTimeout checks the poll-friendly timeout
// path: with a non-zero read timeout and no bytes arriving, Read must
// return (0, nil) — the same shape serial.Port.Read uses so the existing
// readUntilPrompt drain loop still ticks ctx.
func TestMarauderBLEReadReturnsZeroOnTimeout(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)
	if err := p.SetReadTimeout(50 * time.Millisecond); err != nil {
		t.Fatalf("SetReadTimeout: %v", err)
	}

	buf := make([]byte, 8)
	start := time.Now()
	n, err := p.Read(buf)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 0 {
		t.Fatalf("Read returned n=%d, want 0 on timeout", n)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("Read returned after only %v, want >=~50ms", elapsed)
	}
}

// TestMarauderBLECloseUnblocksRead verifies the Close → readCond.Broadcast
// path wakes a Read parked without a timeout and returns os.ErrClosed.
func TestMarauderBLECloseUnblocksRead(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)

	done := make(chan error, 1)
	go func() {
		b := make([]byte, 8)
		_, err := p.Read(b)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read after Close err = %v, want os.ErrClosed", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Read did not unblock within 1s of Close")
	}
}

func TestMarauderBLECloseIsIdempotent(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)
	if err := p.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestMarauderBLEReadEmptyBufIsNoop is a micro-contract: Read on a zero-length
// slice must return (0, nil) without consulting the buffer. Otherwise any
// defensive pre-checks in the existing Marauder readUntilPrompt loop could
// deadlock behind a cond.Wait that never gets signalled.
func TestMarauderBLEReadEmptyBufIsNoop(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)
	n, err := p.Read(nil)
	if err != nil {
		t.Fatalf("Read(nil) err = %v, want nil", err)
	}
	if n != 0 {
		t.Fatalf("Read(nil) n = %d, want 0", n)
	}
}

// TestMarauderBLEWriteBeforeDial exercises the "never dialled" guard. A live
// Write without a prior dial must fail cleanly rather than dereferencing a
// nil device handle.
func TestMarauderBLEWriteBeforeDial(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)
	_, err := p.Write([]byte("scanap"))
	if err == nil {
		t.Fatalf("Write before Dial returned nil error; want an error")
	}
	if !strings.Contains(err.Error(), "before Dial") {
		t.Errorf("Write before Dial err = %q, want substring %q", err.Error(), "before Dial")
	}
}

func TestMarauderBLEWriteEmptyIsNoop(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)
	n, err := p.Write(nil)
	if err != nil {
		t.Fatalf("Write(nil): %v", err)
	}
	if n != 0 {
		t.Fatalf("Write(nil) n = %d, want 0", n)
	}
}

func TestMarauderBLEWriteAfterCloseFails(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := p.Write([]byte("scanap"))
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("Write after Close err = %v, want os.ErrClosed", err)
	}
}

// TestMarauderBLESetReadTimeoutAfterCloseFails locks in the "no operations
// after Close" invariant for SetReadTimeout — the existing Marauder client
// drain/readUntilPrompt code calls SetReadTimeout from many places and a
// silently-accepted post-close call would mask shutdown bugs.
func TestMarauderBLESetReadTimeoutAfterCloseFails(t *testing.T) {
	t.Parallel()
	p := newMarauderBLEForTest(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.SetReadTimeout(100 * time.Millisecond); !errors.Is(err, os.ErrClosed) {
		t.Errorf("SetReadTimeout after Close err = %v, want os.ErrClosed", err)
	}
}

// TestMarauderBLEPortSatisfiesPortInterface is a compile-time assertion that
// the BLE port can be plugged straight into NewWithPort. Keeps the unexported
// Port interface honest if it grows a new method.
func TestMarauderBLEPortSatisfiesPortInterface(t *testing.T) {
	t.Parallel()
	var _ Port = (*marauderBLEPort)(nil)
	var _ io.ReadWriteCloser = (*marauderBLEPort)(nil)
}

// newMarauderBLEForTest returns an un-dialled *marauderBLEPort suitable for
// unit-testing the buffer/cond/timeout logic. Bypasses ConnectBLE so tests
// can call onNotify directly without a real adapter.
func newMarauderBLEForTest(t *testing.T) *marauderBLEPort {
	t.Helper()
	p := &marauderBLEPort{
		addr:     "AA:BB:CC:DD:EE:FF",
		addrKind: bleAddrKindMAC,
		mtu:      bleDefaultMTU - attHeaderOverhead,
	}
	p.readCond = sync.NewCond(&p.mu)
	return p
}
