// Mirrors the build constraint on ble.go so the test references to
// bleTransport / bleDrainTimeout / etc. only compile when the real BLE
// implementation is included. On darwin without CGO the stub in
// ble_darwin.go is the only file built and these symbols don't exist.

//go:build !darwin || (darwin && cgo)

package transport

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests exercise the parts of the BLE transport that don't
// require real hardware: URL parsing, Identity/Kind/DrainTimeout
// surface, the onNotify→Read buffer bridge, read-timeout semantics,
// and Close idempotency. The full scan/connect/MTU/reconnect path is
// covered by the contract test in contract_test.go (gated on
// FLIPPER_BLE_MAC) because it requires a paired peripheral and BlueZ.

func TestBLEDialerURLParsing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		url    string
		wantID string
		errSub string
	}{
		{
			name:   "lowercase MAC is normalised to uppercase in Identity",
			url:    "ble://aa:bb:cc:dd:ee:ff",
			wantID: "ble://AA:BB:CC:DD:EE:FF",
		},
		{
			name:   "uppercase MAC round-trips unchanged",
			url:    "ble://AA:BB:CC:DD:EE:FF",
			wantID: "ble://AA:BB:CC:DD:EE:FF",
		},
		{
			name:   "mixed-case MAC is normalised to uppercase",
			url:    "ble://Aa:Bb:Cc:Dd:Ee:Ff",
			wantID: "ble://AA:BB:CC:DD:EE:FF",
		},
		{
			name:   "uppercase UUID is normalised to lowercase",
			url:    "ble://E127EFC1-05EC-CE53-014E-B79FEE9117FA",
			wantID: "ble://e127efc1-05ec-ce53-014e-b79fee9117fa",
		},
		{
			name:   "lowercase UUID round-trips unchanged",
			url:    "ble://e127efc1-05ec-ce53-014e-b79fee9117fa",
			wantID: "ble://e127efc1-05ec-ce53-014e-b79fee9117fa",
		},
		{
			name:   "device name is preserved verbatim",
			url:    "ble://Unholy",
			wantID: "ble://Unholy",
		},
		{
			name:   "empty path is rejected",
			url:    "ble://",
			errSub: "empty path",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tx, err := Open(tc.url)
			if tc.errSub != "" {
				if err == nil {
					t.Fatalf("Open(%q) err = nil, want error containing %q", tc.url, tc.errSub)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("Open(%q) err = %q, want substring %q", tc.url, err.Error(), tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open(%q): %v", tc.url, err)
			}
			if got := tx.Identity(); got != tc.wantID {
				t.Errorf("Identity() = %q, want %q", got, tc.wantID)
			}
			if got := tx.Kind(); got != "ble" {
				t.Errorf("Kind() = %q, want ble", got)
			}
			if got := tx.DrainTimeout(); got != bleDrainTimeout {
				t.Errorf("DrainTimeout() = %v, want %v", got, bleDrainTimeout)
			}
		})
	}
}

func TestBLEIdentityHasNoNewlines(t *testing.T) {
	t.Parallel()
	tx, err := Open("ble://AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if strings.ContainsAny(tx.Identity(), "\r\n") {
		t.Errorf("Identity() contains newline: %q", tx.Identity())
	}
}

// TestBLENotifyToReadBridge drives onNotify directly (no hardware
// required) and verifies the buffered bytes come out of Read. This is
// the unit-level equivalent of the contract test's "peer.Write →
// tx.Read" round-trip: for BLE the "peer write" is a notification
// packet delivered via the RX characteristic callback, and the code
// under test is the bytes.Buffer + sync.Cond bridge.
func TestBLENotifyToReadBridge(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)

	// Deliver two notifications before any Read. The buffered bytes
	// should stream out of a single large Read in order.
	tx.onNotify([]byte("hello "))
	tx.onNotify([]byte("flipper"))

	buf := make([]byte, 64)
	n, err := tx.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	got := string(buf[:n])
	if got != "hello flipper" && got != "hello " {
		// bytes.Buffer.Read may return either the first chunk or the
		// entire buffered content depending on internal state; accept
		// either but require the prefix.
		t.Fatalf("Read = %q, want prefix %q", got, "hello ")
	}
}

// TestBLEReadBlocksUntilNotify verifies the cond-wait path: Read with
// no buffered data and a non-zero timeout must block, then unblock as
// soon as onNotify delivers bytes.
func TestBLEReadBlocksUntilNotify(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)
	if err := tx.SetReadTimeout(500 * time.Millisecond); err != nil {
		t.Fatalf("SetReadTimeout: %v", err)
	}

	done := make(chan struct {
		n   int
		err error
		buf []byte
	}, 1)
	go func() {
		b := make([]byte, 16)
		n, err := tx.Read(b)
		done <- struct {
			n   int
			err error
			buf []byte
		}{n, err, b}
	}()

	// Give the reader a moment to park in readCond.Wait.
	time.Sleep(50 * time.Millisecond)
	tx.onNotify([]byte("late"))

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

// TestBLEReadReturnsZeroOnTimeout checks the poll-friendly timeout
// path: with a non-zero read timeout and no bytes arriving, Read must
// return (0, nil) — the same shape serial.Port.Read uses so the drain
// loop can tick ctx.
func TestBLEReadReturnsZeroOnTimeout(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)
	if err := tx.SetReadTimeout(50 * time.Millisecond); err != nil {
		t.Fatalf("SetReadTimeout: %v", err)
	}

	buf := make([]byte, 8)
	start := time.Now()
	n, err := tx.Read(buf)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 0 {
		t.Fatalf("Read returned n=%d, want 0 on timeout", n)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("Read returned after only %v, want ~50ms", elapsed)
	}
}

// TestBLECloseUnblocksRead verifies the Close→readCond.Broadcast path
// wakes a Read parked without a timeout and that it returns
// os.ErrClosed.
func TestBLECloseUnblocksRead(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)

	done := make(chan error, 1)
	go func() {
		b := make([]byte, 8)
		_, err := tx.Read(b)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := tx.Close(); err != nil {
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

func TestBLECloseIsIdempotent(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)
	if err := tx.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestBLEReadEmptyBufIsNoop is a micro-contract: Read on a zero-length
// slice must return (0, nil) without consulting the buffer. Otherwise
// the flipper command layer's defensive pre-checks could deadlock
// behind a cond.Wait that never gets signalled.
func TestBLEReadEmptyBufIsNoop(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)
	n, err := tx.Read(nil)
	if err != nil {
		t.Fatalf("Read(nil) err = %v, want nil", err)
	}
	if n != 0 {
		t.Fatalf("Read(nil) n = %d, want 0", n)
	}
}

// TestBLEWriteBeforeDial exercises the "never dialled" guard. A live
// Write without a prior Dial must fail cleanly rather than
// dereferencing a nil device handle.
func TestBLEWriteBeforeDial(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)
	_, err := tx.Write([]byte("x"))
	if err == nil {
		t.Fatalf("Write before Dial returned nil error; want an error")
	}
	if !strings.Contains(err.Error(), "before Dial") {
		t.Errorf("Write before Dial err = %q, want substring %q", err.Error(), "before Dial")
	}
}

func TestBLEWriteEmptyIsNoop(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)
	n, err := tx.Write(nil)
	if err != nil {
		t.Fatalf("Write(nil): %v", err)
	}
	if n != 0 {
		t.Fatalf("Write(nil) n = %d, want 0", n)
	}
}

func TestBLEWriteAfterCloseFails(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)
	if err := tx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := tx.Write([]byte("x"))
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("Write after Close err = %v, want os.ErrClosed", err)
	}
}

// TestBLESetReadTimeoutAfterCloseFails locks in the "no operations
// after Close" invariant for SetReadTimeout specifically, since the
// serial transport surfaces the same error and the flipper layer
// relies on the symmetry.
func TestBLESetReadTimeoutAfterCloseFails(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)
	if err := tx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := tx.SetReadTimeout(100 * time.Millisecond); !errors.Is(err, os.ErrClosed) {
		t.Errorf("SetReadTimeout after Close err = %v, want os.ErrClosed", err)
	}
}

// TestBLEKindAndDrainTimeoutConstants pins the telemetry tag and
// drain interval so a well-meaning refactor doesn't silently break
// downstream metrics dashboards or the post-command drain loop.
func TestBLEKindAndDrainTimeoutConstants(t *testing.T) {
	t.Parallel()
	tx := newBLEForTest(t)
	if tx.Kind() != "ble" {
		t.Errorf("Kind = %q, want ble", tx.Kind())
	}
	if tx.DrainTimeout() != 250*time.Millisecond {
		t.Errorf("DrainTimeout = %v, want 250ms", tx.DrainTimeout())
	}
}

// newBLEForTest returns an un-dialled *bleTransport suitable for
// unit-testing the buffer/cond/timeout logic. Bypasses Open to get a
// typed value so tests can call onNotify directly.
func newBLEForTest(t *testing.T) *bleTransport {
	t.Helper()
	tx := &bleTransport{
		addr:     "AA:BB:CC:DD:EE:FF",
		addrKind: addrKindMAC,
		mtu:      bleDefaultMTU - attHeaderOverhead,
	}
	tx.readCond = sync.NewCond(&tx.mu)
	return tx
}

// TestParseBLEAddressClassification pins the shape-based classifier so
// future churn in the parser doesn't silently re-route a MAC into the
// name path (or vice versa) — both are valid forms but they take
// different runtime paths (scan-match-on-Address vs scan-match-on-
// LocalName, plus the darwin direct-connect fast path on UUID).
func TestParseBLEAddressClassification(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input    string
		wantKind addrKind
		wantOut  string
	}{
		{"80:E1:26:69:6E:55", addrKindMAC, "80:E1:26:69:6E:55"},
		{"80-e1-26-69-6e-55", addrKindMAC, "80:E1:26:69:6E:55"},
		{"e127efc1-05ec-ce53-014e-b79fee9117fa", addrKindUUID, "e127efc1-05ec-ce53-014e-b79fee9117fa"},
		{"E127EFC1-05EC-CE53-014E-B79FEE9117FA", addrKindUUID, "e127efc1-05ec-ce53-014e-b79fee9117fa"},
		{"Unholy", addrKindName, "Unholy"},
		{"  spaced  ", addrKindName, "spaced"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			gotKind, gotOut, err := parseBLEAddress(tc.input)
			if err != nil {
				t.Fatalf("parseBLEAddress(%q): %v", tc.input, err)
			}
			if gotKind != tc.wantKind {
				t.Errorf("kind = %v, want %v", gotKind, tc.wantKind)
			}
			if gotOut != tc.wantOut {
				t.Errorf("normalised = %q, want %q", gotOut, tc.wantOut)
			}
		})
	}

	if _, _, err := parseBLEAddress(""); err == nil {
		t.Error("parseBLEAddress(\"\") expected error, got nil")
	}
	if _, _, err := parseBLEAddress("   "); err == nil {
		t.Error("parseBLEAddress(whitespace-only) expected error, got nil")
	}
}

// Compile-time assertion that the unit-test helper returns the
// interface the rest of the package consumes. Keeps newBLEForTest
// honest if the interface grows a new method.
var _ io.ReadWriteCloser = (*bleTransport)(nil)
