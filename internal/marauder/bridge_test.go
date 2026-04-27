package marauder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/transport"
)

// fakeBridgeFlipper is a test double for the unexported bridgeFlipper
// interface that ConnectViaFlipper depends on. It records every call so
// tests can assert exactly what the function did with the handle.
type fakeBridgeFlipper struct {
	execCmds      []string
	execResp      string
	execErr       error
	suspendCalls  int
	suspendReason string
	suspendErr    error
	isSuspended   bool
	transport     transport.Transport
}

func (f *fakeBridgeFlipper) ExecCtx(_ context.Context, cmd string) (string, error) {
	f.execCmds = append(f.execCmds, cmd)
	return f.execResp, f.execErr
}

func (f *fakeBridgeFlipper) Suspend(reason string) error {
	f.suspendCalls++
	f.suspendReason = reason
	return f.suspendErr
}

func (f *fakeBridgeFlipper) IsSuspended() bool              { return f.isSuspended }
func (f *fakeBridgeFlipper) Transport() transport.Transport { return f.transport }

// stubTransport is a minimal transport.Transport whose only purpose is to
// return a configured Kind() — the only field ConnectViaFlipper consults.
type stubTransport struct {
	kind string
}

func (s *stubTransport) Read(_ []byte) (int, error)           { return 0, io.EOF }
func (s *stubTransport) Write(p []byte) (int, error)          { return len(p), nil }
func (s *stubTransport) Close() error                         { return nil }
func (s *stubTransport) Dial(_ context.Context) error         { return nil }
func (s *stubTransport) Reconnect(_ context.Context) error    { return nil }
func (s *stubTransport) Identity() string                     { return "stub://" + s.kind }
func (s *stubTransport) DrainTimeout() time.Duration          { return 100 * time.Millisecond }
func (s *stubTransport) Kind() string                         { return s.kind }
func (s *stubTransport) SetReadTimeout(_ time.Duration) error { return nil }

// withConnectFn temporarily replaces the package-level connectFn used by
// ConnectViaFlipper to reopen the port as a Marauder. Restored on Cleanup.
func withConnectFn(t *testing.T, fn func(string, int) (*Marauder, error)) {
	t.Helper()
	orig := connectFn
	connectFn = fn
	t.Cleanup(func() { connectFn = orig })
}

// makeFakeMarauder returns a Marauder backed by a fakePort so tests can
// produce a non-nil *Marauder without opening a real device.
func makeFakeMarauder() *Marauder {
	return newMarauderWithPort(newFakePort())
}

// fastSettle / fastReopen keep the test budget low while still exercising
// the post-launch sleep and the reopen retry loop.
const (
	fastSettle = 5 * time.Millisecond
	fastReopen = 100 * time.Millisecond
	tinyReopen = 50 * time.Millisecond
	scriptedOK = "\n> "
)

func TestConnectViaFlipper_HappyPath(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execResp:  scriptedOK,
		transport: &stubTransport{kind: "serial"},
	}
	withConnectFn(t, func(_ string, _ int) (*Marauder, error) { return makeFakeMarauder(), nil })

	m, err := ConnectViaFlipper(context.Background(), flip, "/dev/ttyACM0", 115200, "", fastSettle, fastReopen)
	if err != nil {
		t.Fatalf("ConnectViaFlipper: %v", err)
	}
	if m == nil {
		t.Fatal("got nil Marauder")
	}
	if flip.suspendCalls != 1 {
		t.Errorf("Suspend calls = %d, want 1", flip.suspendCalls)
	}
	if flip.suspendReason != "UART bridge active" {
		t.Errorf("Suspend reason = %q, want %q", flip.suspendReason, "UART bridge active")
	}
}

func TestConnectViaFlipper_DefaultsBridgeCommand(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execResp:  scriptedOK,
		transport: &stubTransport{kind: "serial"},
	}
	withConnectFn(t, func(_ string, _ int) (*Marauder, error) { return makeFakeMarauder(), nil })

	if _, err := ConnectViaFlipper(context.Background(), flip, "/dev/x", 115200, "", fastSettle, fastReopen); err != nil {
		t.Fatal(err)
	}
	if len(flip.execCmds) != 1 || flip.execCmds[0] != DefaultBridgeCommand {
		t.Fatalf("execCmds = %v, want exactly [%q]", flip.execCmds, DefaultBridgeCommand)
	}
}

func TestConnectViaFlipper_PassesCustomCommand(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execResp:  scriptedOK,
		transport: &stubTransport{kind: "serial"},
	}
	withConnectFn(t, func(_ string, _ int) (*Marauder, error) { return makeFakeMarauder(), nil })

	custom := `loader open "Custom Bridge"`
	if _, err := ConnectViaFlipper(context.Background(), flip, "/dev/x", 115200, custom, fastSettle, fastReopen); err != nil {
		t.Fatal(err)
	}
	if flip.execCmds[0] != custom {
		t.Fatalf("execCmds[0] = %q, want %q", flip.execCmds[0], custom)
	}
}

func TestConnectViaFlipper_RejectedByFirmware(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execResp:  "App not found\n> ",
		transport: &stubTransport{kind: "serial"},
	}

	_, err := ConnectViaFlipper(context.Background(), flip, "/dev/x", 115200, "", fastSettle, fastReopen)
	if !errors.Is(err, ErrBridgeRejected) {
		t.Fatalf("err = %v, want ErrBridgeRejected", err)
	}
	if !strings.Contains(err.Error(), "App not found") {
		t.Errorf("err missing firmware text: %v", err)
	}
	if flip.suspendCalls != 0 {
		t.Errorf("Suspend called %d times after rejection (must remain 0)", flip.suspendCalls)
	}
}

func TestConnectViaFlipper_RejectionMatrix(t *testing.T) {
	cases := []struct {
		name string
		out  string
	}{
		{"app_not_found", "App not found\n> "},
		{"app_is_not_installed", "app is not installed\n> "},
		{"could_not_find_command", "could not find command 'loader'\n> "},
		{"unknown_command", "Unknown command\n> "},
		{"loader_error", "loader: error: foo\n> "},
		{"invalid_app", "Invalid app\n> "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flip := &fakeBridgeFlipper{
				execResp:  c.out,
				transport: &stubTransport{kind: "serial"},
			}
			_, err := ConnectViaFlipper(context.Background(), flip, "/dev/x", 115200, "", fastSettle, fastReopen)
			if !errors.Is(err, ErrBridgeRejected) {
				t.Fatalf("err = %v, want ErrBridgeRejected", err)
			}
			if flip.suspendCalls != 0 {
				t.Errorf("Suspend called for rejection variant %q", c.name)
			}
		})
	}
}

func TestConnectViaFlipper_ExecError(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execErr:   fmt.Errorf("io error"),
		transport: &stubTransport{kind: "serial"},
	}
	_, err := ConnectViaFlipper(context.Background(), flip, "/dev/x", 115200, "", fastSettle, fastReopen)
	if err == nil {
		t.Fatal("expected error from ExecCtx failure")
	}
	if !strings.Contains(err.Error(), "launching bridge app") {
		t.Errorf("err missing 'launching bridge app' prefix: %v", err)
	}
	if flip.suspendCalls != 0 {
		t.Errorf("Suspend called after ExecCtx error (must remain 0)")
	}
}

func TestConnectViaFlipper_ReopenRetries(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execResp:  scriptedOK,
		transport: &stubTransport{kind: "serial"},
	}
	target := makeFakeMarauder()
	attempts := 0
	withConnectFn(t, func(_ string, _ int) (*Marauder, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("not yet")
		}
		return target, nil
	})

	m, err := ConnectViaFlipper(context.Background(), flip, "/dev/x", 115200, "", fastSettle, 5*time.Second)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if m != target {
		t.Errorf("returned %p, want %p", m, target)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestConnectViaFlipper_ReopenTimeout(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execResp:  scriptedOK,
		transport: &stubTransport{kind: "serial"},
	}
	withConnectFn(t, func(_ string, _ int) (*Marauder, error) {
		return nil, errors.New("port not ready")
	})

	_, err := ConnectViaFlipper(context.Background(), flip, "/dev/ttyACM0", 115200, "", fastSettle, tinyReopen)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "port not ready") {
		t.Errorf("err missing wrapped lastErr: %v", err)
	}
	if !strings.Contains(err.Error(), "/dev/ttyACM0") {
		t.Errorf("err missing port path: %v", err)
	}
}

func TestConnectViaFlipper_ContextCancelDuringSettle(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execResp:  scriptedOK,
		transport: &stubTransport{kind: "serial"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Cancel after launch + Suspend have run but before settle
		// finishes — i.e. during step 3 of ConnectViaFlipper.
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()

	_, err := ConnectViaFlipper(ctx, flip, "/dev/x", 115200, "", 200*time.Millisecond, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// In single-cable mode Suspend runs before settle, so cancellation
	// here means the Flipper is left in the suspended state — that is
	// the documented behaviour (irreversible without replug).
	if flip.suspendCalls != 1 {
		t.Errorf("Suspend calls during settle-cancel = %d, want 1 (irreversible)", flip.suspendCalls)
	}
}

func TestConnectViaFlipper_NilFlipper(t *testing.T) {
	_, err := ConnectViaFlipper(context.Background(), nil, "/dev/x", 115200, "", 0, 0)
	if err == nil {
		t.Fatal("expected error for nil flip")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("err message: %v", err)
	}
}

func TestConnectViaFlipper_AlreadySuspended(t *testing.T) {
	flip := &fakeBridgeFlipper{
		isSuspended: true,
		transport:   &stubTransport{kind: "serial"},
	}
	_, err := ConnectViaFlipper(context.Background(), flip, "/dev/x", 115200, "", 0, 0)
	if err == nil {
		t.Fatal("expected error when already suspended")
	}
	if !strings.Contains(err.Error(), "already suspended") {
		t.Errorf("err message: %v", err)
	}
	if flip.suspendCalls != 0 {
		t.Errorf("Suspend re-called on already-suspended flip (calls=%d)", flip.suspendCalls)
	}
}

// --- Hybrid mode (BLE-Flipper + USB-bridged-Marauder) ---

func TestConnectViaFlipper_Hybrid_DoesNotSuspend(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execResp:  scriptedOK,
		transport: &stubTransport{kind: "ble"},
	}
	withConnectFn(t, func(_ string, _ int) (*Marauder, error) { return makeFakeMarauder(), nil })

	m, err := ConnectViaFlipper(context.Background(), flip, "/dev/ttyACM0", 115200, "", fastSettle, fastReopen)
	if err != nil {
		t.Fatalf("hybrid ConnectViaFlipper: %v", err)
	}
	if m == nil {
		t.Fatal("nil Marauder in hybrid mode")
	}
	if flip.suspendCalls != 0 {
		t.Errorf("Suspend called %d times in hybrid mode (must remain 0)", flip.suspendCalls)
	}
}

func TestConnectViaFlipper_Hybrid_RejectsUnsupportedTransport(t *testing.T) {
	cases := []string{"http", "mock", "https"}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			flip := &fakeBridgeFlipper{
				transport: &stubTransport{kind: kind},
			}
			_, err := ConnectViaFlipper(context.Background(), flip, "/dev/x", 115200, "", 0, 0)
			if err == nil {
				t.Fatal("expected error for unsupported transport")
			}
			if !strings.Contains(err.Error(), kind) {
				t.Errorf("err missing transport kind %q: %v", kind, err)
			}
			if !strings.Contains(err.Error(), "not supported") {
				t.Errorf("err missing 'not supported': %v", err)
			}
			if flip.suspendCalls != 0 {
				t.Errorf("Suspend called for unsupported transport %q", kind)
			}
		})
	}
}

func TestConnectViaFlipper_SingleCable_StillSuspends(t *testing.T) {
	flip := &fakeBridgeFlipper{
		execResp:  scriptedOK,
		transport: &stubTransport{kind: "serial"},
	}
	withConnectFn(t, func(_ string, _ int) (*Marauder, error) { return makeFakeMarauder(), nil })

	if _, err := ConnectViaFlipper(context.Background(), flip, "/dev/x", 115200, "", fastSettle, fastReopen); err != nil {
		t.Fatal(err)
	}
	if flip.suspendCalls != 1 {
		t.Fatalf("single-cable Suspend calls = %d, want 1", flip.suspendCalls)
	}
}

// --- classifier sanity ---

func TestClassifyBridgeRejection_CleanResponseNotRejected(t *testing.T) {
	// A clean prompt response with no rejection markers must classify as
	// "no rejection". Regression guard against over-eager substring matches.
	for _, ok := range []string{"\n> ", "> ", "loaded\n> ", "Bridge ready\n> "} {
		if got := classifyBridgeRejection(ok); got != "" {
			t.Errorf("classifyBridgeRejection(%q) = %q, want \"\"", ok, got)
		}
	}
}
