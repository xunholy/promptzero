package flipper

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/transport"
)

// fakeBLETransport is a minimal transport.Transport reporting Kind "ble". It
// records whether Reconnect/Close were invoked so a test can assert the
// reconnect path does NOT tear down a working BLE link.
type fakeBLETransport struct {
	reconnectCalled atomic.Bool
	closeCalled     atomic.Bool
}

var _ transport.Transport = (*fakeBLETransport)(nil)

func (f *fakeBLETransport) Read(p []byte) (int, error)   { return 0, nil }
func (f *fakeBLETransport) Write(p []byte) (int, error)  { return len(p), nil }
func (f *fakeBLETransport) Close() error                 { f.closeCalled.Store(true); return nil }
func (f *fakeBLETransport) Dial(_ context.Context) error { return nil }
func (f *fakeBLETransport) Reconnect(_ context.Context) error {
	f.reconnectCalled.Store(true)
	return nil
}
func (f *fakeBLETransport) Identity() string                     { return "ble://AA:BB:CC:DD:EE:FF" }
func (f *fakeBLETransport) DrainTimeout() time.Duration          { return 10 * time.Millisecond }
func (f *fakeBLETransport) Kind() string                         { return "ble" }
func (f *fakeBLETransport) SetReadTimeout(_ time.Duration) error { return nil }

// TestReconnect_BLE_RefusesWithoutTearingDownLink guards against the BLE
// reconnect bug: Flipper.Reconnect over BLE would run the serial CLI handshake
// path — first tearing down the working BLE link via transport.Reconnect, then
// bouncing it on every failed handshake retry. It must instead refuse with a
// clear USB-only error and leave the live transport untouched.
func TestReconnect_BLE_RefusesWithoutTearingDownLink(t *testing.T) {
	tr := &fakeBLETransport{}
	f := &Flipper{transport: tr}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := f.Reconnect(ctx)

	if err == nil {
		t.Fatal("expected reconnect over BLE to be refused, got nil")
	}
	if !errors.Is(err, ErrCommandRequiresUSB) {
		t.Errorf("err = %v, want it to wrap ErrCommandRequiresUSB", err)
	}
	if tr.reconnectCalled.Load() {
		t.Fatal("BLE reconnect must NOT call transport.Reconnect — it would tear down the working link")
	}
	if tr.closeCalled.Load() {
		t.Error("BLE reconnect must not close the working transport")
	}
}
