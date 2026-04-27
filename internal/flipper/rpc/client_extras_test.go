package rpc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
)

// TestClientReboot verifies Reboot writes a SystemRebootRequest with the
// supplied mode and returns nil without blocking on a response — the
// firmware does not emit one for reboots, so the call must complete on
// the write alone. We assert the on-the-wire mode matches the requested
// enum value, then drop any subsequent reads to confirm the client
// didn't loop waiting for an ack.
func TestClientReboot(t *testing.T) {
	cases := []struct {
		name string
		mode pb.RebootRequest_RebootMode
	}{
		{"OS", pb.RebootRequest_OS},
		{"DFU", pb.RebootRequest_DFU},
		{"UPDATE", pb.RebootRequest_UPDATE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientTx, srv := newChanTransportPair()
			c := NewClient(clientTx)
			openClient(t, c, srv)

			errCh := make(chan error, 1)
			go func() {
				errCh <- c.Reboot(context.Background(), tc.mode)
			}()

			req := awaitClientFrame(t, srv, 2*time.Second)
			rb, ok := req.Content.(*pb.Main_SystemRebootRequest)
			if !ok {
				t.Fatalf("unexpected content type %T", req.Content)
			}
			if rb.SystemRebootRequest.GetMode() != tc.mode {
				t.Errorf("mode = %v, want %v", rb.SystemRebootRequest.GetMode(), tc.mode)
			}
			select {
			case err := <-errCh:
				if err != nil {
					t.Errorf("Reboot returned error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Reboot timed out — should not block on response")
			}
		})
	}
}

// TestClientRebootClosed asserts Reboot honours the closed-session
// contract every other RPC in this package follows.
func TestClientRebootClosed(t *testing.T) {
	clientTx, _ := newChanTransportPair()
	c := NewClient(clientTx)
	if err := c.Reboot(context.Background(), pb.RebootRequest_OS); err != ErrSessionClosed {
		t.Errorf("Reboot before Open: got %v, want ErrSessionClosed", err)
	}
}

// TestClientGPIOSetPinMode asserts the request carries the expected
// pin/mode and the OK ack is consumed without error.
func TestClientGPIOSetPinMode(t *testing.T) {
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)
	openClient(t, c, srv)

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.GPIOSetPinMode(context.Background(), pb.GpioPin_PA7, pb.GpioPinMode_INPUT)
	}()

	req := awaitClientFrame(t, srv, 2*time.Second)
	sp, ok := req.Content.(*pb.Main_GpioSetPinMode)
	if !ok {
		t.Fatalf("unexpected content type %T", req.Content)
	}
	if sp.GpioSetPinMode.GetPin() != pb.GpioPin_PA7 {
		t.Errorf("pin = %v, want PA7", sp.GpioSetPinMode.GetPin())
	}
	if sp.GpioSetPinMode.GetMode() != pb.GpioPinMode_INPUT {
		t.Errorf("mode = %v, want INPUT", sp.GpioSetPinMode.GetMode())
	}

	writeFramedTo(srv, &pb.Main{
		CommandId:     req.CommandId,
		CommandStatus: pb.CommandStatus_OK,
		Content:       &pb.Main_Empty{Empty: &pb.Empty{}},
	})

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("GPIOSetPinMode returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GPIOSetPinMode timed out")
	}
}

// TestClientGPIOSetPinModeError surfaces a firmware GPIO error status as
// a non-nil error containing the canonical enum name.
func TestClientGPIOSetPinModeError(t *testing.T) {
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)
	openClient(t, c, srv)

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.GPIOSetPinMode(context.Background(), pb.GpioPin_PA7, pb.GpioPinMode_INPUT)
	}()

	req := awaitClientFrame(t, srv, 2*time.Second)
	writeFramedTo(srv, &pb.Main{
		CommandId:     req.CommandId,
		CommandStatus: pb.CommandStatus_ERROR_GPIO_MODE_INCORRECT,
		Content:       &pb.Main_Empty{Empty: &pb.Empty{}},
	})

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected GPIOSetPinMode to surface ERROR_GPIO_MODE_INCORRECT")
		}
		if !strings.Contains(err.Error(), "ERROR_GPIO_MODE_INCORRECT") {
			t.Errorf("error %q should mention ERROR_GPIO_MODE_INCORRECT", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GPIOSetPinMode error path timed out")
	}
}

// TestClientGPIOWritePin asserts the request carries the expected
// pin/value and the OK ack is consumed.
func TestClientGPIOWritePin(t *testing.T) {
	cases := []struct {
		name  string
		pin   pb.GpioPin
		value uint32
	}{
		{"PA7_HIGH", pb.GpioPin_PA7, 1},
		{"PC0_LOW", pb.GpioPin_PC0, 0},
		{"PB3_HIGH", pb.GpioPin_PB3, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientTx, srv := newChanTransportPair()
			c := NewClient(clientTx)
			openClient(t, c, srv)

			errCh := make(chan error, 1)
			go func() {
				errCh <- c.GPIOWritePin(context.Background(), tc.pin, tc.value)
			}()

			req := awaitClientFrame(t, srv, 2*time.Second)
			wp, ok := req.Content.(*pb.Main_GpioWritePin)
			if !ok {
				t.Fatalf("unexpected content type %T", req.Content)
			}
			if wp.GpioWritePin.GetPin() != tc.pin {
				t.Errorf("pin = %v, want %v", wp.GpioWritePin.GetPin(), tc.pin)
			}
			if wp.GpioWritePin.GetValue() != tc.value {
				t.Errorf("value = %d, want %d", wp.GpioWritePin.GetValue(), tc.value)
			}

			writeFramedTo(srv, &pb.Main{
				CommandId:     req.CommandId,
				CommandStatus: pb.CommandStatus_OK,
				Content:       &pb.Main_Empty{Empty: &pb.Empty{}},
			})

			select {
			case err := <-errCh:
				if err != nil {
					t.Errorf("GPIOWritePin returned error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("GPIOWritePin timed out")
			}
		})
	}
}

// TestClientGPIOReadPin verifies the value carried in the response is
// returned to the caller, and that ERROR_GPIO_* statuses surface as
// errors.
func TestClientGPIOReadPin(t *testing.T) {
	cases := []struct {
		name string
		want uint32
	}{
		{"low", 0},
		{"high", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientTx, srv := newChanTransportPair()
			c := NewClient(clientTx)
			openClient(t, c, srv)

			type result struct {
				v   uint32
				err error
			}
			ch := make(chan result, 1)
			go func() {
				v, err := c.GPIOReadPin(context.Background(), pb.GpioPin_PA7)
				ch <- result{v, err}
			}()

			req := awaitClientFrame(t, srv, 2*time.Second)
			if _, ok := req.Content.(*pb.Main_GpioReadPin); !ok {
				t.Fatalf("unexpected content type %T", req.Content)
			}

			writeFramedTo(srv, &pb.Main{
				CommandId:     req.CommandId,
				CommandStatus: pb.CommandStatus_OK,
				Content: &pb.Main_GpioReadPinResponse{
					GpioReadPinResponse: &pb.ReadPinResponse{Value: tc.want},
				},
			})

			select {
			case got := <-ch:
				if got.err != nil {
					t.Errorf("GPIOReadPin returned error: %v", got.err)
				}
				if got.v != tc.want {
					t.Errorf("value = %d, want %d", got.v, tc.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("GPIOReadPin timed out")
			}
		})
	}
}

// TestClientGPIOReadPinError verifies an ERROR_GPIO_* CommandStatus
// becomes a non-nil error rather than a silent zero value.
func TestClientGPIOReadPinError(t *testing.T) {
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)
	openClient(t, c, srv)

	type result struct {
		v   uint32
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := c.GPIOReadPin(context.Background(), pb.GpioPin_PA7)
		ch <- result{v, err}
	}()

	req := awaitClientFrame(t, srv, 2*time.Second)
	writeFramedTo(srv, &pb.Main{
		CommandId:     req.CommandId,
		CommandStatus: pb.CommandStatus_ERROR_GPIO_UNKNOWN_PIN_MODE,
		Content:       &pb.Main_Empty{Empty: &pb.Empty{}},
	})

	select {
	case got := <-ch:
		if got.err == nil {
			t.Fatal("expected GPIOReadPin to surface ERROR_GPIO_UNKNOWN_PIN_MODE")
		}
		if !strings.Contains(got.err.Error(), "ERROR_GPIO_UNKNOWN_PIN_MODE") {
			t.Errorf("error %q should mention ERROR_GPIO_UNKNOWN_PIN_MODE", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GPIOReadPin error path timed out")
	}
}

// TestClientDesktopIsLocked checks the firmware's status-encoded
// boolean: OK → locked, ERROR → unlocked, anything else → error.
func TestClientDesktopIsLocked(t *testing.T) {
	cases := []struct {
		name       string
		status     pb.CommandStatus
		wantLocked bool
		wantErr    bool
	}{
		{"locked", pb.CommandStatus_OK, true, false},
		{"unlocked", pb.CommandStatus_ERROR, false, false},
		{"unexpected_status", pb.CommandStatus_ERROR_NOT_IMPLEMENTED, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientTx, srv := newChanTransportPair()
			c := NewClient(clientTx)
			openClient(t, c, srv)

			type result struct {
				locked bool
				err    error
			}
			ch := make(chan result, 1)
			go func() {
				locked, err := c.DesktopIsLocked(context.Background())
				ch <- result{locked, err}
			}()

			req := awaitClientFrame(t, srv, 2*time.Second)
			if _, ok := req.Content.(*pb.Main_DesktopIsLockedRequest); !ok {
				t.Fatalf("unexpected content type %T", req.Content)
			}

			writeFramedTo(srv, &pb.Main{
				CommandId:     req.CommandId,
				CommandStatus: tc.status,
				Content:       &pb.Main_Empty{Empty: &pb.Empty{}},
			})

			select {
			case got := <-ch:
				if tc.wantErr {
					if got.err == nil {
						t.Fatal("expected error for unexpected status")
					}
					return
				}
				if got.err != nil {
					t.Errorf("DesktopIsLocked returned error: %v", got.err)
				}
				if got.locked != tc.wantLocked {
					t.Errorf("locked = %v, want %v", got.locked, tc.wantLocked)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("DesktopIsLocked timed out")
			}
		})
	}
}

// TestClientDesktopUnlock asserts the request type and that an OK ack
// is consumed without error.
func TestClientDesktopUnlock(t *testing.T) {
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)
	openClient(t, c, srv)

	errCh := make(chan error, 1)
	go func() { errCh <- c.DesktopUnlock(context.Background()) }()

	req := awaitClientFrame(t, srv, 2*time.Second)
	if _, ok := req.Content.(*pb.Main_DesktopUnlockRequest); !ok {
		t.Fatalf("unexpected content type %T", req.Content)
	}

	writeFramedTo(srv, &pb.Main{
		CommandId:     req.CommandId,
		CommandStatus: pb.CommandStatus_OK,
		Content:       &pb.Main_Empty{Empty: &pb.Empty{}},
	})

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("DesktopUnlock returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DesktopUnlock timed out")
	}
}

// TestClientPropertyGetStream feeds a multi-frame streaming response
// (has_next true → true → false) and asserts every (key, value) pair
// is collected in firmware-emission order.
func TestClientPropertyGetStream(t *testing.T) {
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)
	openClient(t, c, srv)

	type result struct {
		pairs []struct{ Key, Value string }
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		pairs, err := c.PropertyGet(context.Background(), "devinfo.")
		ch <- result{pairs, err}
	}()

	req := awaitClientFrame(t, srv, 2*time.Second)
	pg, ok := req.Content.(*pb.Main_PropertyGetRequest)
	if !ok {
		t.Fatalf("unexpected content type %T", req.Content)
	}
	if pg.PropertyGetRequest.GetKey() != "devinfo." {
		t.Errorf("key = %q, want %q", pg.PropertyGetRequest.GetKey(), "devinfo.")
	}

	stream := []struct {
		key, value string
		hasNext    bool
	}{
		{"devinfo.hardware_model", "Flipper", true},
		{"devinfo.firmware_version", "1.4.0", true},
		{"devinfo.battery_level", "73", false},
	}
	for _, s := range stream {
		writeFramedTo(srv, &pb.Main{
			CommandId:     req.CommandId,
			CommandStatus: pb.CommandStatus_OK,
			HasNext:       s.hasNext,
			Content: &pb.Main_PropertyGetResponse{
				PropertyGetResponse: &pb.GetResponse{Key: s.key, Value: s.value},
			},
		})
	}

	select {
	case got := <-ch:
		if got.err != nil {
			t.Errorf("PropertyGet returned error: %v", got.err)
		}
		if len(got.pairs) != len(stream) {
			t.Fatalf("got %d pairs, want %d", len(got.pairs), len(stream))
		}
		for i, want := range stream {
			if got.pairs[i].Key != want.key || got.pairs[i].Value != want.value {
				t.Errorf("pair[%d] = (%q,%q), want (%q,%q)",
					i, got.pairs[i].Key, got.pairs[i].Value, want.key, want.value)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PropertyGet timed out")
	}
}

// TestClientPropertyGetError asserts a non-OK CommandStatus mid-stream
// aborts and surfaces the firmware status name.
func TestClientPropertyGetError(t *testing.T) {
	clientTx, srv := newChanTransportPair()
	c := NewClient(clientTx)
	openClient(t, c, srv)

	type result struct {
		pairs []struct{ Key, Value string }
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		pairs, err := c.PropertyGet(context.Background(), "")
		ch <- result{pairs, err}
	}()

	req := awaitClientFrame(t, srv, 2*time.Second)
	writeFramedTo(srv, &pb.Main{
		CommandId:     req.CommandId,
		CommandStatus: pb.CommandStatus_ERROR_INVALID_PARAMETERS,
		Content:       &pb.Main_Empty{Empty: &pb.Empty{}},
	})

	select {
	case got := <-ch:
		if got.err == nil {
			t.Fatal("expected PropertyGet to surface ERROR_INVALID_PARAMETERS")
		}
		if !strings.Contains(got.err.Error(), "ERROR_INVALID_PARAMETERS") {
			t.Errorf("error %q should mention ERROR_INVALID_PARAMETERS", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PropertyGet error path timed out")
	}
}

// TestClientNewVerbsClosed pins the closed-session contract for every
// new RPC method added in this batch.
func TestClientNewVerbsClosed(t *testing.T) {
	clientTx, _ := newChanTransportPair()
	c := NewClient(clientTx)

	t.Run("GPIOSetPinMode", func(t *testing.T) {
		err := c.GPIOSetPinMode(context.Background(), pb.GpioPin_PA7, pb.GpioPinMode_INPUT)
		if !errors.Is(err, ErrSessionClosed) {
			t.Errorf("got %v, want ErrSessionClosed", err)
		}
	})
	t.Run("GPIOWritePin", func(t *testing.T) {
		err := c.GPIOWritePin(context.Background(), pb.GpioPin_PA7, 1)
		if !errors.Is(err, ErrSessionClosed) {
			t.Errorf("got %v, want ErrSessionClosed", err)
		}
	})
	t.Run("GPIOReadPin", func(t *testing.T) {
		_, err := c.GPIOReadPin(context.Background(), pb.GpioPin_PA7)
		if !errors.Is(err, ErrSessionClosed) {
			t.Errorf("got %v, want ErrSessionClosed", err)
		}
	})
	t.Run("DesktopIsLocked", func(t *testing.T) {
		_, err := c.DesktopIsLocked(context.Background())
		if !errors.Is(err, ErrSessionClosed) {
			t.Errorf("got %v, want ErrSessionClosed", err)
		}
	})
	t.Run("DesktopUnlock", func(t *testing.T) {
		err := c.DesktopUnlock(context.Background())
		if !errors.Is(err, ErrSessionClosed) {
			t.Errorf("got %v, want ErrSessionClosed", err)
		}
	})
	t.Run("PropertyGet", func(t *testing.T) {
		_, err := c.PropertyGet(context.Background(), "")
		if !errors.Is(err, ErrSessionClosed) {
			t.Errorf("got %v, want ErrSessionClosed", err)
		}
	})
}
