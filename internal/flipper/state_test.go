package flipper

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// newStateFlipperWithCaps returns a Flipper whose capabilities cache is
// prepopulated and whose transport is nil. fetchState tolerates a nil
// transport via PowerInfoMap returning an error, which is the test path
// we want — it exercises the "capabilities-only partial state" branch
// without dragging in a mock serial transport.
func newStateFlipperWithCaps(c Capabilities) *Flipper {
	f := &Flipper{}
	f.caps.Store(&c)
	return f
}

func TestFlipper_State_UsesCapabilities(t *testing.T) {
	f := newStateFlipperWithCaps(Capabilities{
		FirmwareFork:    "Momentum",
		FirmwareVersion: "0.99.1",
		HardwareName:    "Testipper",
		HardwareUID:     "deadbeef",
		PowerInfoCmd:    "info power",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	st, _ := f.State(ctx)
	if !st.Connected {
		t.Fatalf("State().Connected = false, want true (capabilities cache populated)")
	}
	if st.Fork != "Momentum" {
		t.Errorf("Fork = %q, want Momentum", st.Fork)
	}
	if st.FirmwareVersion != "0.99.1" {
		t.Errorf("FirmwareVersion = %q, want 0.99.1", st.FirmwareVersion)
	}
	if st.HardwareName != "Testipper" {
		t.Errorf("HardwareName = %q, want Testipper", st.HardwareName)
	}
	if st.CollectedAt.IsZero() {
		t.Errorf("CollectedAt should be set")
	}
}

func TestFlipper_State_CachesForTTL(t *testing.T) {
	// First call populates the cache; second call within TTL must reuse.
	f := newStateFlipperWithCaps(Capabilities{FirmwareFork: "Unleashed"})
	ctx := context.Background()

	st1, _ := f.State(ctx)
	first := st1.CollectedAt

	// Immediate second call — should return the same snapshot (same
	// CollectedAt — cache hit, no refetch).
	st2, _ := f.State(ctx)
	if !st2.CollectedAt.Equal(first) {
		t.Fatalf("second State() call refetched inside TTL: first=%v second=%v", first, st2.CollectedAt)
	}
}

func TestFlipper_State_InvalidateForcesRefetch(t *testing.T) {
	f := newStateFlipperWithCaps(Capabilities{FirmwareFork: "Momentum"})
	ctx := context.Background()

	st1, _ := f.State(ctx)
	f.InvalidateState()

	// Sleep a beat so CollectedAt can differ measurably.
	time.Sleep(2 * time.Millisecond)
	st2, _ := f.State(ctx)

	if !st2.CollectedAt.After(st1.CollectedAt) {
		t.Fatalf("InvalidateState did not force refetch: first=%v second=%v", st1.CollectedAt, st2.CollectedAt)
	}
}

func TestFlipper_State_ConcurrentSafe(t *testing.T) {
	f := newStateFlipperWithCaps(Capabilities{FirmwareFork: "Xtreme"})
	ctx := context.Background()

	// Hammer State() from many goroutines. With the stateCache mutex the
	// race detector must stay clean.
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = f.State(ctx)
			}
		}()
	}
	wg.Wait()
}

func TestFlipper_State_CancelledContext(t *testing.T) {
	// A cancelled context should not prevent the capabilities-only slice
	// of state from being returned. fetchState bails before the serial
	// hop so the return still carries fork/firmware.
	f := newStateFlipperWithCaps(Capabilities{FirmwareFork: "Momentum"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	st, _ := f.State(ctx)
	// Partial state is fine — Connected must still be true because the
	// capabilities cache has content. BatteryPct stays zero because
	// the power hop was skipped.
	if !strings.EqualFold(st.Fork, "Momentum") {
		t.Fatalf("Fork = %q, want Momentum even on cancelled ctx", st.Fork)
	}
	if st.BatteryPct != 0 {
		t.Errorf("BatteryPct = %d, want 0 when power hop is skipped", st.BatteryPct)
	}
}
