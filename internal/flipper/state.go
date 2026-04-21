package flipper

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

// State is a point-in-time snapshot of the connected Flipper, cheap to
// render into the model's turn context. Carries only fields that help
// the agent avoid redundant "what's connected?" round-trips; heavyweight
// probes (SD walk, loader state, log dump) are deliberately excluded.
type State struct {
	Connected       bool      `json:"connected"`
	Fork            string    `json:"fork,omitempty"`             // stock/Momentum/Unleashed/RogueMaster/Xtreme
	FirmwareVersion string    `json:"firmware_version,omitempty"` // version string from device_info
	HardwareName    string    `json:"hardware_name,omitempty"`    // user-settable dolphin name
	HardwareUID     string    `json:"hardware_uid,omitempty"`
	BatteryPct      int       `json:"battery_pct,omitempty"`  // 0-100, 0 if unknown
	ChargeState     string    `json:"charge_state,omitempty"` // "charging" / "discharging" / ""
	CollectedAt     time.Time `json:"collected_at"`
}

// stateCacheTTL bounds how often State() hits the device. Two seconds is
// long enough to amortise multi-turn bursts (each REPL response reads
// state once and forwards it to the LLM) while short enough that a
// freshly-plugged card or a just-flipped charge state is visible.
const stateCacheTTL = 2 * time.Second

// stateCache is embedded by Flipper to memoise the last State() result.
// Protected by its own mutex so state reads never contend with Exec —
// a mid-long-scan state probe must not have to wait for the scan to
// finish.
type stateCache struct {
	mu    sync.Mutex
	snap  State
	at    time.Time
	valid bool
}

// State returns the freshest State snapshot that satisfies the cache
// TTL. On a cache miss it re-queries capabilities + power_info with the
// caller's context; partial results (capabilities only, no power data)
// are still cached and returned because they carry useful framing for
// the agent. A genuinely empty cache is returned with Connected=false
// and an error — the caller treats that as "skip injection this turn".
func (f *Flipper) State(ctx context.Context) (State, error) {
	f.state.mu.Lock()
	if f.state.valid && time.Since(f.state.at) < stateCacheTTL {
		snap := f.state.snap
		f.state.mu.Unlock()
		return snap, nil
	}
	f.state.mu.Unlock()

	fresh, err := f.fetchState(ctx)

	// Cache any snapshot carrying useful data (capabilities populated
	// or transport present). This keeps a transient ctx cancellation
	// from dropping a just-collected snapshot, and avoids hammering the
	// device with retry probes within the TTL if power_info errored.
	if fresh.Connected {
		f.state.mu.Lock()
		f.state.snap = fresh
		f.state.at = time.Now()
		f.state.valid = true
		f.state.mu.Unlock()
		return fresh, nil
	}

	// Truly empty fetch — fall back to whatever we had last.
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	if f.state.valid {
		return f.state.snap, nil
	}
	return fresh, err
}

// fetchState gathers the fields that make up a State. Capabilities are
// already cached on the struct; only PowerInfoMap costs a serial round
// trip. Connected is derived from whether we have *any* useful data
// (capabilities populated or a live transport) so a stale-but-cached
// device still gives the agent a useful block to render.
func (f *Flipper) fetchState(ctx context.Context) (State, error) {
	caps := f.Capabilities()
	hasCapsData := caps.FirmwareVersion != "" || caps.FirmwareFork != "" || caps.HardwareUID != ""

	st := State{
		Connected:       hasCapsData || f.transport != nil,
		Fork:            caps.FriendlyFork(),
		FirmwareVersion: caps.FirmwareVersion,
		HardwareName:    caps.HardwareName,
		HardwareUID:     caps.HardwareUID,
		CollectedAt:     time.Now(),
	}

	// Context respect: skip the serial hop if the caller's deadline is
	// already blown. The capabilities block above is cheap (atomic load)
	// and useful even without battery info, so we return what we have.
	if err := ctx.Err(); err != nil {
		return st, err
	}

	// Transport absent (tests, mid-reconnect) — we can't probe power.
	// Partial state from capabilities alone is still useful to the model.
	if f.transport == nil {
		return st, nil
	}

	power, err := f.PowerInfoMap()
	if err != nil {
		// Partial state is still useful to the model.
		return st, nil
	}
	if v, ok := power["charge_level"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 && n <= 100 {
			st.BatteryPct = n
		}
	}
	if v, ok := power["charge_state"]; ok {
		st.ChargeState = strings.TrimSpace(v)
	}
	return st, nil
}

// InvalidateState drops the cached snapshot so the next State() call
// forces a re-query. Intended for use after operations that might
// change the observable state materially (firmware updates, power
// reboots, storage format), not for every write — the 2 s TTL already
// covers ordinary drift.
func (f *Flipper) InvalidateState() {
	f.state.mu.Lock()
	f.state.valid = false
	f.state.mu.Unlock()
}

// NewForTest returns a Flipper with preloaded capabilities and no
// transport. Intended for unit tests in other packages that need to
// exercise State-consuming code paths without wiring up a mock serial
// port. The returned Flipper will never successfully Exec — only
// capability-derived and transport-less-safe methods should be called.
func NewForTest(caps Capabilities) *Flipper {
	f := &Flipper{}
	f.caps.Store(&caps)
	return f
}
