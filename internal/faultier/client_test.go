package faultier

import (
	"strings"
	"testing"
)

// --- Helpers -----------------------------------------------------------------

// mustOK calls fn and fails the test if it returns an error.
func mustOK(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", name, err)
	}
}

// mustErr calls fn and fails the test if it does NOT return an error, or if
// the error message does not contain wantSubstr.
func mustErr(t *testing.T, name string, err error, wantSubstr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error containing %q, got nil", name, wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("%s: error %q does not contain %q", name, err.Error(), wantSubstr)
	}
}

// --- Configure ---------------------------------------------------------------

// TestConfigure verifies that Configure sends the right payload and the device
// (Mock) accepts it, storing the config in Mock.State.
func TestConfigure(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	cfg := GlitcherConfig{
		TriggerType:   TriggerRisingEdge,
		TriggerSource: TriggerSrcExt0,
		GlitchOutput:  OutMux0,
		DelayUS:       1000,
		PulseUS:       50,
		PowerCycle:    false,
		PowerCycleLen: 0,
	}
	mustOK(t, "Configure", c.Configure(cfg))

	m.mu.Lock()
	got := m.State.Config
	m.mu.Unlock()

	if got != cfg {
		t.Errorf("Mock.State.Config:\n got  %+v\n want %+v", got, cfg)
	}
}

// --- SetPulse ----------------------------------------------------------------

// TestSetPulse verifies that SetPulse configures delay and pulse with sane
// defaults for other fields.
func TestSetPulse(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustOK(t, "SetPulse", c.SetPulse(500, 25))

	m.mu.Lock()
	got := m.State.Config
	m.mu.Unlock()

	if got.DelayUS != 500 {
		t.Errorf("DelayUS = %d, want 500", got.DelayUS)
	}
	if got.PulseUS != 25 {
		t.Errorf("PulseUS = %d, want 25", got.PulseUS)
	}
	if got.TriggerType != TriggerNone {
		t.Errorf("TriggerType = %v, want TriggerNone", got.TriggerType)
	}
}

// --- Arm / Fire / Disarm -----------------------------------------------------

// TestArmSetsArmedState verifies Arm marks the device as armed.
func TestArmSetsArmedState(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustOK(t, "Arm", c.Arm())

	m.mu.Lock()
	armed := m.State.Armed
	m.mu.Unlock()

	if !armed {
		t.Error("Mock.State.Armed is false after Arm()")
	}
}

// TestFireSetsGlitchOutcome verifies Fire records OutcomeGlitch and clears armed.
func TestFireSetsGlitchOutcome(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustOK(t, "Fire", c.Fire())

	m.mu.Lock()
	outcome := m.State.LastOutcome
	armed := m.State.Armed
	m.mu.Unlock()

	if outcome != OutcomeGlitch {
		t.Errorf("LastOutcome = %d, want OutcomeGlitch(%d)", outcome, OutcomeGlitch)
	}
	if armed {
		t.Error("Mock.State.Armed is true after Fire()")
	}
}

// TestDisarmClearsArmedState verifies Disarm resets the armed flag.
func TestDisarmClearsArmedState(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustOK(t, "Arm", c.Arm())
	mustOK(t, "Disarm", c.Disarm())

	m.mu.Lock()
	armed := m.State.Armed
	m.mu.Unlock()

	if armed {
		t.Error("Mock.State.Armed is true after Disarm()")
	}
}

// --- Status ------------------------------------------------------------------

// TestStatusInitial verifies the initial status response (no glitch yet).
func TestStatusInitial(t *testing.T) {
	c, _ := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	sb, err := c.Status()
	mustOK(t, "Status", err)

	if sb.Armed {
		t.Error("initial status: Armed should be false")
	}
	if sb.LastDelayUS != 0 {
		t.Errorf("initial status: LastDelayUS = %d, want 0", sb.LastDelayUS)
	}
	if sb.LastOutcome != OutcomeNone {
		t.Errorf("initial status: LastOutcome = %d, want OutcomeNone", sb.LastOutcome)
	}
}

// TestStatusAfterConfigureAndArm verifies that Status reflects configured
// delay and armed state.
func TestStatusAfterConfigureAndArm(t *testing.T) {
	c, _ := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustOK(t, "SetPulse", c.SetPulse(9999, 10))
	mustOK(t, "Arm", c.Arm())

	sb, err := c.Status()
	mustOK(t, "Status", err)

	if !sb.Armed {
		t.Error("status after Arm: Armed should be true")
	}
	if sb.LastDelayUS != 9999 {
		t.Errorf("status after SetPulse(9999): LastDelayUS = %d, want 9999", sb.LastDelayUS)
	}
}

// TestStatusAfterFire verifies that Status reflects OutcomeGlitch after Fire.
func TestStatusAfterFire(t *testing.T) {
	c, _ := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustOK(t, "Fire", c.Fire())

	sb, err := c.Status()
	mustOK(t, "Status", err)

	if sb.LastOutcome != OutcomeGlitch {
		t.Errorf("LastOutcome = %d, want OutcomeGlitch(%d)", sb.LastOutcome, OutcomeGlitch)
	}
}

// --- Sweep -------------------------------------------------------------------

// TestSweepRoundTrip fires across a small range and verifies the final
// configured delay matches the last step.
func TestSweepRoundTrip(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	// start=100, end=300, step=100 → delays 100, 200, 300 (3 fires)
	mustOK(t, "Sweep", c.Sweep(100, 300, 100))

	m.mu.Lock()
	delay := m.State.Config.DelayUS
	m.mu.Unlock()

	if delay != 300 {
		t.Errorf("after Sweep(100,300,100): final delay = %d, want 300", delay)
	}
}

// TestSweepZeroStepErrors verifies Sweep rejects a zero step.
func TestSweepZeroStepErrors(t *testing.T) {
	c, _ := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustErr(t, "Sweep(zero step)", c.Sweep(0, 100, 0), "step_us must be > 0")
}

// TestSweepInvertedRangeErrors verifies Sweep rejects start > end.
func TestSweepInvertedRangeErrors(t *testing.T) {
	c, _ := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustErr(t, "Sweep(inverted)", c.Sweep(200, 100, 10), "start_us")
}

// TestSweepSingleStep verifies Sweep works when start == end.
func TestSweepSingleStep(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustOK(t, "Sweep(single)", c.Sweep(42, 42, 10))

	m.mu.Lock()
	delay := m.State.Config.DelayUS
	m.mu.Unlock()

	if delay != 42 {
		t.Errorf("after Sweep(42,42,10): delay = %d, want 42", delay)
	}
}

// --- Error injection ---------------------------------------------------------

// TestInjectErrorNotArmed verifies that a device ErrNotArmed translates to a
// descriptive Go error.
func TestInjectErrorNotArmed(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	m.mu.Lock()
	m.InjectError = ErrNotArmed
	m.mu.Unlock()

	mustErr(t, "Fire(inject not-armed)", c.Fire(), "not armed")
}

// TestInjectErrorBusy verifies that ErrBusy is surfaced correctly.
func TestInjectErrorBusy(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	m.mu.Lock()
	m.InjectError = ErrBusy
	m.mu.Unlock()

	mustErr(t, "Arm(inject busy)", c.Arm(), "busy")
}

// TestInjectErrorHWFault verifies that ErrHWFault is surfaced correctly.
func TestInjectErrorHWFault(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	m.mu.Lock()
	m.InjectError = ErrHWFault
	m.mu.Unlock()

	mustErr(t, "Configure(inject hw-fault)", c.Configure(GlitcherConfig{}), "hardware fault")
}

// TestInjectErrorInvalidParam verifies that ErrInvalidParam is surfaced.
func TestInjectErrorInvalidParam(t *testing.T) {
	c, m := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	m.mu.Lock()
	m.InjectError = ErrInvalidParam
	m.mu.Unlock()

	mustErr(t, "Disarm(inject invalid-param)", c.Disarm(), "invalid param")
}

// --- Close idempotence -------------------------------------------------------

// TestCloseIdempotent verifies that calling Close twice does not panic or
// return an error.
func TestCloseIdempotent(t *testing.T) {
	c, _ := NewMockClient()

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// --- Sequential commands (protocol integrity) --------------------------------

// TestMultipleCommandsSequential verifies that the client can issue several
// different commands back-to-back without framing corruption.
func TestMultipleCommandsSequential(t *testing.T) {
	c, _ := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustOK(t, "SetPulse", c.SetPulse(100, 10))
	mustOK(t, "Arm", c.Arm())

	sb, err := c.Status()
	mustOK(t, "Status", err)
	if !sb.Armed {
		t.Error("should be armed after Arm()")
	}

	mustOK(t, "Disarm", c.Disarm())

	sb2, err := c.Status()
	mustOK(t, "Status after Disarm", err)
	if sb2.Armed {
		t.Error("should not be armed after Disarm()")
	}
}

// TestAllOpcodesRoundTrip exercises every defined opcode at least once.
func TestAllOpcodesRoundTrip(t *testing.T) {
	c, _ := NewMockClient()
	t.Cleanup(func() { _ = c.Close() })

	mustOK(t, "Configure", c.Configure(GlitcherConfig{
		GlitchOutput: OutMux1,
		DelayUS:      200,
		PulseUS:      20,
	}))
	mustOK(t, "Arm", c.Arm())
	mustOK(t, "Disarm", c.Disarm())
	mustOK(t, "Fire", c.Fire())
	_, err := c.Status()
	mustOK(t, "Status", err)
}
