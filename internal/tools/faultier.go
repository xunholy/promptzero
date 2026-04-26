// faultier.go — Faultier USB voltage-glitcher Specs.
//
// Six primitives wired here:
//
//   - glitch_arm        — arm the configured trigger; device waits for edge.
//   - glitch_fire       — fire a single glitch immediately (no trigger wait).
//   - glitch_set_pulse  — configure delay_us + pulse_us before arm/fire.
//   - glitch_sweep      — sweep delay from start_us to end_us, firing on each step.
//   - glitch_disarm     — cancel an armed trigger.
//   - glitch_status     — read armed state and last glitch outcome (read-only).
//
// All destructive specs carry risk.Critical because a voltage glitch can
// permanently damage the target chip or Faultier hardware if parameters are
// mis-set.  glitch_status is risk.Low (read-only query).
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(glitchArmSpec)
	Register(glitchFireSpec)
	Register(glitchSetPulseSpec)
	Register(glitchSweepSpec)
	Register(glitchDisarmSpec)
	Register(glitchStatusSpec)
}

// GroupFaultier is the router bucket for Faultier voltage-glitcher tools.
const GroupFaultier Group = "faultier"

// RequireFaultier returns a friendly error when the optional Faultier client
// is not connected.  Faultier handlers call this before invoking any
// d.Faultier method.
func (d *Deps) RequireFaultier() error {
	if d == nil || d.Faultier == nil {
		return fmt.Errorf("Faultier not connected — start PromptZero with a faultier.port configured")
	}
	return nil
}

// --- Specs -------------------------------------------------------------------

var glitchArmSpec = Spec{
	Name:        "glitch_arm",
	Description: "Arm the Faultier trigger. The device will wait for the configured hardware-trigger condition (rising/falling edge on EXT0/EXT1) before firing the glitch pulse. Call glitch_set_pulse first to configure delay and pulse width. Returns OK when the device acknowledges arming.",
	Schema: json.RawMessage(`{
		"type": "object",
		"properties": {}
	}`),
	Required:  []string{},
	Risk:      risk.Critical,
	Group:     GroupFaultier,
	AgentOnly: false,
	Handler:   glitchArmHandler,
}

var glitchFireSpec = Spec{
	Name:        "glitch_fire",
	Description: "Fire a single voltage glitch immediately, without waiting for a hardware trigger. The device uses the delay and pulse width last set by glitch_set_pulse. Returns OK when the glitch pulse has been delivered.",
	Schema: json.RawMessage(`{
		"type": "object",
		"properties": {}
	}`),
	Required:  []string{},
	Risk:      risk.Critical,
	Group:     GroupFaultier,
	AgentOnly: false,
	Handler:   glitchFireHandler,
}

var glitchSetPulseSpec = Spec{
	Name:        "glitch_set_pulse",
	Description: "Configure the glitch delay and pulse width before the next arm or fire. delay_us is the time in microseconds between the trigger event and the start of the glitch pulse. pulse_us is the duration of the glitch pulse in microseconds. Both values must be non-negative integers. These settings persist until changed.",
	Schema: json.RawMessage(`{
		"type": "object",
		"properties": {
			"delay_us": {
				"type": "integer",
				"description": "Delay between trigger and glitch pulse, in microseconds (≥0)"
			},
			"pulse_us": {
				"type": "integer",
				"description": "Width of the glitch pulse, in microseconds (≥0)"
			}
		},
		"required": ["delay_us", "pulse_us"]
	}`),
	Required:  []string{"delay_us", "pulse_us"},
	Risk:      risk.Critical,
	Group:     GroupFaultier,
	AgentOnly: false,
	Handler:   glitchSetPulseHandler,
}

var glitchSweepSpec = Spec{
	Name:        "glitch_sweep",
	Description: "Sweep the glitch delay from start_us to end_us, firing a glitch at each step. step_us is the increment between successive delay values. The device is re-configured and re-fired for each step. The sweep aborts on the first device error. Use this for automated fault-injection parameter exploration.",
	Schema: json.RawMessage(`{
		"type": "object",
		"properties": {
			"start_us": {
				"type": "integer",
				"description": "Starting delay in microseconds (≥0)"
			},
			"end_us": {
				"type": "integer",
				"description": "Ending delay in microseconds (≥start_us)"
			},
			"step_us": {
				"type": "integer",
				"description": "Step size between delay values in microseconds (>0)"
			}
		},
		"required": ["start_us", "end_us", "step_us"]
	}`),
	Required:  []string{"start_us", "end_us", "step_us"},
	Risk:      risk.Critical,
	Group:     GroupFaultier,
	AgentOnly: false,
	Handler:   glitchSweepHandler,
}

var glitchDisarmSpec = Spec{
	Name:        "glitch_disarm",
	Description: "Disarm the Faultier, cancelling any pending armed trigger. The device returns to idle. Safe to call even when not armed.",
	Schema: json.RawMessage(`{
		"type": "object",
		"properties": {}
	}`),
	Required:  []string{},
	Risk:      risk.Critical,
	Group:     GroupFaultier,
	AgentOnly: false,
	Handler:   glitchDisarmHandler,
}

var glitchStatusSpec = Spec{
	Name:        "glitch_status",
	Description: "Read the Faultier's current status: whether it is armed, the last configured delay, and the outcome of the most recent glitch attempt (none, skip, crash, glitch, ok). Read-only — does not change device state.",
	Schema: json.RawMessage(`{
		"type": "object",
		"properties": {}
	}`),
	Required:  []string{},
	Risk:      risk.Low,
	Group:     GroupFaultier,
	AgentOnly: false,
	Handler:   glitchStatusHandler,
}

// --- Handlers ----------------------------------------------------------------

func glitchArmHandler(_ context.Context, d *Deps, _ map[string]any) (string, error) {
	if err := d.RequireFaultier(); err != nil {
		return "", err
	}
	if err := d.Faultier.Arm(); err != nil {
		return "", fmt.Errorf("glitch_arm: %w", err)
	}
	body, _ := json.Marshal(map[string]any{
		"status": "armed",
	})
	return string(body), nil
}

func glitchFireHandler(_ context.Context, d *Deps, _ map[string]any) (string, error) {
	if err := d.RequireFaultier(); err != nil {
		return "", err
	}
	if err := d.Faultier.Fire(); err != nil {
		return "", fmt.Errorf("glitch_fire: %w", err)
	}
	body, _ := json.Marshal(map[string]any{
		"status": "fired",
	})
	return string(body), nil
}

func glitchSetPulseHandler(_ context.Context, d *Deps, args map[string]any) (string, error) {
	if err := d.RequireFaultier(); err != nil {
		return "", err
	}
	delayUS := intOr(args, "delay_us", -1)
	pulseUS := intOr(args, "pulse_us", -1)
	if delayUS < 0 {
		return "", fmt.Errorf("glitch_set_pulse: delay_us must be >= 0")
	}
	if pulseUS < 0 {
		return "", fmt.Errorf("glitch_set_pulse: pulse_us must be >= 0")
	}
	if err := d.Faultier.SetPulse(uint32(delayUS), uint32(pulseUS)); err != nil {
		return "", fmt.Errorf("glitch_set_pulse: %w", err)
	}
	body, _ := json.Marshal(map[string]any{
		"status":   "configured",
		"delay_us": delayUS,
		"pulse_us": pulseUS,
	})
	return string(body), nil
}

func glitchSweepHandler(ctx context.Context, d *Deps, args map[string]any) (string, error) {
	if err := d.RequireFaultier(); err != nil {
		return "", err
	}
	startUS := intOr(args, "start_us", -1)
	endUS := intOr(args, "end_us", -1)
	stepUS := intOr(args, "step_us", -1)
	if startUS < 0 {
		return "", fmt.Errorf("glitch_sweep: start_us must be >= 0")
	}
	if endUS < 0 {
		return "", fmt.Errorf("glitch_sweep: end_us must be >= 0")
	}
	if stepUS <= 0 {
		return "", fmt.Errorf("glitch_sweep: step_us must be > 0")
	}
	// ctx is forwarded so cancellation propagates into the sweep loop.
	if err := d.Faultier.Sweep(ctx, uint32(startUS), uint32(endUS), uint32(stepUS)); err != nil {
		return "", fmt.Errorf("glitch_sweep: %w", err)
	}
	steps := (endUS-startUS)/stepUS + 1
	body, _ := json.Marshal(map[string]any{
		"status":   "sweep_complete",
		"start_us": startUS,
		"end_us":   endUS,
		"step_us":  stepUS,
		"steps":    steps,
	})
	return string(body), nil
}

func glitchDisarmHandler(_ context.Context, d *Deps, _ map[string]any) (string, error) {
	if err := d.RequireFaultier(); err != nil {
		return "", err
	}
	if err := d.Faultier.Disarm(); err != nil {
		return "", fmt.Errorf("glitch_disarm: %w", err)
	}
	body, _ := json.Marshal(map[string]any{
		"status": "disarmed",
	})
	return string(body), nil
}

func glitchStatusHandler(_ context.Context, d *Deps, _ map[string]any) (string, error) {
	if err := d.RequireFaultier(); err != nil {
		return "", err
	}
	sb, err := d.Faultier.Status()
	if err != nil {
		return "", fmt.Errorf("glitch_status: %w", err)
	}

	// Import the outcome-to-string helper from the faultier package.
	// We inline the mapping here so this file has no circular import.
	outcomeStr := faultierOutcomeString(sb.LastOutcome)

	body, _ := json.Marshal(map[string]any{
		"armed":         sb.Armed,
		"last_delay_us": sb.LastDelayUS,
		"last_outcome":  outcomeStr,
	})
	return string(body), nil
}

// faultierOutcomeString maps a LastOutcome byte to its human-readable name.
// Mirrors faultier.OutcomeString but avoids an import cycle (tools → faultier
// is allowed; tools must not import itself).
func faultierOutcomeString(o byte) string {
	switch o {
	case 0x00:
		return "none"
	case 0x01:
		return "skip"
	case 0x02:
		return "crash"
	case 0x03:
		return "glitch"
	case 0x04:
		return "ok"
	default:
		return fmt.Sprintf("unknown(0x%02X)", o)
	}
}
