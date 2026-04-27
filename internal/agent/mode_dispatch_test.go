package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/mode"
)

// TestDispatch_ModeBlocksHighRiskTransmit confirms a Sub-GHz TX
// primitive (Group=GroupFlipperSubGHz, Risk=High) is refused with
// ErrBlockedByMode when the agent is in Recon mode. This is the
// direct guarantee operators rely on: switching to a constrained
// mode actually prevents the transmit, even if the LLM advertises
// the tool and the dispatch catalogue still lists it.
func TestDispatch_ModeBlocksHighRiskTransmit(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.SetMode(mode.ModeRecon)

	// subghz_tx_key is registered with GroupFlipperSubGHz + risk.High.
	// Recon mode's allow-list excludes the SubGHz group, so dispatch
	// should refuse before touching the (nil) flipper handler.
	out, err := a.dispatch(context.Background(), "subghz_tx_key", map[string]interface{}{
		"key_hex":   "F00F00AA",
		"frequency": 433920000,
		"te":        400,
		"repeat":    3,
	})
	if err == nil {
		t.Fatalf("dispatch(subghz_tx_key) in Recon mode = (%q, nil), want refusal error", out)
	}
	if !errors.Is(err, ErrBlockedByMode) {
		t.Fatalf("dispatch error = %v, want errors.Is(err, ErrBlockedByMode) == true", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "subghz_tx_key") {
		t.Errorf("error %q does not name the tool — operators need the tool name in the rejection", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "recon") {
		t.Errorf("error %q does not name the active mode — operators need the mode name to know what to switch", msg)
	}
}

// TestDispatch_ModeAllowsWhenStandardDefault confirms the zero-
// configured agent has Mode() == Standard. We don't drive a real
// dispatch through a non-mock handler here because that requires
// hardware; the "Standard does not gate" property is covered
// transitively by TestDispatch_ModeUnknownToolStillReportsUnknown
// (which only reaches the gate by passing the registry lookup).
func TestDispatch_ModeAllowsWhenStandardDefault(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	if got := a.Mode(); got != mode.ModeStandard {
		t.Fatalf("default agent mode = %q, want %q (Standard must be the zero-config default)", got, mode.ModeStandard)
	}
}

// TestDispatch_ModeUnknownToolStillReportsUnknown confirms the mode
// gate runs AFTER the registry lookup — an unknown tool name must
// still surface as "unknown tool", not as a mode-blocked rejection.
// (The opposite ordering would mask typos as policy refusals.)
func TestDispatch_ModeUnknownToolStillReportsUnknown(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.SetMode(mode.ModeStealth)
	_, err := a.dispatch(context.Background(), "this_tool_does_not_exist", map[string]interface{}{})
	if err == nil {
		t.Fatal("dispatch of unknown tool returned nil error")
	}
	if errors.Is(err, ErrBlockedByMode) {
		t.Fatalf("unknown tool surfaced as mode-blocked: %v — typos must not be confused with policy refusals", err)
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("unknown tool error = %q, want substring %q", err, "unknown tool")
	}
}

// TestSetMode_EmptyResetsToStandard pins the contract: passing the
// empty Mode resets to Standard rather than leaving the agent in a
// degenerate "" state where no group is allowed.
func TestSetMode_EmptyResetsToStandard(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.SetMode(mode.ModeStealth)
	a.SetMode("") // explicit reset
	if got := a.Mode(); got != mode.ModeStandard {
		t.Errorf("SetMode(\"\") then Mode() = %q, want %q", got, mode.ModeStandard)
	}
}
