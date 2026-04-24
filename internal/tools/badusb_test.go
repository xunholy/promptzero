package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/config"
	flippermock "github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/testmocks"
)

// badUSBMakeCfg returns a minimal Config with the given BadUSB options.
func badUSBMakeCfg(allowCritical bool, enabled *bool) *config.Config {
	return &config.Config{
		Validator: config.ValidatorConfig{
			BadUSB: config.BadUSBValidatorConfig{
				AllowCritical: allowCritical,
				Enabled:       enabled,
				WarnAction:    "warn",
			},
		},
	}
}

// TestBadUSBRun_ValidatorGate_BlocksCritical verifies that badusb_run
// returns an error (rather than executing) when the payload contains a
// critical-severity DuckyScript pattern and AllowCritical is false (§F.2).
func TestBadUSBRun_ValidatorGate_BlocksCritical(t *testing.T) {
	// DuckyScript with rm -rf / — triggers the rm_rf_root critical rule.
	criticalScript := "DELAY 500\nSTRING rm -rf /\nENTER\n"

	f := testmocks.NewMockFlipper(t,
		testmocks.WithFlipperHandler("storage", flippermock.Handler(func(args []string) string {
			// args[0]=="read" when the CLI issues "storage read <path>"
			return criticalScript
		})),
	)

	deps := &Deps{
		Flipper: f,
		Config:  badUSBMakeCfg(false, nil), // AllowCritical=false, validator enabled by default
	}

	spec, ok := Get("badusb_run")
	if !ok {
		t.Fatal("badusb_run not registered")
	}

	_, err := spec.Handler(context.Background(), deps, map[string]any{"file": "/ext/badusb/evil.txt"})
	if err == nil {
		t.Fatal("expected error from validator gate, got nil")
	}
	if !strings.Contains(err.Error(), "blocked by sandbox validator") {
		t.Errorf("error does not mention validator block: %v", err)
	}
}

// TestBadUSBRun_ValidatorGate_AllowsCriticalWhenOverridden verifies that
// the gate is bypassed when AllowCritical is explicitly set to true.
func TestBadUSBRun_ValidatorGate_AllowsCriticalWhenOverridden(t *testing.T) {
	criticalScript := "DELAY 500\nSTRING rm -rf /\nENTER\n"

	f := testmocks.NewMockFlipper(t,
		testmocks.WithFlipperHandler("storage", flippermock.Handler(func(args []string) string {
			return criticalScript
		})),
		testmocks.WithFlipperHandler("badusb", flippermock.Handler(func(args []string) string {
			return "ok"
		})),
	)

	deps := &Deps{
		Flipper: f,
		Config:  badUSBMakeCfg(true, nil), // AllowCritical=true
	}

	spec, ok := Get("badusb_run")
	if !ok {
		t.Fatal("badusb_run not registered")
	}

	_, err := spec.Handler(context.Background(), deps, map[string]any{"file": "/ext/badusb/evil.txt"})
	// The gate should not block when AllowCritical=true.
	if err != nil && strings.Contains(err.Error(), "blocked by sandbox validator") {
		t.Errorf("gate should not block when AllowCritical=true: %v", err)
	}
}

// TestBadUSBRun_ValidatorGate_DisabledValidator verifies that when the
// validator is explicitly disabled (Enabled=false), no gate runs.
func TestBadUSBRun_ValidatorGate_DisabledValidator(t *testing.T) {
	disabled := false

	f := testmocks.NewMockFlipper(t,
		testmocks.WithFlipperHandler("badusb", flippermock.Handler(func(args []string) string {
			return "ok"
		})),
	)

	deps := &Deps{
		Flipper: f,
		Config:  badUSBMakeCfg(false, &disabled), // validator disabled
	}

	spec, ok := Get("badusb_run")
	if !ok {
		t.Fatal("badusb_run not registered")
	}

	_, err := spec.Handler(context.Background(), deps, map[string]any{"file": "/ext/badusb/payload.txt"})
	// With validator disabled, we should not get a "blocked" error.
	if err != nil && strings.Contains(err.Error(), "blocked by sandbox validator") {
		t.Errorf("validator is disabled, should not block: %v", err)
	}
}

// TestBadUSBValidate_ReturnsCritical verifies that badusb_validate returns
// structured JSON with SeverityCritical for a payload with rm -rf /.
func TestBadUSBValidate_ReturnsCritical(t *testing.T) {
	criticalScript := "DELAY 500\nSTRING rm -rf /\nENTER\n"

	f := testmocks.NewMockFlipper(t,
		testmocks.WithFlipperHandler("storage", flippermock.Handler(func(args []string) string {
			return criticalScript
		})),
	)

	deps := &Deps{
		Flipper: f,
		Config:  badUSBMakeCfg(false, nil),
	}

	spec, ok := Get("badusb_validate")
	if !ok {
		t.Fatal("badusb_validate not registered")
	}

	result, err := spec.Handler(context.Background(), deps, map[string]any{"file": "/ext/badusb/evil.txt"})
	if err != nil {
		t.Fatalf("badusb_validate returned unexpected error: %v", err)
	}
	// Result should be JSON. SeverityCritical is value 2 — check for the numeric representation.
	if !strings.Contains(result, `"Severity":2`) {
		t.Errorf("badusb_validate result should contain Severity:2 (critical), got: %s", result)
	}
	if !strings.Contains(result, "rm_rf_root") {
		t.Errorf("badusb_validate result should contain rm_rf_root finding, got: %s", result)
	}
}
