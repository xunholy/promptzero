package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/validator"
)

// runBadUSBValidator reads the script off the Flipper SD card and runs it
// through the BadUSB sandbox validator. Returns the Report or an error if
// the file can't be read. Mirrors agent.validateBadUSB with Deps substituted
// for the Agent receiver.
//
// The Enabled *bool is tri-state: nil = default on, false = explicit off.
// When the validator is disabled an empty info-severity report is returned
// (no findings, no block). This ensures the pre-flight gate is a no-op when
// the operator explicitly opts out — the BadUSBRun still proceeds.
func runBadUSBValidator(d *Deps, path string) (validator.Report, error) {
	if path == "" {
		return validator.Report{}, fmt.Errorf("path required")
	}
	if d.Config != nil {
		if en := d.Config.Validator.BadUSB.Enabled; en != nil && !*en {
			return validator.Report{Name: path}, nil
		}
	}
	raw, err := d.Flipper.StorageRead(path)
	if err != nil {
		return validator.Report{}, fmt.Errorf("storage read %s: %w", path, err)
	}
	return validator.Validate(path, raw), nil
}

func init() {
	// badusb_run includes the pre-flight validator gate (§F.2). This gate was
	// previously absent from MCP mode — registering via the registry silently
	// adds it, which is a security improvement for MCP clients.
	Register(Spec{
		Name: "badusb_run",
		Description: "Execute a BadUSB/Rubber Ducky script. The Flipper acts as a USB keyboard and types commands on the connected computer. The pre-flight validator runs before execution; critical findings are blocked unless allow_critical is set in config.\n\nExamples:\n" +
			`- {"file":"/ext/badusb/demo.txt"}  — execute a generated or saved DuckyScript payload`,
		Schema:    json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to .txt BadUSB script on SD card"}}}`),
		Required:  []string{"file"},
		Risk:      risk.High,
		Group:     GroupFlipperBadUSB,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "file")
			// Fail closed: the pre-flight validator is a security control, so
			// if it cannot run (e.g. the script can't be read off the SD card)
			// we refuse rather than execute an unvalidated payload. An operator
			// who deliberately opts out via validator.badusb.enabled=false gets
			// no error from runBadUSBValidator and still proceeds.
			rep, err := runBadUSBValidator(d, path)
			if err != nil {
				return "", fmt.Errorf("badusb_run blocked: pre-flight validator could not run: %w", err)
			}
			if rep.Severity == validator.SeverityCritical {
				if d.Config == nil || !d.Config.Validator.BadUSB.AllowCritical {
					return "", fmt.Errorf("badusb_run blocked by sandbox validator:\n%s\nSet validator.badusb.allow_critical=true to override, or call badusb_validate to triage", rep.RenderText())
				}
			}
			if rep.Severity == validator.SeverityWarn {
				if d.Config != nil && d.Config.Validator.BadUSB.WarnAction == "block" {
					return "", fmt.Errorf("badusb_run blocked (warn-action=block):\n%s", rep.RenderText())
				}
			}
			return d.Flipper.BadUSBRun(path)
		},
	})

	Register(Spec{
		Name:        "badusb_validate",
		Description: "Dry-run a BadUSB/DuckyScript payload through the pre-flight validator without executing it. Flags rm -rf /, reverse shells, persistence, defense-disable, and other dangerous patterns. Returns structured JSON with Severity and Findings.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to .txt BadUSB script on SD card"}}}`),
		Required:    []string{"file"},
		Risk:        risk.Low,
		Group:       GroupFlipperBadUSB,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "file")
			rep, err := runBadUSBValidator(d, path)
			if err != nil {
				return "", err
			}
			out, _ := json.Marshal(rep)
			return string(out), nil
		},
	})

	// v0.22.0 — BadKB / BadBT: same DuckyScript over BLE HID instead
	// of USB HID. Available on Momentum, Unleashed, RogueMaster (the
	// stock firmware lacks the BadBT app). Same validator gate as
	// badusb_run because the payload risk is identical — only the
	// transport changes. The "thin wrapper" framing from the
	// 2026-05-06 ecosystem review: shares everything except the
	// final loader call.
	Register(Spec{
		Name: "badkb_run",
		Description: "Execute a BadUSB/Rubber Ducky script over BLE HID (BadBT/BadKB app). Requires Momentum, Unleashed, or RogueMaster firmware — the stock OFW does not ship the BadBT app. Same DuckyScript syntax and pre-flight validator as badusb_run; just routes the keystrokes over Bluetooth Low Energy instead of USB. Pair the Flipper to the target host first via the BLE settings menu.\n\nExamples:\n" +
			`- {"file":"/ext/badusb/demo.txt"}  — execute the same payload over BLE`,
		Schema:    json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to .txt BadUSB/DuckyScript on SD card"}}}`),
		Required:  []string{"file"},
		Risk:      risk.High,
		Group:     GroupFlipperBadUSB,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "file")
			// Fail closed on validator error — same security rationale as
			// badusb_run above; the payload risk is identical, only the
			// transport (BLE HID) differs.
			rep, err := runBadUSBValidator(d, path)
			if err != nil {
				return "", fmt.Errorf("badkb_run blocked: pre-flight validator could not run: %w", err)
			}
			if rep.Severity == validator.SeverityCritical {
				if d.Config == nil || !d.Config.Validator.BadUSB.AllowCritical {
					return "", fmt.Errorf("badkb_run blocked by sandbox validator:\n%s\nSet validator.badusb.allow_critical=true to override, or call badusb_validate to triage", rep.RenderText())
				}
			}
			if rep.Severity == validator.SeverityWarn {
				if d.Config != nil && d.Config.Validator.BadUSB.WarnAction == "block" {
					return "", fmt.Errorf("badkb_run blocked (warn-action=block):\n%s", rep.RenderText())
				}
			}
			// Open the BadBT app via the loader, passing the script
			// path as the launch argument (same convention as the
			// stock loader_open path that other Flipper apps follow).
			return d.Flipper.LoaderOpen("BadBT", path)
		},
	})
}
