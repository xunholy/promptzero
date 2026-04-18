package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
)

// --- First-run & init -----------------------------------------------------

// isFirstRun reports whether this invocation has no config anywhere and no
// API key env var, so we should show the onboarding hint instead of
// attempting to connect.
func isFirstRun(cfgPath string) bool {
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return false
	}
	if _, err := os.Stat(cfgPath); err == nil {
		return false
	}
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(home, ".promptzero", "config.yaml")); err == nil {
			return false
		}
	}
	return true
}

func printFirstRunHint() {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Welcome. A few steps to get started:")
	fmt.Fprintln(os.Stderr, "    1. Run `promptzero --init` to scaffold ~/.promptzero/config.yaml")
	fmt.Fprintln(os.Stderr, "    2. Set ANTHROPIC_API_KEY (required) — export it or add api_key to the config")
	fmt.Fprintln(os.Stderr, "    3. Plug in your Flipper Zero (USB Virtual COM Port mode)")
	fmt.Fprintln(os.Stderr, "    4. Relaunch `promptzero` and type /help for commands")
	fmt.Fprintln(os.Stderr)
}

// runInit scaffolds ~/.promptzero/config.yaml from the on-disk example
// (preferred, so edits stay in sync) or the embedded template, then opens
// $EDITOR if set. Refuses to overwrite an existing config.
func runInit() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolving home dir: %w", err)
	}
	dir := filepath.Join(home, ".promptzero")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	target := filepath.Join(dir, "config.yaml")
	if _, err := os.Stat(target); err == nil {
		fmt.Fprintf(os.Stderr, "  %s%s already exists — refusing to overwrite%s\n", yellow, target, reset)
		return nil
	}
	data, err := os.ReadFile("config.example.yaml")
	if err != nil {
		data = []byte(configTemplate)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", target, err)
	}
	fmt.Fprintf(os.Stderr, "  %s●%s wrote %s\n", green, reset, target)
	if editor := os.Getenv("EDITOR"); editor != "" {
		// Split on whitespace so values like "code --wait" or "nvim -p" work.
		parts := append(strings.Fields(editor), target)
		cmd := exec.Command(parts[0], parts[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  %s%s failed: %v%s\n", yellow, editor, err, reset)
		}
	}
	return nil
}

// --- Risk threshold resolution -------------------------------------------

// resolveConfirmRisk collapses the config value, the --confirm-risk flag,
// and --yolo into a (threshold, enabled) pair. Flags win over config.
// Returns a warning error (not fatal) when the user supplied an unknown
// level; the caller falls back to the default.
func resolveConfirmRisk(cfgValue, flagValue string, yolo bool) (risk.Level, bool, error) {
	raw := strings.ToLower(strings.TrimSpace(cfgValue))
	if flagValue != "" {
		raw = strings.ToLower(strings.TrimSpace(flagValue))
	}
	if yolo {
		raw = "none"
	}
	switch raw {
	case "":
		return risk.High, true, nil
	case "none":
		return risk.High, false, nil
	case "low":
		return risk.Low, true, nil
	case "medium":
		return risk.Medium, true, nil
	case "high":
		return risk.High, true, nil
	case "critical":
		return risk.Critical, true, nil
	default:
		return risk.High, true, fmt.Errorf("unknown confirm_risk %q, using high", raw)
	}
}
