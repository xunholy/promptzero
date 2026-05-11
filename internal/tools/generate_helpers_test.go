package tools

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/validator"
)

// generate_helpers_test.go covers the four pure helpers in
// generate.go plus the exitCode helper in fap_build.go that were
// 0%-tested. All shape operator-visible output that no other
// layer asserts against.

// TestGenDefaultPath pins the payload-type → SD-card path map
// the generator falls back to when the caller doesn't supply an
// explicit destination. A regression here would silently route
// generated files into the wrong directory (e.g. a generated
// .nfc going into /ext/subghz, where the NFC viewer wouldn't see
// it).
func TestGenDefaultPath(t *testing.T) {
	cases := map[string]string{
		"evil_portal":  "/ext/apps_data/evil_portal/index.html",
		"badusb":       "/ext/badusb/generated_payload.txt",
		"subghz":       "/ext/subghz/generated_signal.sub",
		"ir":           "/ext/infrared/generated_remote.ir",
		"nfc":          "/ext/nfc/generated_tag.nfc",
		"":             "", // unknown → empty
		"unknown_type": "",
		"NFC":          "", // case-sensitive match
		"badusb ":      "", // whitespace-sensitive
	}
	for in, want := range cases {
		if got := genDefaultPath(in); got != want {
			t.Errorf("genDefaultPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGenMapNFCType pins the scanner-string → DeviceType
// normalisation used by nfc_read_save. Case insensitive
// substring match; protocol-string variants ("Mifare Classic 1K",
// "MIFARE Ultralight EV1") all collapse to the canonical name.
// Unrecognised inputs fall through to "NFC" (the generic builder
// accepts any UID length).
func TestGenMapNFCType(t *testing.T) {
	cases := map[string]string{
		// NTAG family.
		"NTAG213":        "NTAG213",
		"ntag213":        "NTAG213",
		"NTAG215 (Read)": "NTAG215",
		"ntag216 v2":     "NTAG216",
		// Mifare family.
		"Mifare Ultralight EV1": "Mifare Ultralight",
		"ULTRALIGHT":            "Mifare Ultralight",
		"Mifare Classic 1K":     "Mifare Classic",
		"mifare classic":        "Mifare Classic",
		"Mifare DESFire EV1":    "Mifare DESFire",
		"DESFIRE":               "Mifare DESFire",
		"Mifare Plus X 4K":      "Mifare Plus",
		// Unrecognised → generic.
		"":         "NFC",
		"Unknown":  "NFC",
		"ISO15693": "NFC",
	}
	for in, want := range cases {
		if got := genMapNFCType(in); got != want {
			t.Errorf("genMapNFCType(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGenSanitizeFilename pins the UID-to-filename sanitiser:
// alphanumeric / underscore / dash pass through; everything else
// (slashes, spaces, control chars, non-ASCII) becomes `_`. Empty
// or all-stripped input → "unknown".
func TestGenSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		// Pass-through.
		"DEADBEEF":     "DEADBEEF",
		"deadbeef":     "deadbeef",
		"ab-cd_ef":     "ab-cd_ef",
		"DEAD_BEEF-42": "DEAD_BEEF-42",
		"1234567890":   "1234567890",
		// Replaced.
		"AA:BB:CC":    "AA_BB_CC",
		"AA/BB":       "AA_BB",
		"AA\\BB":      "AA_BB",
		"AA BB":       "AA_BB",
		"AA\nBB":      "AA_BB",
		"AA;rm -rf /": "AA_rm_-rf__",
		"日本語":         "___",
		// Empty / all-stripped.
		"":   "unknown",
		"//": "__",
		// "...": "___" — at least 1 non-stripped char isn't required
		// (the all-stripped check is `== ""` after sanitisation),
		// so "..." becomes "___" not "unknown".
		"...": "___",
	}
	for in, want := range cases {
		if got := genSanitizeFilename(in); got != want {
			t.Errorf("genSanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGenRenderValidatorReport pins the static-validator flatten
// the generate_payload tool surfaces back to the agent.
// Empty findings → one-line summary. Findings with Line > 0
// render "[severity] L<n> <rule>: <message>"; Line == 0 omits
// the L<n> prefix. Trailing newline trimmed.
func TestGenRenderValidatorReport(t *testing.T) {
	t.Run("no_findings", func(t *testing.T) {
		r := validator.Report{Severity: validator.SeverityInfo}
		got := genRenderValidatorReport(r)
		if got != "static validator: info (no findings)" {
			t.Errorf("no-findings render = %q", got)
		}
	})

	t.Run("findings_with_lines", func(t *testing.T) {
		r := validator.Report{
			Severity: validator.SeverityCritical,
			Findings: []validator.Finding{
				{Severity: validator.SeverityCritical, Rule: "rm_rf", Message: "destructive rm -rf /", Line: 5},
				{Severity: validator.SeverityWarn, Rule: "persist", Message: "registry persistence", Line: 12},
			},
		}
		got := genRenderValidatorReport(r)
		// Header.
		if !strings.HasPrefix(got, "static validator: critical — 2 finding(s)") {
			t.Errorf("missing header: %q", got)
		}
		// Per-finding lines with L<n> prefix.
		if !strings.Contains(got, "[critical] L5 rm_rf: destructive rm -rf /") {
			t.Errorf("missing finding 1: %q", got)
		}
		if !strings.Contains(got, "[warn] L12 persist: registry persistence") {
			t.Errorf("missing finding 2: %q", got)
		}
		// Trailing newline trimmed.
		if strings.HasSuffix(got, "\n") {
			t.Errorf("trailing newline not trimmed: %q", got)
		}
	})

	t.Run("finding_without_line_number", func(t *testing.T) {
		r := validator.Report{
			Severity: validator.SeverityWarn,
			Findings: []validator.Finding{
				{Severity: validator.SeverityWarn, Rule: "suspicious_url", Message: "external domain reference", Line: 0},
			},
		}
		got := genRenderValidatorReport(r)
		// Line == 0 → no L<n> prefix, just [sev] rule: msg.
		if !strings.Contains(got, "[warn] suspicious_url: external domain reference") {
			t.Errorf("Line=0 render wrong: %q", got)
		}
		// Must NOT contain "L0".
		if strings.Contains(got, "L0") {
			t.Errorf("Line=0 should not render L0: %q", got)
		}
	})
}

// TestExitCode pins the fap_build helper that probes a process's
// ExitCode safely. A nil ProcessState (cmd never ran) → -1
// sentinel. A real run with a successful exit → 0. The helper is
// used in error messages, so a regression here would silently
// report -1 for a successful build (mildly confusing).
func TestExitCode(t *testing.T) {
	t.Run("never_ran", func(t *testing.T) {
		cmd := exec.Command("/bin/true")
		// Don't call Run/Start — ProcessState is nil.
		if got := exitCode(cmd); got != -1 {
			t.Errorf("exitCode(never-ran) = %d, want -1", got)
		}
	})

	t.Run("zero_exit", func(t *testing.T) {
		cmd := exec.Command("/bin/true")
		if err := cmd.Run(); err != nil {
			t.Skipf("/bin/true unavailable: %v", err)
		}
		if got := exitCode(cmd); got != 0 {
			t.Errorf("exitCode(/bin/true) = %d, want 0", got)
		}
	})

	t.Run("nonzero_exit", func(t *testing.T) {
		cmd := exec.Command("/bin/false")
		// Run returns an *ExitError on non-zero exit — that's expected.
		_ = cmd.Run()
		if got := exitCode(cmd); got != 1 {
			t.Errorf("exitCode(/bin/false) = %d, want 1", got)
		}
	})
}
