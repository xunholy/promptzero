// Package validator scans BadUSB/DuckyScript payloads for patterns that
// the operator would want to see before the Flipper types them on a real
// target. The intent is not to *block* payloads (PromptZero is a pentest
// tool and the full keyboard is the point) but to surface what they do,
// so the risk gate can ask an informed question.
//
// Severity ladder:
//   - Critical — irreversible, destructive, or unambiguously malicious
//     (rm -rf /, reverse shells, defender disable).
//   - Warn     — persistence, elevation, sensitive APIs that need intent.
//   - Info     — benign but notable (long typing runs, REM obfuscation).
//
// Findings are line-keyed so the /debug and audit output can point the
// operator at the exact DuckyScript statement that tripped the rule.
package validator

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// Severity is the three-tier classification used by the pre-flight gate.
type Severity int

const (
	// SeverityInfo is informational — recorded but does not affect gating.
	SeverityInfo Severity = iota
	// SeverityWarn is a suspicious pattern that the operator should see.
	SeverityWarn
	// SeverityCritical is a destructive or unambiguously-malicious signal.
	SeverityCritical
)

// String returns the human-friendly label (lowercased).
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// Finding is one rule hit inside a payload.
type Finding struct {
	Severity Severity
	Rule     string // short rule id: "rm_rf_root", "reverse_shell", etc.
	Message  string // human-facing one-liner
	Line     int    // 1-based line number in the source payload
	Excerpt  string // the offending line, trimmed, possibly truncated
}

// Report is the full validation result. The top-level Severity is the
// highest severity across Findings; an empty report is SeverityInfo.
type Report struct {
	Name     string
	Severity Severity
	Findings []Finding
}

// Has returns true if the report contains at least one finding >= sev.
func (r Report) Has(sev Severity) bool {
	for _, f := range r.Findings {
		if f.Severity >= sev {
			return true
		}
	}
	return false
}

// rule is a compiled detection. When pattern matches, a Finding at
// severity is emitted. Rules are ordered by specificity so the first
// matching rule on a line wins — this keeps the report noise-free for
// common cases like "STRING rm -rf /" where multiple rules could fire.
type rule struct {
	id       string
	pattern  *regexp.Regexp
	severity Severity
	message  string
}

var rules = []rule{
	// Destructive filesystem operations that can't be rolled back.
	{"rm_rf_root", regexp.MustCompile(`(?i)\brm\s+-rf?\s+/(?:\s|$)`), SeverityCritical,
		"rm -rf /  — wipes the target filesystem"},
	{"rm_rf_home", regexp.MustCompile(`(?i)\brm\s+-rf?\s+~`), SeverityCritical,
		"rm -rf ~  — wipes the user's home directory"},
	{"format_drive", regexp.MustCompile(`(?i)\bformat\s+[a-z]:\s*/`), SeverityCritical,
		"format C: style drive format"},
	{"diskpart_clean", regexp.MustCompile(`(?i)\bdiskpart\b.*\bclean\b`), SeverityCritical,
		"diskpart clean  — destroys partition tables"},
	{"mkfs_root", regexp.MustCompile(`(?i)\bmkfs\.\w+\s+/dev/sda\b`), SeverityCritical,
		"mkfs on /dev/sda  — reformats the primary disk"},

	// Reverse shells (several common forms).
	{"revshell_bash", regexp.MustCompile(`(?i)bash\s+-i\s*>\s*&\s*/dev/tcp/`), SeverityCritical,
		"bash reverse shell via /dev/tcp"},
	{"revshell_nc", regexp.MustCompile(`(?i)\bnc(?:at)?\b[^;|&]*\s-e\s+(?:/bin/|/usr/bin/|sh\b|bash\b|zsh\b|cmd\b|powershell\b)`), SeverityCritical,
		"netcat reverse shell (nc -e)"},
	{"revshell_python", regexp.MustCompile(`(?i)python[23]?\s+-c\s+["'].*socket\..*connect\(`), SeverityCritical,
		"python reverse shell (socket.connect)"},
	{"revshell_powershell", regexp.MustCompile(`(?i)powershell.*-(?:nop|noni|w\s+hidden).*(?:iex|invoke-expression).*(?:downloadstring|webclient)`), SeverityCritical,
		"PowerShell download-and-exec pattern"},

	// Persistence mechanisms.
	{"persist_runkey", regexp.MustCompile(`(?i)reg\s+add\s+.*\\run\b`), SeverityWarn,
		"registry Run key — persistence on boot"},
	{"persist_launchd", regexp.MustCompile(`(?i)launchctl\s+load\s+.*/Library/LaunchAgents/`), SeverityWarn,
		"launchd persistence via LaunchAgent"},
	{"persist_cron", regexp.MustCompile(`(?i)(?:crontab\s+-\b|echo\s+.*\|\s*crontab)`), SeverityWarn,
		"cron persistence"},
	{"persist_schtasks", regexp.MustCompile(`(?i)schtasks\s+/create\b`), SeverityWarn,
		"Windows scheduled task persistence"},
	{"persist_systemd", regexp.MustCompile(`(?i)systemctl\s+enable\s+`), SeverityWarn,
		"systemd service enable — persistence on boot"},

	// Defense evasion.
	{"disable_defender", regexp.MustCompile(`(?i)Set-MpPreference.*DisableRealtimeMonitoring\s+\$?true`), SeverityCritical,
		"Windows Defender real-time monitoring disabled"},
	{"disable_firewall_win", regexp.MustCompile(`(?i)netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off`), SeverityCritical,
		"Windows firewall turned off (all profiles)"},
	{"disable_gatekeeper", regexp.MustCompile(`(?i)spctl\s+--master-disable`), SeverityCritical,
		"macOS Gatekeeper disabled"},
	{"disable_sip", regexp.MustCompile(`(?i)csrutil\s+disable`), SeverityCritical,
		"macOS SIP disabled"},

	// Elevation attempts.
	{"elevate_uac", regexp.MustCompile(`(?i)Start-Process.*-Verb\s+RunAs`), SeverityWarn,
		"UAC elevation prompt (Start-Process -Verb RunAs)"},
	{"elevate_sudo_nopass", regexp.MustCompile(`(?i)\bsudo\s+-S\b.*echo\s+['"][^'"]+['"]`), SeverityWarn,
		"sudo with piped password — credential exposure"},

	// Exfiltration / sensitive device access.
	{"clipboard_read_win", regexp.MustCompile(`(?i)Get-Clipboard\b`), SeverityWarn,
		"reads clipboard contents"},
	{"camera_access", regexp.MustCompile(`(?i)(imagesnap|ffmpeg\s+-f\s+(?:avfoundation|v4l2))`), SeverityWarn,
		"camera/webcam capture"},
	{"download_exec_curl", regexp.MustCompile(`(?i)(?:curl|wget)\s+(?:-[a-zA-Z]+\s+)*https?://[^\s|;]+.*\|\s*(?:bash|sh|zsh|python)`), SeverityCritical,
		"download-and-pipe-to-shell"},
	{"iwr_iex", regexp.MustCompile(`(?i)(?:iwr|invoke-webrequest).*\|.*iex\b`), SeverityCritical,
		"PowerShell iwr | iex  — download-and-exec"},
	{"ssh_keydump", regexp.MustCompile(`(?i)(?:cat|type)\s+.*\.ssh/(?:id_rsa|id_ed25519)\b`), SeverityWarn,
		"reads SSH private key"},
}

// Validate parses a DuckyScript payload and returns the Report. Pass the
// payload filename (for display) and the raw content. Callers should
// have already Storage-Read'd the file off the Flipper.
func Validate(name, src string) Report {
	rep := Report{Name: name}

	sc := bufio.NewScanner(strings.NewReader(src))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	stringBytes := 0

	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		// DuckyScript line types that actually type keystrokes. We only
		// scan the payload body (after the first token) because regex
		// matches like "rm -rf /" would fire on a REM comment too —
		// comments are noise, not risk.
		head, rest := splitHead(trimmed)
		if head == "REM" {
			continue
		}
		if head == "STRING" || head == "STRINGLN" || head == "STRING_DELAY" || head == "" {
			stringBytes += len(rest)
		}

		scanLine := trimmed
		if head == "STRING" || head == "STRINGLN" {
			scanLine = rest
		}

		for _, r := range rules {
			if r.pattern.MatchString(scanLine) {
				rep.Findings = append(rep.Findings, Finding{
					Severity: r.severity,
					Rule:     r.id,
					Message:  r.message,
					Line:     lineNo,
					Excerpt:  truncate(trimmed, 120),
				})
				break // one finding per line, highest-priority rule wins
			}
		}
	}

	// Long typing runs aren't inherently malicious but do warrant a
	// heads-up — BadUSB typing at 25ms/key means a 5k-byte payload takes
	// ~2 minutes of the target ignoring the keyboard. Note-only.
	if stringBytes > 4096 {
		rep.Findings = append(rep.Findings, Finding{
			Severity: SeverityInfo,
			Rule:     "long_typing",
			Message:  fmt.Sprintf("long typing run (%d STRING bytes) — expect multi-minute execution", stringBytes),
			Line:     0,
		})
	}

	for _, f := range rep.Findings {
		if f.Severity > rep.Severity {
			rep.Severity = f.Severity
		}
	}
	return rep
}

// splitHead returns the first whitespace-delimited token (upper-cased)
// and the rest of the line with leading whitespace stripped. For unknown
// or lowercase first tokens the head comes back empty so the full line is
// scanned.
func splitHead(line string) (head, rest string) {
	idx := strings.IndexAny(line, " \t")
	if idx < 0 {
		return strings.ToUpper(line), ""
	}
	token := line[:idx]
	if token != strings.ToUpper(token) {
		return "", line
	}
	return token, strings.TrimLeft(line[idx:], " \t")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RenderText formats a Report as the human-readable block shown in REPL
// output and the risk gate prompt. Empty reports render "no findings".
func (r Report) RenderText() string {
	if len(r.Findings) == 0 {
		return fmt.Sprintf("validator: %s — no findings\n", r.Name)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "validator: %s — %s (%d finding%s)\n", r.Name, r.Severity.String(), len(r.Findings), plural(len(r.Findings)))
	for _, f := range r.Findings {
		if f.Line > 0 {
			fmt.Fprintf(&b, "  [%s] line %d: %s\n", f.Severity.String(), f.Line, f.Message)
			if f.Excerpt != "" {
				fmt.Fprintf(&b, "      %s\n", f.Excerpt)
			}
		} else {
			fmt.Fprintf(&b, "  [%s] %s\n", f.Severity.String(), f.Message)
		}
	}
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
