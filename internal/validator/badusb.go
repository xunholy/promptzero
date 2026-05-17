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

	"github.com/xunholy/promptzero/internal/clisafe"
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
// severity is emitted. When a single line matches multiple rules the
// highest-severity rule wins — keeping the report at one finding per
// line (so dozens of overlapping regexes don't flood the output)
// while ensuring a Critical pattern never silently demotes to a Warn
// because the Warn rule happens to appear earlier in the slice. The
// pre-v0.149 form was "first match wins", which demoted lines that
// combined a Warn-tier pattern (e.g. registry Run key persistence)
// with a Critical-tier pattern (e.g. powershell -EncodedCommand) to
// Warn — the line was effectively under-reported.
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
	{"dd_block_wipe", regexp.MustCompile(`(?i)\bdd\s+if=/dev/(?:zero|urandom|random)\s+of=/dev/(?:sda|nvme\d+n\d+|hda|mmcblk\d+)\b`), SeverityCritical,
		"dd to a block device  — overwrites the primary disk"},
	{"fork_bomb", regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`), SeverityCritical,
		"shell fork bomb  — exhausts process table"},
	{"chmod_777_root", regexp.MustCompile(`(?i)\bchmod\s+(?:-R\s+)?(?:0?7){3}\s+(?:-R\s+)?/(?:\s|$)`), SeverityCritical,
		"chmod 777 /  — opens every file on the system"},

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
	// LOLBAS download/execute primitives — well-documented attack techniques
	// that don't require dropping a binary; built-in Windows tools fetch the
	// payload directly. See https://lolbas-project.github.io/.
	{"certutil_download", regexp.MustCompile(`(?i)\bcertutil\b[^|;\n]*-urlcache\b[^|;\n]*-f\b[^|;\n]*https?://`), SeverityCritical,
		"certutil -urlcache -f  — LOLBAS download primitive"},
	{"bitsadmin_download", regexp.MustCompile(`(?i)\bbitsadmin\b[^|;\n]*/transfer\b[^|;\n]*https?://`), SeverityCritical,
		"bitsadmin /transfer  — LOLBAS download primitive"},
	{"mshta_remote", regexp.MustCompile(`(?i)\bmshta\b\s+(?:["']?https?://|vbscript:)`), SeverityCritical,
		"mshta with remote URL or vbscript:  — LOLBAS script-host exec"},
	{"regsvr32_squiblydoo", regexp.MustCompile(`(?i)\bregsvr32\b[^|;\n]*/i:https?://`), SeverityCritical,
		"regsvr32 /i:http... (Squiblydoo)  — LOLBAS scriptlet exec"},
	{"wmic_exec", regexp.MustCompile(`(?i)\bwmic\b[^|;\n]*\bprocess\b[^|;\n]*\bcall\s+create\b`), SeverityCritical,
		"wmic process call create  — lateral execution"},
	{"ssh_keydump", regexp.MustCompile(`(?i)(?:cat|type)\s+.*\.ssh/(?:id_rsa|id_ed25519)\b`), SeverityWarn,
		"reads SSH private key"},

	// Defense evasion — log clearing (T1070.001 / T1070.002). Common in
	// BadUSB to cover tracks before the operator unplugs.
	{"clear_eventlog_wevtutil", regexp.MustCompile(`(?i)\bwevtutil\b\s+cl\b`), SeverityCritical,
		"wevtutil cl  — clears Windows event logs (T1070.001)"},
	{"clear_eventlog_ps", regexp.MustCompile(`(?i)\bClear-EventLog\b`), SeverityCritical,
		"Clear-EventLog  — clears Windows event logs (T1070.001)"},

	// Obfuscation — PowerShell encoded commands (T1027 / T1059.001).
	// `powershell -enc <base64>` hides the actual command from
	// shoulder-surfing and basic string-grep telemetry.
	{"powershell_enc", regexp.MustCompile(`(?i)\bpowershell(?:\.exe)?\b[^|;\n]*\s-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand|ec)\s+[A-Za-z0-9+/=]{12,}`), SeverityCritical,
		"powershell -EncodedCommand  — base64-obfuscated payload (T1027/T1059.001)"},

	// Defense evasion — Linux firewall flush. Distinct from disabling
	// since `-F` is sometimes legitimate, but in a BadUSB context it
	// is almost always part of clearing the way for follow-on traffic.
	{"iptables_flush", regexp.MustCompile(`(?i)\biptables\b\s+(?:-F|--flush)\b`), SeverityWarn,
		"iptables -F  — flushes Linux firewall rules (T1562.004)"},
	{"ufw_disable", regexp.MustCompile(`(?i)\bufw\b\s+disable\b`), SeverityWarn,
		"ufw disable  — disables Linux firewall (T1562.004)"},

	// Credential dumping — Mimikatz module strings (T1003.001). Operators
	// using a launcher won't always type the exe name, but the function
	// names are extremely high-signal.
	{"mimikatz_logonpasswords", regexp.MustCompile(`(?i)\bsekurlsa::logonpasswords\b`), SeverityCritical,
		"mimikatz sekurlsa::logonpasswords  — LSASS credential dump (T1003.001)"},
	{"mimikatz_dcsync", regexp.MustCompile(`(?i)\blsadump::dcsync\b`), SeverityCritical,
		"mimikatz lsadump::dcsync  — domain credential extraction (T1003.006)"},

	// Credential dumping — Windows registry hive saves (T1003.002).
	// `reg save HKLM\SAM` exfils the SAM database; SYSTEM/SECURITY are
	// needed to decrypt the SAM offline (impacket-secretsdump etc.).
	{"reg_save_sam_hive", regexp.MustCompile(`(?i)\breg\s+save\s+HKLM\\(?:SAM|SYSTEM|SECURITY)\b`), SeverityCritical,
		"reg save HKLM\\<HIVE>  — registry hive dump for offline SAM cracking (T1003.002)"},

	// Account creation — local admin via `net user /add` followed by
	// `net localgroup administrators add` (T1136.001 Local Account).
	// Common in BadUSB to leave a backup login when malware persists.
	{"net_user_add", regexp.MustCompile(`(?i)\bnet\s+user\s+\S+\s+\S+\s+/add\b`), SeverityCritical,
		"net user <name> <password> /add  — local account creation (T1136.001)"},
	{"net_localgroup_admin", regexp.MustCompile(`(?i)\bnet\s+localgroup\s+administrators\b\s+\S+\s+/add\b`), SeverityCritical,
		"net localgroup administrators <name> /add  — privilege escalation (T1078.003)"},

	// SSH authorized_keys backdoor — `echo <pubkey> >> ~/.ssh/authorized_keys`
	// is the canonical Linux persistence trick (T1098.004).
	{"ssh_authorized_keys_append", regexp.MustCompile(`(?i)>>\s*\S*\.ssh/authorized_keys\b`), SeverityCritical,
		"appends to ~/.ssh/authorized_keys  — SSH backdoor (T1098.004)"},

	// /etc/sudoers modification via echo / cat / tee — operator implants
	// a NOPASSWD line for an attacker-controlled account (T1548.003).
	{"sudoers_nopasswd_append", regexp.MustCompile(`(?i)NOPASSWD\s*:\s*ALL\b`), SeverityCritical,
		"NOPASSWD:ALL line  — passwordless sudo elevation (T1548.003)"},
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

		// Walk every rule and pick the highest-severity match. A
		// single line emits at most one Finding (Critical > Warn >
		// Info), so the report stays one-finding-per-line — but a
		// Critical pattern can never be silently suppressed by a
		// Warn rule that happened to be checked first. Early-exit
		// once a Critical lands since nothing higher exists.
		var bestRule *rule
		for i := range rules {
			if rules[i].pattern.MatchString(scanLine) {
				if bestRule == nil || rules[i].severity > bestRule.severity {
					bestRule = &rules[i]
				}
				if bestRule.severity == SeverityCritical {
					break
				}
			}
		}
		if bestRule != nil {
			rep.Findings = append(rep.Findings, Finding{
				Severity: bestRule.severity,
				Rule:     bestRule.id,
				Message:  bestRule.message,
				Line:     lineNo,
				Excerpt:  truncate(trimmed, 120),
			})
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

// truncate is a thin wrapper over clisafe.TruncateWithEllipsis kept
// for back-compat with the existing call sites in this file. The
// shared helper centralises the UTF-8 walk-back so the same fix lands
// across every truncating site (evilportal, badusb, future migration
// targets in agent / generate / report / audit).
func truncate(s string, n int) string {
	return clisafe.TruncateWithEllipsis(s, n)
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
