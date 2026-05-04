package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMarauderHandoffHashcat_RequiresPcapPath locks the input
// validation contract.
func TestMarauderHandoffHashcat_RequiresPcapPath(t *testing.T) {
	if _, err := marauderHandoffHashcatHandler(context.Background(), nil, map[string]any{}); err == nil {
		t.Fatal("missing pcap_path should error")
	}
}

// TestMarauderHandoffHashcat_PcapNotFound surfaces a clear filesystem
// error rather than a downstream tool error when the input is bogus.
func TestMarauderHandoffHashcat_PcapNotFound(t *testing.T) {
	_, err := marauderHandoffHashcatHandler(context.Background(), nil, map[string]any{
		"pcap_path": "/nonexistent/path/capture.pcap",
	})
	if err == nil {
		t.Fatal("nonexistent pcap should error")
	}
	if !strings.Contains(err.Error(), "pcap not found") {
		t.Errorf("error should mention pcap not found; got: %v", err)
	}
}

// TestMarauderHandoffHashcat_AbsentTool covers the install-hint path:
// when hcxpcapngtool isn't on PATH, the tool returns an actionable
// install command and the eventual hashcat CLI rather than failing.
//
// We force the absent-tool branch by putting a fake empty PATH for
// the duration of the call. (LookPath consults $PATH, so an empty
// PATH guarantees lookup failure regardless of the host's actual
// installation state — making the test deterministic across CI
// environments that may or may not have hcxtools available.)
func TestMarauderHandoffHashcat_AbsentTool(t *testing.T) {
	// Stage a tiny fake pcap on disk — content doesn't matter; the
	// handler short-circuits at LookPath before it tries to read.
	dir := t.TempDir()
	pcap := filepath.Join(dir, "test.pcap")
	if err := os.WriteFile(pcap, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer t.Setenv("PATH", origPath)

	res, err := marauderHandoffHashcatHandler(context.Background(), nil, map[string]any{
		"pcap_path":  pcap,
		"output_dir": dir,
	})
	if err != nil {
		t.Fatalf("absent tool path should not error; got %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(res), &parsed); err != nil {
		t.Fatalf("response should be JSON: %v\n%s", err, res)
	}
	if parsed["status"] != "tool_missing" {
		t.Errorf("status = %v, want tool_missing", parsed["status"])
	}
	hint, _ := parsed["install_hint"].(string)
	if !strings.Contains(hint, "hcxtools") {
		t.Errorf("install hint should name hcxtools; got: %s", hint)
	}
	if !strings.Contains(hint, "apt install") || !strings.Contains(hint, "brew install") {
		t.Errorf("install hint should cover both Linux and macOS; got: %s", hint)
	}
	cmd, _ := parsed["hashcat_command_after_install"].(string)
	if !strings.Contains(cmd, "hashcat -m 22000") {
		t.Errorf("hashcat command should be the canonical -m 22000 form; got: %s", cmd)
	}
}

// TestMarauderHandoffHashcat_AbsentTool_DefaultWordlist checks the
// default wordlist path is sensible (rockyou is the de-facto WPA
// dictionary; operators with their own can override).
func TestMarauderHandoffHashcat_AbsentTool_DefaultWordlist(t *testing.T) {
	dir := t.TempDir()
	pcap := filepath.Join(dir, "x.pcap")
	if err := os.WriteFile(pcap, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")

	res, err := marauderHandoffHashcatHandler(context.Background(), nil, map[string]any{
		"pcap_path": pcap,
	})
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	_ = json.Unmarshal([]byte(res), &parsed)
	if wl, _ := parsed["wordlist"].(string); wl != "/usr/share/wordlists/rockyou.txt" {
		t.Errorf("default wordlist = %q", wl)
	}
}
