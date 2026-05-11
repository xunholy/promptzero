package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
)

// marauder_handoff_hashcat closes the missing-link in the WiFi attack
// chain identified by the hardware-ecosystem reviewer: from a captured
// PMKID pcap to a ready-to-run hashcat command. Pre-v0.20.0 the
// operator had to manually call hcxpcapngtool, format the .hc22000 file,
// look up the right hashcat mode (22000), and assemble the wordlist
// path. This tool does all of that and prints the exact CLI the
// operator can paste into a terminal.
//
// The actual cracking still runs on the operator's machine — PromptZero
// does not ship with hashcat or hcxtools (size + license + reasonable
// scope). When hcxpcapngtool is missing the tool prints the standard
// `apt install hcxtools` / `brew install hcxtools` hint plus the
// command the operator should run after installing.

//nolint:gochecknoinits
func init() {
	Register(Spec{
		Name: "marauder_handoff_hashcat",
		Description: "Convert a PMKID pcap (typically from wifi_sniff_pmkid pulled off the Marauder SD card) " +
			"to hashcat -m 22000 .hc22000 format and emit a ready-to-run hashcat command line. " +
			"Requires hcxpcapngtool on PATH (apt install hcxtools / brew install hcxtools); when " +
			"absent the tool prints the install hint and the eventual command. Pure host-side " +
			"work — no RF, no Flipper, no Marauder writes.",
		Schema: json.RawMessage(`{"type":"object","properties":{
			"pcap_path":{"type":"string","description":"Local filesystem path to the captured pcap (typically pulled from /ext/marauder/pcaps/ on the Marauder SD)"},
			"essid":{"type":"string","description":"Optional ESSID filter — restrict output to handshakes for this network"},
			"wordlist":{"type":"string","description":"Wordlist path for the eventual hashcat command (default: /usr/share/wordlists/rockyou.txt)"},
			"output_dir":{"type":"string","description":"Where to write the .hc22000 file. Defaults to a TempDir."}
		},"required":["pcap_path"]}`),
		Required:  []string{"pcap_path"},
		Risk:      risk.Medium,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler:   marauderHandoffHashcatHandler,
	})
}

func marauderHandoffHashcatHandler(ctx context.Context, _ *Deps, args map[string]any) (string, error) {
	pcapPath := strings.TrimSpace(str(args, "pcap_path"))
	if pcapPath == "" {
		return "", fmt.Errorf("marauder_handoff_hashcat: pcap_path is required")
	}
	absPcap, err := filepath.Abs(pcapPath)
	if err != nil {
		return "", fmt.Errorf("marauder_handoff_hashcat: resolve pcap_path: %w", err)
	}
	if _, err := os.Stat(absPcap); err != nil {
		return "", fmt.Errorf("marauder_handoff_hashcat: pcap not found at %s: %w", absPcap, err)
	}

	wordlist := strings.TrimSpace(str(args, "wordlist"))
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/rockyou.txt"
	}

	outDir := strings.TrimSpace(str(args, "output_dir"))
	if outDir == "" {
		outDir, err = os.MkdirTemp("", "promptzero-hc22000-*")
		if err != nil {
			return "", fmt.Errorf("marauder_handoff_hashcat: create temp output dir: %w", err)
		}
	} else {
		// 0o700 matches the v0.124-v0.127 operator-data baseline: the
		// hc22000 output contains WPA handshake material crackable
		// offline into the target's password, so it must not be
		// world-readable. MkdirAll is a no-op for existing dirs, so
		// an operator who explicitly wants a shared output dir can
		// pre-create it themselves with the wider mode.
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			return "", fmt.Errorf("marauder_handoff_hashcat: create %s: %w", outDir, err)
		}
	}

	hc22000Path := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(absPcap), filepath.Ext(absPcap))+".hc22000")
	hashcatCmd := fmt.Sprintf("hashcat -m 22000 -a 0 %s %s", hc22000Path, wordlist)

	out := map[string]any{
		"pcap_path":       absPcap,
		"hc22000_path":    hc22000Path,
		"wordlist":        wordlist,
		"hashcat_mode":    22000,
		"hashcat_command": hashcatCmd,
		"hashcat_attack":  "dictionary (-a 0)",
	}

	// hcxpcapngtool is the canonical pcap → hc22000 converter from
	// hcxtools. When it's not on PATH, return the install hint so the
	// operator gets a complete recipe rather than an opaque "missing
	// dependency" error.
	tool, err := exec.LookPath("hcxpcapngtool")
	if err != nil {
		out["status"] = "tool_missing"
		out["install_hint"] = "Install hcxtools to enable conversion: " +
			"`apt install hcxtools` (Debian/Ubuntu/Kali) " +
			"or `brew install hcxtools` (macOS). " +
			"After install, run: hcxpcapngtool -o " + hc22000Path + " " + absPcap
		out["hashcat_command_after_install"] = hashcatCmd
		body, _ := json.Marshal(out)
		return string(body), nil
	}

	// Run the conversion. hcxpcapngtool exits 0 even when there are no
	// useful frames in the pcap, so we also inspect whether the output
	// file is non-empty to surface the practical "no PMKIDs found"
	// case to the operator.
	cmdArgs := []string{"-o", hc22000Path}
	if essid := strings.TrimSpace(str(args, "essid")); essid != "" {
		cmdArgs = append(cmdArgs, "--filtermode=2", "--essid="+essid)
	}
	cmdArgs = append(cmdArgs, absPcap)
	cmd := exec.CommandContext(ctx, tool, cmdArgs...) //nolint:gosec
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		out["status"] = "conversion_failed"
		out["hcxpcapngtool_stdout"] = stdout.String()
		out["hcxpcapngtool_stderr"] = stderr.String()
		out["hcxpcapngtool_err"] = err.Error()
		body, _ := json.Marshal(out)
		return string(body), fmt.Errorf("hcxpcapngtool failed: %w", err)
	}

	// Check that we actually produced something useful.
	info, err := os.Stat(hc22000Path)
	if err != nil || info.Size() == 0 {
		out["status"] = "no_handshakes_found"
		out["hcxpcapngtool_stdout"] = stdout.String()
		out["hcxpcapngtool_stderr"] = stderr.String()
		out["hint"] = "The pcap may not contain a complete PMKID/4-way handshake. Try wifi_sniff_pmkid with deauth=true to coerce reconnects."
		body, _ := json.Marshal(out)
		return string(body), nil
	}

	out["status"] = "ok"
	out["hc22000_size_bytes"] = info.Size()
	out["hcxpcapngtool_stdout"] = stdout.String()
	body, _ := json.Marshal(out)
	return string(body), nil
}
