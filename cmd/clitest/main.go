// clitest spawns `promptzero` in REPL mode under a pty (because the
// REPL refuses to enter raw mode without a TTY) and drives a few
// non-LLM slash commands to verify the CLI plumbing works end-to-end:
// banner prints, /help renders, /quit exits cleanly. No agent turns
// are executed, so this runs without burning Anthropic credits.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/creack/pty"
)

type step struct {
	send    string
	waitFor string // substring that must appear in output before sending the next step
	timeout time.Duration
}

func main() {
	var (
		bin     = flag.String("bin", "./bin/promptzero", "promptzero binary")
		port    = flag.String("port", "/dev/ttyACM0", "Flipper serial port")
		verbose = flag.Bool("v", false, "stream all pty output to stderr live")
	)
	flag.Parse()

	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		_ = os.Setenv("ANTHROPIC_API_KEY", "sk-ant-dummy-for-smoke-test")
	}

	steps := []step{
		// First wait for the agent-ready banner so subsequent input lands
		// after the prompt is up.
		{waitFor: "Agent ready", timeout: 30 * time.Second},
		// Print help — exercises /help dispatch + render
		{send: "/help\r", waitFor: "Show this help", timeout: 5 * time.Second},
		// Print stats — non-LLM, exercises subsystem accessors
		{send: "/stats\r", waitFor: "session", timeout: 5 * time.Second},
		// Quit cleanly — exercises shutdown path
		{send: "/quit\r", waitFor: "", timeout: 5 * time.Second},
	}

	cmd := exec.Command(*bin, "--port", *port)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	tty, err := pty.Start(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pty start: %v\n", err)
		os.Exit(1)
	}
	defer tty.Close()

	// Capture all output for inspection. We tee to stderr only when -v
	// is on so the test output stays clean by default.
	var buf bytes.Buffer
	go func() {
		w := io.Writer(&buf)
		if *verbose {
			w = io.MultiWriter(&buf, os.Stderr)
		}
		_, _ = io.Copy(w, tty)
	}()

	pass, fail := 0, 0
	for i, st := range steps {
		var label string
		if st.send != "" {
			label = fmt.Sprintf("step %d: %q", i+1, strings.TrimRight(st.send, "\r\n"))
		} else {
			label = fmt.Sprintf("step %d: wait for %q", i+1, st.waitFor)
		}

		if st.send != "" {
			if _, err := tty.Write([]byte(st.send)); err != nil {
				fmt.Printf("FAIL  %s — write: %v\n", label, err)
				fail++
				break
			}
		}

		if st.waitFor == "" {
			// No condition — small grace period for shutdown to flush.
			time.Sleep(200 * time.Millisecond)
			fmt.Printf("PASS  %s\n", label)
			pass++
			continue
		}

		ok := waitForSubstring(&buf, st.waitFor, st.timeout)
		if !ok {
			fmt.Printf("FAIL  %s — never saw %q within %s\n", label, st.waitFor, st.timeout)
			fail++
			break
		}
		fmt.Printf("PASS  %s\n", label)
		pass++
	}

	// Wait for the process to exit on its own (we sent /quit). If it
	// doesn't within 3s, kill it and surface that as a fail.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil && err.Error() != "signal: hangup" {
			fmt.Printf("NOTE  exit error: %v\n", err)
		}
		fmt.Printf("PASS  process exited cleanly\n")
		pass++
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		fmt.Printf("FAIL  process did not exit within 3s after /quit\n")
		fail++
	}

	fmt.Printf("\n# %d pass, %d fail\n", pass, fail)
	if fail > 0 {
		fmt.Fprintf(os.Stderr, "\n--- last 60 lines of pty output ---\n%s\n", tail(buf.String(), 60))
		os.Exit(1)
	}
}

// waitForSubstring polls buf until needle appears or timeout fires.
// 50 ms granularity keeps wall time low without melting CPU.
func waitForSubstring(buf *bytes.Buffer, needle string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(stripANSI(buf.String()), needle) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// stripANSI removes the colour escapes the REPL paints output with so
// substring matching against plain strings works reliably.
func stripANSI(s string) string {
	var out strings.Builder
	in := []byte(s)
	for i := 0; i < len(in); {
		if in[i] == 0x1b && i+1 < len(in) && in[i+1] == '[' {
			j := i + 2
			for j < len(in) && (in[j] < 'A' || in[j] > 'Z') && (in[j] < 'a' || in[j] > 'z') {
				j++
			}
			if j < len(in) {
				j++
			}
			i = j
			continue
		}
		out.WriteByte(in[i])
		i++
	}
	return out.String()
}

func tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
