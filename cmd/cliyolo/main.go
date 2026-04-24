// cliyolo drives the promptzero REPL through a pty with a curated set of
// natural-language prompts to exercise every non-destructive Flipper
// subsystem. Uses --yolo so the agent doesn't pause for confirmations.
//
// Per-prompt protocol:
//  1. Send the prompt + Enter
//  2. Wait for output silence (no new bytes for `silenceWindow`) — that's
//     our heuristic for "agent finished its turn"
//  3. Snapshot the buffer slice that arrived since the last prompt
//  4. Apply pass/fail heuristics: a turn is a FAIL if the snapshot
//     contains "error:" or "failed" near the end, or empty after timeout
//
// Not destructive: every prompt was hand-picked to avoid RF transmit,
// emulation, write-to-tag, deauth, beacon spam, reboot, install, js_run,
// crypto_store_key. Storage round-trip writes/deletes its own canary
// file, mirroring the hwtest harness pattern.
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

type prompt struct {
	category string
	text     string
	// failOn is a substring that, if present in the response, marks the
	// prompt as FAIL. Default is "error:" (the agent's friendly error
	// rendering); per-prompt override for cases where the answer
	// legitimately mentions errors.
	failOn string
	// minBytes is the minimum response length to count as success.
	// Defaults to 1; a turn that produced zero bytes after the prompt
	// echoed back is suspicious.
	minBytes int
}

type result struct {
	prompt    prompt
	bytes     int
	dur       time.Duration
	pass      bool
	excerpt   string
	failCause string
}

func main() {
	var (
		bin           = flag.String("bin", "./bin/promptzero", "promptzero binary")
		port          = flag.String("port", "/dev/ttyACM0", "Flipper serial port")
		persona       = flag.String("persona", "default", "agent persona (built-ins: default, rf-recon, badge-cloner, hw-recon, physical-pentest, defender)")
		limit         = flag.Int("limit", 0, "if >0, only run the first N prompts (for smoke testing)")
		silenceWindow = flag.Duration("silence", 8*time.Second, "no-new-bytes window that marks turn completion")
		perPromptCap  = flag.Duration("cap", 120*time.Second, "max wall time per prompt before forcing the next one")
		showStream    = flag.Bool("v", false, "stream agent output live to stderr (verbose)")
	)
	flag.Parse()

	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		fmt.Fprintln(os.Stderr, "ANTHROPIC_API_KEY is not set in env")
		os.Exit(1)
	}

	prompts := buildPromptSet()
	if *limit > 0 && *limit < len(prompts) {
		prompts = prompts[:*limit]
	}

	cmd := exec.Command(*bin, "--yolo", "--persona", *persona, "--port", *port)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	tty, err := pty.Start(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pty start: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	defer tty.Close()

	// All output captured in a single ring; we slice off per-prompt deltas
	// using a moving offset.
	var ring bytes.Buffer
	go func() {
		w := io.Writer(&ring)
		if *showStream {
			w = io.MultiWriter(&ring, os.Stderr)
		}
		_, _ = io.Copy(w, tty)
	}()

	// Wait for the "Agent ready" banner so subsequent input lands after
	// the prompt is up.
	if !waitForSubstring(&ring, "Agent ready", 60*time.Second) {
		fmt.Fprintf(os.Stderr, "agent never reported ready within 60s\nbuffer:\n%s\n", ring.String())
		os.Exit(1)
	}
	// Settle pause to let the rest of the banner flush before we start
	// stuffing prompts.
	time.Sleep(800 * time.Millisecond)

	results := make([]result, 0, len(prompts))
	for i, p := range prompts {
		fmt.Printf("\n──── %d/%d (%s) ────\n", i+1, len(prompts), p.category)
		fmt.Printf("> %s\n", p.text)

		offset := ring.Len()
		start := time.Now()
		if _, err := tty.Write([]byte(p.text + "\r")); err != nil {
			results = append(results, result{prompt: p, pass: false, failCause: "pty write: " + err.Error()})
			continue
		}

		dur := waitForTurnComplete(&ring, *silenceWindow, *perPromptCap)
		full := ring.Bytes()[offset:]
		clean := stripANSI(string(full))
		summary := tail(clean, 12)
		bytesGrew := len(clean)

		failOn := p.failOn
		if failOn == "" {
			failOn = "error:"
		}
		minBytes := p.minBytes
		if minBytes == 0 {
			minBytes = 40 // arbitrary "got something back" floor
		}

		r := result{
			prompt:  p,
			bytes:   bytesGrew,
			dur:     dur,
			excerpt: summary,
		}
		switch {
		case bytesGrew < minBytes:
			r.pass = false
			r.failCause = fmt.Sprintf("response under %d bytes (%d)", minBytes, bytesGrew)
		case strings.Contains(strings.ToLower(clean), strings.ToLower(failOn)):
			r.pass = false
			r.failCause = "saw fail marker: " + failOn
		default:
			r.pass = true
		}

		marker := "PASS"
		if !r.pass {
			marker = "FAIL"
		}
		fmt.Printf("[%s %6s %5d bytes] %s\n",
			marker, dur.Round(100*time.Millisecond), bytesGrew, r.failCause)
		fmt.Printf("    tail: %s\n", strings.ReplaceAll(summary, "\n", " ⏎ "))
		results = append(results, r)

		_ = start
	}

	// Try to /quit cleanly.
	_, _ = tty.Write([]byte("/quit\r"))
	time.Sleep(2 * time.Second)

	pass, fail := 0, 0
	for _, r := range results {
		if r.pass {
			pass++
		} else {
			fail++
		}
	}

	fmt.Printf("\n────────────────────────────────────────\n")
	fmt.Printf("# %d pass, %d fail / %d total\n", pass, fail, len(results))
	fmt.Println()
	if fail > 0 {
		fmt.Println("FAILURES:")
		for i, r := range results {
			if r.pass {
				continue
			}
			fmt.Printf("  %d. %s — %s\n", i+1, r.prompt.text, r.failCause)
		}
		os.Exit(1)
	}
}

// buildPromptSet hand-picks 35 prompts spanning every non-destructive
// subsystem. Order matters: writes happen after reads so the SD baseline
// is preserved as long as possible.
func buildPromptSet() []prompt {
	return []prompt{
		// --- System info (5) ---
		{category: "system", text: "Get the Flipper device info."},
		{category: "system", text: "Show me the current battery and power info."},
		{category: "system", text: "List the apps installed on my Flipper."},
		{category: "system", text: "What's the current loader / running app state?"},
		{category: "system", text: "Show me the Bluetooth HCI info."},

		// --- Storage (8) ---
		{category: "storage", text: "List the contents of /ext on the SD card."},
		{category: "storage", text: "List all NFC files in /ext/nfc."},
		{category: "storage", text: "List all SubGHz files in /ext/subghz."},
		{category: "storage", text: "Show me what's in /ext/infrared."},
		{category: "storage", text: "Get file system info for /ext."},
		{category: "storage", text: "Compute the MD5 of /ext/Manifest."},
		{category: "storage", text: "Show me a recursive tree of /ext/nfc."},
		{category: "storage", text: "Read /ext/nfc/Test.nfc using the file format parser and give me the parsed structure."},

		// --- Hardware peripherals (3) ---
		{category: "hw", text: "Scan the I2C bus and tell me what devices are attached."},
		{category: "hw", text: "Search the 1-Wire bus for 3 seconds."},
		{category: "hw", text: "Read the state of GPIO pin PA7."},

		// --- LED / vibro (2) ---
		{category: "feedback", text: "Set the red LED to brightness 200, wait a moment, then turn it back to 0."},
		{category: "feedback", text: "Buzz the vibration motor briefly (turn vibro on, then off)."},

		// --- NFC (3) ---
		{category: "nfc", text: "Detect any NFC tag in the field with a 5 second timeout."},
		{category: "nfc", text: "Dump the contents of any Mifare Classic tag in the field with a 5 second timeout."},
		{category: "nfc", text: "Diff the file format of /ext/nfc/Test.nfc and /ext/nfc/RickRoll.nfc."},

		// --- SubGHz (RX only — no transmit) (2) ---
		{category: "subghz", text: "Receive Sub-GHz on 433920000 Hz for 3 seconds."},
		{category: "subghz", text: "Decode this saved Sub-GHz file: /ext/subghz/assets/keystore_test.sub if it exists, otherwise just list /ext/subghz/assets."},

		// --- IR (RX only) (2) ---
		{category: "ir", text: "Receive an IR signal for 3 seconds (just listen, don't transmit)."},
		{category: "ir", text: "List entries in the universal TV remote library."},

		// --- RFID (RX only) (1) ---
		{category: "rfid", text: "Read any 125 kHz RFID tag for 3 seconds."},

		// --- iButton (RX only) (1) ---
		{category: "ibutton", text: "Read any iButton key for 3 seconds."},

		// --- Audit (3) ---
		{category: "audit", text: "Query the audit log for the last 5 entries."},
		{category: "audit", text: "Show me audit stats."},
		{category: "audit", text: "What targets have I remembered? Use target_recall."},

		// --- BadUSB validate (read-only) (1) ---
		{category: "badusb", text: "Validate this BadUSB script as content (do not deploy or run): \"DELAY 200\\nSTRING hello\\nENTER\"."},

		// --- Workflow (read-only) (1) ---
		{category: "workflow", text: "Run the hardware recon workflow on my GPIO header."},

		// --- Storage round-trip (writes — last so the rest already saw a clean SD) (3) ---
		{category: "storage-rw", text: "Write 'cliyolo canary 2026-04-24' to /ext/cliyolo_canary.txt."},
		{category: "storage-rw", text: "Read back /ext/cliyolo_canary.txt and compute its MD5."},
		{category: "storage-rw", text: "Delete /ext/cliyolo_canary.txt."},
	}
}

// waitForTurnComplete returns once the agent has been silent for
// silenceWindow OR cap is reached. The duration returned is the elapsed
// wall time inside this function.
func waitForTurnComplete(ring *bytes.Buffer, silenceWindow, cap time.Duration) time.Duration {
	start := time.Now()
	deadline := start.Add(cap)
	lastLen := ring.Len()
	lastChange := time.Now()
	for {
		now := time.Now()
		if now.After(deadline) {
			return time.Since(start)
		}
		curLen := ring.Len()
		if curLen != lastLen {
			lastLen = curLen
			lastChange = now
		} else if now.Sub(lastChange) >= silenceWindow {
			return time.Since(start)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func waitForSubstring(ring *bytes.Buffer, needle string, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if strings.Contains(stripANSI(ring.String()), needle) {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

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
	lines := strings.Split(strings.TrimRight(s, " \r\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
