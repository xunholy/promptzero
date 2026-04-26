//go:build !windows

// webtest spawns `promptzero --web` against a real Flipper, then drives
// every HTTP API endpoint and the websocket handshake to confirm the
// public web surface is wired correctly. Read-only by default — no LLM
// turn is invoked, so this runs without burning Anthropic credits.
//
// Sets ANTHROPIC_API_KEY=dummy because cfg.RequireAPIKey() gates the
// agent-construction path in --web mode. The dummy key is never used
// because we never call /ws to drive a turn.
//
// Not built on Windows — uses POSIX process-group + signal primitives.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

type result struct {
	method, path string
	status       int
	dur          time.Duration
	body         string
	err          error
}

func main() {
	var (
		bin       = flag.String("bin", "./bin/promptzero", "promptzero binary")
		port      = flag.String("port", "/dev/ttyACM0", "Flipper serial port")
		webPort   = flag.Int("web-port", 8088, "ephemeral web port")
		wsTurn    = flag.Bool("ws-turn", false, "drive a real LLM turn over the websocket (burns Anthropic credits; requires real API key)")
		apiKey    = os.Getenv("ANTHROPIC_API_KEY")
		showStdio = flag.Bool("show-server-output", false, "print server stdout/stderr to ours")
	)
	flag.Parse()

	if apiKey == "" {
		// Use a dummy so cfg.RequireAPIKey passes. We won't call any
		// LLM-driven endpoint unless --ws-turn is set.
		apiKey = "sk-ant-dummy-for-smoke-test"
		_ = os.Setenv("ANTHROPIC_API_KEY", apiKey)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", *webPort)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, *bin,
		"--web",
		"--web-port", fmt.Sprintf("%d", *webPort),
		"--port", *port,
	)
	cmd.Env = append(os.Environ(), "ANTHROPIC_API_KEY="+apiKey)

	// Capture stdio so we can show it on failure even if we don't pipe it
	// through to our own.
	var stdoutBuf, stderrBuf bytes.Buffer
	if *showStdio {
		cmd.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
	} else {
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "spawn: %v\n", err)
		os.Exit(1)
	}
	// Cleanup is done via a Go runtime SetFinalizer-equivalent: a
	// goroutine watches our own stdout/stderr pipe-write to detect
	// SIGPIPE before defers can fire (e.g. when the harness is run
	// under `| head`). See teardown() for the kill cascade.
	td := newTeardown(cmd)
	defer td.run()
	installSIGPIPEFallback(td)

	if !waitForListener(addr, 30*time.Second) {
		fmt.Fprintf(os.Stderr, "web port %s never came up\n--- server stderr ---\n%s\n", addr, stderrBuf.String())
		os.Exit(1)
	}

	base := "http://" + addr
	cases := []struct {
		method, path, body string
		// allow503 marks endpoints that legitimately return 503 when the
		// host process didn't wire the optional subsystem (watcher, etc.)
		// — per the api.go contract: "the frontend uses that to hide the
		// relevant panel rather than showing a broken state."
		allow503 bool
	}{
		{method: "GET", path: "/api/auth"},
		{method: "GET", path: "/api/personas"},
		{method: "GET", path: "/api/watch", allow503: true},
		{method: "GET", path: "/api/cost"},
		{method: "GET", path: "/api/rules"},
		{method: "GET", path: "/api/debug"},
		{method: "GET", path: "/api/device"},
		// Validator: send a tiny BadUSB DuckyScript that should pass.
		{method: "POST", path: "/api/validate", body: `{"kind":"badusb","content":"REM ok\nDELAY 100"}`},
		// Static homepage should serve.
		{method: "GET", path: "/"},
	}

	pass, fail := 0, 0
	for _, tc := range cases {
		r := hit(ctx, tc.method, base+tc.path, tc.body)
		ok := r.err == nil && r.status >= 200 && r.status < 400
		marker := "PASS"
		switch {
		case ok:
			pass++
		case tc.allow503 && r.status == 503:
			marker = "SKIP" // documented "subsystem not wired" path
		default:
			marker = "FAIL"
			fail++
		}
		body := summary(r.body)
		if r.err != nil {
			body = "ERR: " + r.err.Error()
		}
		fmt.Printf("%s  %-4s %-22s %3d  %6s  %s\n", marker, r.method, r.path, r.status, r.dur.Round(time.Millisecond), body)
	}

	// Websocket handshake check (no turn driven).
	wsURL := "ws://" + addr + "/ws"
	wsCtx, wsCancel := context.WithTimeout(ctx, 5*time.Second)
	conn, _, err := websocket.Dial(wsCtx, wsURL, nil)
	wsCancel()
	if err != nil {
		fmt.Printf("FAIL  ws    /ws                       —     —     handshake: %v\n", err)
		fail++
	} else {
		fmt.Printf("PASS  ws    /ws                     101     —     handshake clean\n")
		pass++
		// Optionally drive a real turn through the websocket. Off by
		// default because it requires a real API key and burns credits.
		if *wsTurn {
			if err := wsTurnSmoke(ctx, conn); err != nil {
				fmt.Printf("FAIL  ws    /ws turn               —     —     %v\n", err)
				fail++
			} else {
				fmt.Printf("PASS  ws    /ws turn             ok     —     LLM turn round-trip clean\n")
				pass++
			}
		}
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}

	fmt.Printf("\n# %d pass, %d fail\n", pass, fail)
	if fail > 0 {
		fmt.Fprintf(os.Stderr, "\n--- last 40 lines of server stderr ---\n%s\n", tail(stderrBuf.String(), 40))
		os.Exit(1)
	}
}

// teardown bundles the kill-the-spawned-process cascade. SIGTERM first
// so promptzero gets to clean up its serial port; SIGKILL after a short
// grace if it didn't exit. Runnable at most once via sync.Once so the
// SIGPIPE fallback and the deferred call don't double-fire.
type teardown struct {
	cmd  *exec.Cmd
	once sync.Once
}

func newTeardown(cmd *exec.Cmd) *teardown { return &teardown{cmd: cmd} }

func (t *teardown) run() {
	t.once.Do(func() {
		if t.cmd == nil || t.cmd.Process == nil {
			return
		}
		_ = syscall.Kill(-t.cmd.Process.Pid, syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- t.cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
	})
}

// installSIGPIPEFallback ensures the spawned binary is reaped even when
// our stdout pipe closes before main() returns (running under `| head`,
// for example). The Go runtime turns SIGPIPE on stdio into a silent
// process exit without firing defers, so we trap it explicitly and run
// the teardown before re-raising so the test still exits with the
// SIGPIPE-equivalent status.
func installSIGPIPEFallback(td *teardown) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGPIPE)
	go func() {
		<-ch
		td.run()
		// Re-raise so the parent sees the signal it expected.
		signal.Reset(syscall.SIGPIPE)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGPIPE)
	}()
}

func waitForListener(addr string, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

func hit(ctx context.Context, method, url, body string) result {
	r := result{method: method, path: strings.TrimPrefix(url, "http://127.0.0.1:")}
	if i := strings.IndexByte(r.path, '/'); i >= 0 {
		r.path = r.path[i:]
	}

	start := time.Now()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		r.err = err
		return r
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	r.dur = time.Since(start)
	if err != nil {
		r.err = err
		return r
	}
	defer resp.Body.Close()
	r.status = resp.StatusCode
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	r.body = string(b)
	return r
}

func wsTurnSmoke(ctx context.Context, conn *websocket.Conn) error {
	turnCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	msg, _ := json.Marshal(map[string]any{"type": "text", "content": "what's connected?"})
	if err := conn.Write(turnCtx, websocket.MessageText, msg); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	for {
		_, data, err := conn.Read(turnCtx)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		var env map[string]any
		_ = json.Unmarshal(data, &env)
		if env["type"] == "response" || env["type"] == "error" {
			return nil
		}
	}
}

func summary(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 100 {
		s = s[:97] + "..."
	}
	return s
}

func tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
