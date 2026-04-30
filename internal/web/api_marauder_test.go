//go:build linux

package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/marauder/parsers"
)

// fakeMarauder implements marauderClient. It records every Exec call and lets
// each test script the response body / errors and the lines a Stream emits.
type fakeMarauder struct {
	mu sync.Mutex
	// scripted Exec replies keyed on the literal command line.
	exec    map[string]string
	execErr map[string]error
	// streamLines is the slice of lines the next Stream call will emit. The
	// test seeds this and the goroutine drains it; subsequent Stream calls
	// pop the next slice (one per call).
	streamLines [][]string
	// recorded commands (Exec + Stream).
	calls []string
	// stopWatchers can wait for stopscan to land on Exec.
	stopChan chan struct{}
	// wakeStreams is signalled when the test wants the active Stream to
	// finish dispatching its preset lines.
	streamMu sync.Mutex
	openDone chan struct{} // closed when Stream's goroutine actually exits
}

func newFakeMarauder() *fakeMarauder {
	return &fakeMarauder{
		exec:     map[string]string{},
		execErr:  map[string]error{},
		stopChan: make(chan struct{}, 8),
	}
}

func (f *fakeMarauder) Exec(cmd string, _ time.Duration) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "exec:"+cmd)
	body := f.exec[cmd]
	err := f.execErr[cmd]
	f.mu.Unlock()
	if cmd == "stopscan" {
		select {
		case f.stopChan <- struct{}{}:
		default:
		}
	}
	return body, err
}

func (f *fakeMarauder) Stream(cmd string) (<-chan string, chan<- struct{}, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "stream:"+cmd)
	var lines []string
	if len(f.streamLines) > 0 {
		lines = f.streamLines[0]
		f.streamLines = f.streamLines[1:]
	}
	f.mu.Unlock()

	ch := make(chan string, len(lines)+1)
	for _, l := range lines {
		ch <- l
	}
	done := make(chan struct{})

	exited := make(chan struct{})
	f.streamMu.Lock()
	f.openDone = exited
	f.streamMu.Unlock()

	go func() {
		defer close(exited)
		<-done
		// Mirror the real package: write stopscan to the stopChan so
		// tests can verify it was sent.
		select {
		case f.stopChan <- struct{}{}:
		default:
		}
		close(ch)
	}()
	return ch, done, nil
}

func (f *fakeMarauder) callsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// marauderServer constructs a Server with a fake Marauder + httptest WS server.
func marauderServer(t *testing.T, m marauderClient) (*Server, *httptest.Server) {
	t.Helper()
	s := &Server{
		agent:             &fakeAgent{},
		addr:              "127.0.0.1:0",
		conns:             make(map[*sessionConn]struct{}),
		confirms:          make(map[string]chan agent.ConfirmResponse),
		heartbeatInterval: 100 * time.Millisecond,
		heartbeatTimeout:  2 * time.Second,
		writeTimeout:      2 * time.Second,
		startedAt:         time.Now(),
		requestQueue:      make(chan struct{}, 64),
	}
	s.attachAgentCallbacks()
	if m != nil {
		s.SetMarauder(m)
		s.SetMarauderConnected(true)
		s.SetMarauderInfo("/dev/ttyACM1", "v1.11.1")
	}
	ts := httptest.NewServer(http.HandlerFunc(s.handleWebSocket))
	t.Cleanup(ts.Close)
	return s, ts
}

// TestMarauderAcquireNoDevice: marauder is nil → marauder_error.
func TestMarauderAcquireNoDevice(t *testing.T) {
	_, ts := marauderServer(t, nil)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	m := readUntilType(t, ctx, c, "marauder_error")
	if msg, _ := m["message"].(string); !strings.Contains(msg, "no marauder") {
		t.Errorf("message = %q, want substring 'no marauder'", msg)
	}
}

// TestMarauderAcquireSendsStatus: a successful acquire emits marauder_status
// with the configured port + firmware fields.
func TestMarauderAcquireSendsStatus(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	m := readUntilType(t, ctx, c, "marauder_status")
	if m["connected"] != true {
		t.Errorf("connected = %v, want true", m["connected"])
	}
	if m["port"] != "/dev/ttyACM1" {
		t.Errorf("port = %v", m["port"])
	}
	if m["firmware"] != "v1.11.1" {
		t.Errorf("firmware = %v", m["firmware"])
	}
}

// TestMarauderAcquireConflict: a second client cannot acquire while the first
// holds.
func TestMarauderAcquireConflict(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)

	c1, cleanup1 := dialWS(t, ts)
	defer cleanup1()
	c2, cleanup2 := dialWS(t, ts)
	defer cleanup2()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c1, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c1, "marauder_status")

	sendJSON(t, ctx, c2, map[string]any{"type": "marauder_acquire"})
	m := readUntilType(t, ctx, c2, "marauder_error")
	if msg, _ := m["message"].(string); !strings.Contains(msg, "in use") {
		t.Errorf("message = %q", msg)
	}
}

// TestMarauderCmdRejectsNonHolder: a non-holder sending marauder_cmd gets a
// clear error and the device is never touched.
func TestMarauderCmdRejectsNonHolder(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "scanap", "action": "start"})
	m := readUntilType(t, ctx, c, "marauder_error")
	if msg, _ := m["message"].(string); !strings.Contains(msg, "not marauder holder") {
		t.Errorf("message = %q", msg)
	}
	for _, call := range fm.callsSnapshot() {
		if !strings.HasPrefix(call, "exec:") {
			continue
		}
		t.Errorf("device should not have been called, but saw %s", call)
	}
}

// TestMarauderUnknownCmd: an unknown registry key returns a clean error.
func TestMarauderUnknownCmd(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "frobulate"})
	m := readUntilType(t, ctx, c, "marauder_error")
	if msg, _ := m["message"].(string); !strings.Contains(msg, "unknown") {
		t.Errorf("message = %q", msg)
	}
}

// TestMarauderStreamScanAP: scanap streams parsed AP events.
func TestMarauderStreamScanAP(t *testing.T) {
	fm := newFakeMarauder()
	fm.streamLines = [][]string{{
		"-45 Ch: 6 aa:bb:cc:dd:ee:ff ESSID: HomeWiFi 64 00",
		"-72 Ch: 11 11:22:33:44:55:66 ESSID: Guest-Network 64 00",
	}}
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "scanap", "action": "start"})

	got := 0
	deadline := time.After(2 * time.Second)
loop:
	for got < 2 {
		select {
		case <-deadline:
			t.Fatalf("only got %d events", got)
		default:
		}
		m := readUntilType(t, ctx, c, "marauder_event")
		if m["kind"] != "ap_seen" {
			t.Errorf("kind = %v", m["kind"])
			continue
		}
		got++
		if got == 2 {
			break loop
		}
	}

	// Now stop and confirm stopscan was sent.
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "scanap", "action": "stop"})
	readUntilType(t, ctx, c, "marauder_done")

	select {
	case <-fm.stopChan:
	case <-time.After(2 * time.Second):
		t.Fatal("stopscan not observed within deadline")
	}

	calls := fm.callsSnapshot()
	if len(calls) == 0 || calls[0] != "stream:scanall" {
		t.Errorf("first call = %q, want stream:scanall (calls=%v)", firstOr(calls, ""), calls)
	}
}

// TestMarauderReleaseCancelsStream: explicit release cancels an in-flight
// stream and triggers stopscan.
func TestMarauderReleaseCancelsStream(t *testing.T) {
	fm := newFakeMarauder()
	fm.streamLines = [][]string{{
		"-45 Ch: 6 aa:bb:cc:dd:ee:ff ESSID: HomeWiFi",
	}}
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "scanap", "action": "start"})
	readUntilType(t, ctx, c, "marauder_event")

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_release"})

	select {
	case <-fm.stopChan:
	case <-time.After(2 * time.Second):
		t.Fatal("stopscan not observed within deadline after release")
	}
}

// TestMarauderStreamRotatesOnNewCmd: starting a new stream while one is
// running cancels the prior one (exactly one streaming command at a time
// per holder). Uses two Low-risk commands so no confirm gate is involved.
func TestMarauderStreamRotatesOnNewCmd(t *testing.T) {
	fm := newFakeMarauder()
	fm.streamLines = [][]string{
		{"-45 Ch: 6 aa:bb:cc:dd:ee:ff ESSID: A"},
		{"-45 Ch: 6 Client: aa:bb:cc:dd:ee:ff Probe: TestSSID"},
	}
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "scanap"})
	readUntilType(t, ctx, c, "marauder_event")

	// sniffprobe is Low-risk — no confirm needed; rotation happens immediately.
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "sniffprobe"})
	// The probe event should arrive after rotation.
	m := readUntilType(t, ctx, c, "marauder_event")
	if m["kind"] != "probe" {
		t.Errorf("rotated kind = %v want probe", m["kind"])
	}
}

// TestMarauderHolderDisconnectReleases: closing the WebSocket while holding
// triggers stopscan and frees the slot for another acquire.
func TestMarauderHolderDisconnectReleases(t *testing.T) {
	fm := newFakeMarauder()
	fm.streamLines = [][]string{{"-45 Ch: 6 aa:bb:cc:dd:ee:ff ESSID: A"}}
	_, ts := marauderServer(t, fm)

	c1, cleanup1 := dialWS(t, ts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c1, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c1, "marauder_status")
	sendJSON(t, ctx, c1, map[string]any{"type": "marauder_cmd", "cmd": "scanap"})
	readUntilType(t, ctx, c1, "marauder_event")

	cleanup1() // hard-close c1

	select {
	case <-fm.stopChan:
	case <-time.After(2 * time.Second):
		t.Fatal("stopscan not observed after holder disconnect")
	}

	// Second client should be able to acquire.
	c2, cleanup2 := dialWS(t, ts)
	defer cleanup2()
	sendJSON(t, ctx, c2, map[string]any{"type": "marauder_acquire"})
	m := readUntilType(t, ctx, c2, "marauder_status")
	if m["connected"] != true {
		t.Errorf("connected = %v, want true", m["connected"])
	}
}

// TestMarauderCmdInvalidArg: blespam with no target → marauder_error.
func TestMarauderCmdInvalidArg(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "blespam", "args": map[string]any{"target": "evil"}})
	m := readUntilType(t, ctx, c, "marauder_error")
	if msg, _ := m["message"].(string); !strings.Contains(msg, "invalid blespam target") {
		t.Errorf("message = %q", msg)
	}
	for _, call := range fm.callsSnapshot() {
		if strings.Contains(call, "blespam") {
			t.Errorf("device touched on bad arg: %v", call)
		}
	}
}

// TestMarauderCmdLEDExec: led_set runs Exec(led -s <hex>) and emits done.
func TestMarauderCmdLEDExec(t *testing.T) {
	fm := newFakeMarauder()
	fm.exec["led -s ff0000"] = "ok"
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "led_set", "args": map[string]any{"hex": "ff0000"}})
	readUntilType(t, ctx, c, "marauder_done")

	calls := fm.callsSnapshot()
	wantExec := "exec:led -s ff0000"
	found := false
	for _, c := range calls {
		if c == wantExec {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in calls, got %v", wantExec, calls)
	}
}

// TestMarauderExecError: a device error surfaces as marauder_error with the
// Exec error message.
func TestMarauderExecError(t *testing.T) {
	fm := newFakeMarauder()
	fm.execErr["led -s ff0000"] = errors.New("port closed")
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "led_set", "args": map[string]any{"hex": "ff0000"}})
	m := readUntilType(t, ctx, c, "marauder_error")
	if msg, _ := m["message"].(string); !strings.Contains(msg, "port closed") {
		t.Errorf("message = %q", msg)
	}
}

// TestMarauderStopActionWhenIdle: action=stop when nothing is running still
// sends stopscan and marauder_done — idempotent.
func TestMarauderStopActionWhenIdle(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "scanap", "action": "stop"})
	readUntilType(t, ctx, c, "marauder_done")
	select {
	case <-fm.stopChan:
	case <-time.After(2 * time.Second):
		t.Fatal("stopscan not observed for idle stop")
	}
}

// TestMarauderRegistryCoversSpec sanity-checks that all spec-mandated keys
// resolve to a registry entry. Renaming or accidentally dropping a key from
// the registry breaks this test loudly.
func TestMarauderRegistryCoversSpec(t *testing.T) {
	want := []string{
		"scanap", "scansta", "sniffbeacon", "sniffprobe",
		"sniffraw", "sniffraw_lines", "sniffdeauth", "packetcount",
		"attack_deauth", "attack_beacon_random", "attack_beacon_list",
		"attack_beacon_ap", "attack_probe", "attack_rickroll",
		"evilportal_start",
		"blescan", "blewardrive", "blespam",
		"gpsdata", "nmea",
		"ls",
		"led_set", "led_rainbow",
		"stop",
	}
	for _, k := range want {
		if _, ok := marauderRegistry[k]; !ok {
			t.Errorf("registry missing key %q", k)
		}
	}
}

// TestMarauderSniffRawLinesPerLine: sniffraw_lines (per-line variant added
// for task #9) must stream every non-empty line as a `raw` event so the
// frontend Sniff Raw list view populates. The aggregate-stats `sniffraw`
// entry covers Packet Monitor; this entry covers the firmware's verbatim
// frame stream.
func TestMarauderSniffRawLinesPerLine(t *testing.T) {
	fm := newFakeMarauder()
	fm.streamLines = [][]string{{
		"-50 802.11 mgmt beacon ssid=HomeWiFi",
		"-72 802.11 data from=aa:bb:cc:dd:ee:ff",
		"     Mgmt: 12", // also passes ParseRaw — block-stat lines arrive verbatim too
	}}
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "sniffraw_lines"})

	got := 0
	for got < 3 {
		m := readUntilType(t, ctx, c, "marauder_event")
		if m["kind"] != "raw" {
			t.Fatalf("kind = %v want raw", m["kind"])
		}
		got++
	}

	// Confirm the device was driven via Stream("sniffraw") — same upstream
	// command as the aggregate variant.
	calls := fm.callsSnapshot()
	if len(calls) == 0 || calls[0] != "stream:sniffraw" {
		t.Errorf("first call = %q, want stream:sniffraw (calls=%v)", firstOr(calls, ""), calls)
	}
}

// ---------------------------------------------------------------------------
// Regression tests — frontend/backend command-key mismatches (QA task #5).
//
// These tests document bugs where the frontend (app.js) sends a different
// cmd key or args key than the backend registry expects. Each test asserts
// the BACKEND behaviour (which is correct); the fix belongs in app.js.
// ---------------------------------------------------------------------------

// TestFrontendLEDCmdKeyMismatch documents BUG-1:
// app.js selectCurrent() sends cmd:"settingslsled" for LED actions, but the
// backend registry only knows "led_set" and "led_rainbow". Every LED swatch
// press therefore returns marauder_error:"unknown command".
//
// Fix needed in app.js: send cmd:"led_rainbow" or cmd:"led_set" with
// args:{"hex":"<RRGGBB>"}.
func TestFrontendLEDCmdKeyMismatch(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")

	// This is what app.js currently sends for the rainbow LED swatch.
	sendJSON(t, ctx, c, map[string]any{
		"type":   "marauder_cmd",
		"cmd":    "settingslsled",
		"action": "once",
		"args":   map[string]any{"value": "rainbow"},
	})
	m := readUntilType(t, ctx, c, "marauder_error")
	msg, _ := m["message"].(string)
	if !strings.Contains(msg, "unknown") {
		t.Errorf("expected unknown-command error, got %q", msg)
	}

	// Confirm the device was never touched.
	for _, call := range fm.callsSnapshot() {
		if strings.Contains(call, "led") || strings.Contains(call, "rainbow") {
			t.Errorf("device should not be called for unknown key; saw %s", call)
		}
	}
}

// TestFrontendAttackCmdKeyMismatch documents BUG-2:
// app.js fireArmed() fires the cmd value from the TREE node directly, e.g.
// cmd:"attack" for WiFi attacks and cmd:"evilportal" for Evil Portal. The
// backend registry has separate keys per attack type (attack_beacon_random,
// attack_deauth, evilportal_start, …). "attack" and "evilportal" are
// unknown to the registry, so every attack attempt results in marauder_error.
//
// Fix needed in app.js: map TREE leaf cmd+args to the correct registry key
// (e.g. args.t=="beacon" && args.mode=="rand" → "attack_beacon_random").
func TestFrontendAttackCmdKeyMismatch(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")

	cases := []struct {
		cmd  string
		args map[string]any
	}{
		{"attack", map[string]any{"t": "beacon", "mode": "rand"}},
		{"attack", map[string]any{"t": "deauth"}},
		{"evilportal", map[string]any{"c": "start"}},
	}
	for _, tc := range cases {
		sendJSON(t, ctx, c, map[string]any{
			"type":   "marauder_cmd",
			"cmd":    tc.cmd,
			"action": "start",
			"args":   tc.args,
		})
		m := readUntilType(t, ctx, c, "marauder_error")
		msg, _ := m["message"].(string)
		if !strings.Contains(msg, "unknown") {
			t.Errorf("cmd=%q: expected unknown-command error, got %q", tc.cmd, msg)
		}
	}
}

// TestFrontendBLESpamArgKeyMismatch documents BUG-3:
// app.js sends args:{"t":"apple"} for BLE spam targets. The backend blespam
// builder reads stringArg(args, "target") — key "target", not "t". When "t"
// is present but "target" is absent, target="" which hits the default case
// returning "invalid blespam target". All BLE spam attacks therefore fail.
//
// Fix needed in app.js: send args:{"target":"apple"} etc.
func TestFrontendBLESpamArgKeyMismatch(t *testing.T) {
	entry := marauderRegistry["blespam"]
	if entry.build == nil {
		t.Fatal("blespam registry entry missing build func")
	}

	// Wrong key ("t", as app.js currently sends) → build returns error.
	// The error surfaces as marauder_error before the device is ever touched.
	_, err := entry.build(map[string]any{"t": "apple"})
	if err == nil {
		t.Fatal("expected error for arg key 't', got nil")
	}
	if !strings.Contains(err.Error(), "invalid blespam target") {
		t.Errorf("wrong error message: %q", err)
	}

	// Correct key ("target", as the backend expects) → build succeeds.
	for _, tgt := range []string{"apple", "samsung", "google", "windows"} {
		cmd, err := entry.build(map[string]any{"target": tgt})
		if err != nil {
			t.Errorf("target=%q: unexpected error: %v", tgt, err)
		}
		if cmd != "blespam -t "+tgt {
			t.Errorf("target=%q: cmd=%q, want blespam -t %s", tgt, cmd, tgt)
		}
	}

	// Integration: send with wrong key via WS → marauder_error (no stream).
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{
		"type":   "marauder_cmd",
		"cmd":    "blespam",
		"action": "start",
		"args":   map[string]any{"t": "apple"},
	})
	m := readUntilType(t, ctx, c, "marauder_error")
	msg, _ := m["message"].(string)
	if !strings.Contains(msg, "invalid blespam target") {
		t.Errorf("WS: expected invalid-target error, got %q", msg)
	}
	// Device must NOT have been touched (build errors before any Stream call).
	for _, call := range fm.callsSnapshot() {
		if strings.Contains(call, "blespam") {
			t.Errorf("device touched with blespam despite bad arg: %s", call)
		}
	}
}

// TestFrontendBLEScanArgKeyMismatch documents BUG-4:
// app.js sends args:{"t":"apple"} for typed BLE scans. The backend blescan
// builder reads stringArg(args, "target"). When "t" is present but "target"
// is absent, target="" which hits the `case "", "all":` branch and sends
// plain "sniffbt" (BT_SCAN_ALL) regardless of the intended filter.
// Apple/Samsung/Flipper detector modes therefore silently scan everything.
//
// Fix needed in app.js: send args:{"target":"apple"} etc.
func TestFrontendBLEScanArgKeyMismatch(t *testing.T) {
	entry := marauderRegistry["blescan"]
	if entry.build == nil {
		t.Fatal("blescan registry entry missing build func")
	}

	// Correct key ("target") works and produces the right CLI command.
	for _, tgt := range []string{"apple", "samsung", "flipper"} {
		cmd, err := entry.build(map[string]any{"target": tgt})
		if err != nil {
			t.Errorf("target=%q: unexpected error: %v", tgt, err)
		}
		if cmd != "sniffbt -t "+tgt {
			t.Errorf("target=%q: cmd=%q, want sniffbt -t %s", tgt, cmd, tgt)
		}
	}

	// Wrong key ("t", as app.js sends) → build returns no error but falls
	// back to unfiltered BT_SCAN_ALL ("sniffbt"). No per-vendor filter is
	// applied, so Apple/Samsung/Flipper detectors silently scan all devices.
	for _, tgt := range []string{"apple", "samsung", "flipper"} {
		cmd, err := entry.build(map[string]any{"t": tgt})
		if err != nil {
			t.Errorf("wrong-key target=%q: unexpected error: %v", tgt, err)
		}
		if cmd != "sniffbt" {
			// If this assertion fails, BUG-4 is fixed — update the test.
			t.Errorf("wrong-key target=%q: cmd=%q; expected silent fallback to \"sniffbt\" (BUG-4)", tgt, cmd)
		}
	}
}

// TestPacketRateJSONFieldNames documents BUG-5:
// The frontend ingestPacketRate() reads p.probe and p.raw from packet_rate
// events. However, parsers.PacketRate serialises probe counts as "probe_req"
// and "probe_res", and has no "raw" field at all. Both series will always
// read as 0 regardless of real traffic.
//
// Fix needed in app.js: read p.probe_req (+ p.probe_res) for the probe
// series; choose an appropriate field for the "raw" series (e.g. p.data).
func TestPacketRateJSONFieldNames(t *testing.T) {
	pr := parsers.PacketRate{
		Mgmt:     10,
		Data:     5,
		Channel:  6,
		Beacon:   64,
		ProbeReq: 12,
		ProbeRes: 7,
		Deauth:   3,
		EAPOL:    1,
		RSSIMin:  -92,
		RSSIMax:  -33,
	}
	b, err := json.Marshal(pr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Fields the frontend reads — must be present in the JSON.
	mustHave := []string{"beacon", "deauth", "eapol"}
	for _, k := range mustHave {
		if _, ok := m[k]; !ok {
			t.Errorf("required field %q missing from packet_rate JSON", k)
		}
	}

	// Fields the frontend currently reads but that are ABSENT (the bugs).
	missingInFrontend := map[string]string{
		"probe": "probe_req",  // frontend reads "probe"; backend emits "probe_req"
		"raw":   "(no field)", // frontend reads "raw"; backend emits nothing with that key
	}
	for feKey, beKey := range missingInFrontend {
		if _, ok := m[feKey]; ok {
			t.Errorf("BUG-5 field %q unexpectedly present — mismatch already fixed?", feKey)
		} else {
			t.Logf("BUG-5: frontend reads %q but PacketRate JSON has %q (or nothing)", feKey, beKey)
		}
	}

	// Confirm the actual backend field names are present.
	backendFields := []string{"probe_req", "probe_res", "mgmt", "data", "channel"}
	for _, k := range backendFields {
		if _, ok := m[k]; !ok {
			t.Errorf("expected backend field %q in packet_rate JSON", k)
		}
	}
}

func firstOr(xs []string, fallback string) string {
	if len(xs) == 0 {
		return fallback
	}
	return xs[0]
}

// TestFrontendBrowseSDEventKindMismatch documents BUG-6:
// The frontend handleEvent() listens for kind "ls" expecting a batch payload
// {entries:[...], path:"..."}. The backend emits individual "ls_entry" events
// (one per file/dir) with payload {name, bytes, is_dir}. The "ls_entry"
// kind falls through the switch with no handler, so state.data.entries is
// never populated and Browse SD always shows an empty listing.
//
// Fix needed in app.js: add a case 'ls_entry': that appends to
// state.data.entries, similar to how appendListRow accumulates ap_seen rows.
func TestFrontendBrowseSDEventKindMismatch(t *testing.T) {
	// Backend ls entry emits per-file events with kind "ls_entry".
	entry := marauderRegistry["ls"]
	if entry.kind != "ls_entry" {
		t.Fatalf("ls registry kind = %q, want ls_entry", entry.kind)
	}

	// The frontend switch case is 'ls', not 'ls_entry'. Confirm the kinds differ.
	const frontendExpects = "ls"
	if entry.kind == frontendExpects {
		t.Errorf("BUG-6 already fixed? backend kind %q now matches frontend case", entry.kind)
	} else {
		t.Logf("BUG-6: backend emits kind %q; frontend handleEvent has case %q — Browse SD entries never accumulate",
			entry.kind, frontendExpects)
	}

	// Also confirm the payload shape mismatch: LSEntry has name/bytes/is_dir,
	// not entries[]/path as the frontend 'ls' case reads.
	ev := parsers.LSEntry{Name: "test.txt", Bytes: 1024}
	b, _ := json.Marshal(ev)
	var m map[string]any
	_ = json.Unmarshal(b, &m)

	if _, ok := m["entries"]; ok {
		t.Error("BUG-6: 'entries' field unexpectedly present in LSEntry JSON")
	}
	if _, ok := m["path"]; ok {
		t.Error("BUG-6: 'path' field unexpectedly present in LSEntry JSON")
	}
	if _, ok := m["name"]; !ok {
		t.Error("LSEntry JSON missing 'name' field")
	}
}

// ---------------------------------------------------------------------------
// Risk gate + consent + audit tests (validated.md row 4)
// ---------------------------------------------------------------------------

// readUntilOneOfTypes returns the first frame whose type is one of the wanted
// types, skipping all others. Returned map includes {"type": matchedType, ...}.
func readUntilOneOfTypes(t *testing.T, ctx context.Context, c *websocket.Conn, types ...string) map[string]any {
	t.Helper()
	for {
		m := readJSON(t, ctx, c)
		typ, _ := m["type"].(string)
		for _, want := range types {
			if typ == want {
				return m
			}
		}
	}
}

// TestMarauderLowRiskDispatchesWithoutConfirm verifies that a Low-risk command
// (scanap) reaches the device directly — no marauder_confirm_request emitted.
func TestMarauderLowRiskDispatchesWithoutConfirm(t *testing.T) {
	fm := newFakeMarauder()
	fm.streamLines = [][]string{{
		"-45 Ch: 6 aa:bb:cc:dd:ee:ff ESSID: HomeWiFi 64 00",
	}}
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "scanap", "action": "start"})

	// First substantive frame must NOT be a confirm_request.
	m := readUntilOneOfTypes(t, ctx, c, "marauder_confirm_request", "marauder_event", "marauder_done")
	if m["type"] == "marauder_confirm_request" {
		t.Fatalf("Low-risk command should not emit marauder_confirm_request; got %v", m)
	}
}

// TestMarauderHighRiskRequiresConfirmToken verifies that a High-risk command
// (blespam) emits marauder_confirm_request with a non-empty confirm_id and the
// correct risk string, and does NOT immediately dispatch.
func TestMarauderHighRiskRequiresConfirmToken(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{
		"type": "marauder_cmd", "cmd": "blespam",
		"args": map[string]any{"target": "apple"},
	})

	m := readUntilType(t, ctx, c, "marauder_confirm_request")
	if m["cmd"] != "blespam" {
		t.Errorf("confirm_request cmd = %v, want blespam", m["cmd"])
	}
	if m["risk"] != "high" {
		t.Errorf("confirm_request risk = %v, want high", m["risk"])
	}
	cid, _ := m["confirm_id"].(string)
	if cid == "" {
		t.Fatalf("confirm_request missing confirm_id: %v", m)
	}
	// Device must not have been touched yet.
	for _, call := range fm.callsSnapshot() {
		if strings.Contains(call, "blespam") {
			t.Errorf("device should not be called before confirm; saw %s", call)
		}
	}
}

// TestMarauderAuditRowWrittenForAllowAndDeny verifies that:
//   - a Low-risk command writes an audit row with success=true;
//   - a High-risk command denied by the operator writes an audit row with
//     success=false.
func TestMarauderAuditRowWrittenForAllowAndDeny(t *testing.T) {
	fm := newFakeMarauder()
	fm.streamLines = [][]string{{
		"-45 Ch: 6 aa:bb:cc:dd:ee:ff ESSID: HomeWiFi 64 00",
	}}
	s, ts2 := marauderServer(t, fm)

	logPath := filepath.Join(t.TempDir(), "audit.db")
	auditLog, err := audit.Open(logPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	s.SetAuditLog(auditLog)

	c, cleanup := dialWS(t, ts2)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")

	// Part A: Low-risk command (scanap) — allowed, no confirm.
	sendJSON(t, ctx, c, map[string]any{"type": "marauder_cmd", "cmd": "scanap", "action": "start"})
	readUntilOneOfTypes(t, ctx, c, "marauder_event", "marauder_done")
	// Allow audit goroutine to flush.
	time.Sleep(50 * time.Millisecond)

	entries, err := auditLog.QueryFiltered(audit.Filter{Tool: "web.marauder.scanap"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected audit row for scanap, got none")
	}
	if !entries[0].Success {
		t.Errorf("scanap audit success = false, want true")
	}

	// Part B: High-risk command (blespam) denied by the operator.
	sendJSON(t, ctx, c, map[string]any{
		"type": "marauder_cmd", "cmd": "blespam",
		"args": map[string]any{"target": "samsung"},
	})
	confirmMsg := readUntilType(t, ctx, c, "marauder_confirm_request")
	cid, _ := confirmMsg["confirm_id"].(string)
	sendJSON(t, ctx, c, map[string]any{
		"type":       "confirm_response",
		"confirm_id": cid,
		"decision":   "deny",
	})
	errMsg := readUntilType(t, ctx, c, "marauder_error")
	if msg, _ := errMsg["message"].(string); !strings.Contains(msg, "denied") {
		t.Errorf("error message = %q, want substring 'denied'", msg)
	}
	time.Sleep(50 * time.Millisecond)

	entries2, err := auditLog.QueryFiltered(audit.Filter{Tool: "web.marauder.blespam"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries2) == 0 {
		t.Fatal("expected audit row for blespam deny, got none")
	}
	if entries2[0].Success {
		t.Errorf("blespam denied audit success = true, want false")
	}
}

// TestMarauderConfirmTooFastRejected verifies that approving a High-risk
// command before the minimum 2-second delay yields marauder_error (the
// server-side gate rejects the keystroke).
func TestMarauderConfirmTooFastRejected(t *testing.T) {
	fm := newFakeMarauder()
	_, ts := marauderServer(t, fm)
	c, cleanup := dialWS(t, ts)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendJSON(t, ctx, c, map[string]any{"type": "marauder_acquire"})
	readUntilType(t, ctx, c, "marauder_status")
	sendJSON(t, ctx, c, map[string]any{
		"type": "marauder_cmd", "cmd": "blespam",
		"args": map[string]any{"target": "apple"},
	})
	confirmMsg := readUntilType(t, ctx, c, "marauder_confirm_request")
	cid, _ := confirmMsg["confirm_id"].(string)

	// Approve immediately — gate window has not elapsed.
	sendJSON(t, ctx, c, map[string]any{
		"type":       "confirm_response",
		"confirm_id": cid,
		"decision":   "approve",
	})
	errMsg := readUntilType(t, ctx, c, "marauder_error")
	if msg, _ := errMsg["message"].(string); !strings.Contains(msg, "minimum delay") {
		t.Errorf("error message = %q, want substring 'minimum delay'", msg)
	}
	// Device must not have been called.
	for _, call := range fm.callsSnapshot() {
		if strings.Contains(call, "blespam") {
			t.Errorf("device should not be called on fast-approve; saw %s", call)
		}
	}
}
