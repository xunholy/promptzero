// Marauder synth-panel WebSocket layer.
//
// Owns the marauder_acquire / marauder_release / marauder_cmd WS frames and
// the command registry that maps a stable client-side key to a Marauder CLI
// command + parser + event kind. See SPEC.md §3 for the architecture and §3.4
// for the registry table; the registry below is the authoritative copy in code.
//
// Threading rules:
//   - marauderMu guards marauderHolder, marauderCancel, marauderRunning.
//   - marauderActive (atomic) is the fast-path "is the panel held" flag.
//   - All emits go through s.sendTo / s.broadcast (the same writer pipeline
//     as every other JSON frame).
//   - Stream goroutines watch ctx for cancellation and close the Marauder
//     `done` channel on exit; the package's Stream implementation sends
//     `stopscan` to the device when that channel is closed.
package web

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/marauder/parsers"
	"github.com/xunholy/promptzero/internal/risk"
)

// marauderClient is the narrow surface the synth-panel needs from a Marauder
// client. *marauder.Marauder satisfies it directly; tests inject a fake.
type marauderClient interface {
	Exec(cmd string, timeout time.Duration) (string, error)
	Stream(cmd string) (<-chan string, chan<- struct{}, error)
}

// commandMode picks the dispatch path for a registry entry.
type commandMode int

const (
	// modeExec runs a single Exec call, parses the response (if a parser
	// is set), emits one event, and returns marauder_done.
	modeExec commandMode = iota
	// modeStream opens a Stream and emits per-line events until ctx is
	// cancelled (release / explicit stop / disconnect).
	modeStream
	// modeBlock collects lines from a Stream into block-shaped events
	// (multiple lines → one parser invocation). Used by GPS data and the
	// renderRawStats packet rate.
	modeBlock
)

// commandEntry describes one registry row.
type commandEntry struct {
	// build is called with the operator-supplied args map and must return
	// the literal CLI command string to send. May return an error to
	// surface a clean marauder_error before the device is touched.
	build func(args map[string]any) (string, error)
	// mode picks Exec vs Stream vs Block.
	mode commandMode
	// emit is called per-event; it owns translating the parsed payload
	// into a marauder_event JSON map. nil means no per-event emit.
	emit func(s *Server, c *sessionConn, kind, line string, block []string)
	// kind is the marauder_event.kind value.
	kind string
	// timeout is the Exec deadline (modeExec only). modeStream / modeBlock
	// run until cancellation.
	timeout time.Duration
	// blockTerminator, when non-empty, is the line prefix that closes a
	// block in modeBlock mode. The block (excluding the terminator line)
	// is fed to the parser, then a fresh block starts.
	blockTerminator string
	// blockEvery, when >0, flushes the block every N lines (used by
	// renderRawStats which has a fixed shape but no terminator marker).
	blockEvery int
	// risk is the operator-visible risk level for this command. Used by
	// handleMarauderCmd to gate risk≥High behind the confirm round-trip.
	risk risk.Level
}

// marauderRegistry is the locked-in mapping of WS cmd keys to device
// commands + parsers. Adding a new screen means adding a row here and
// (if the parser is new) wiring it in internal/marauder/parsers.
//
// The registry is NOT user-extensible at runtime; gating happens here.
var marauderRegistry = map[string]commandEntry{
	// scanap and scansta are legacy WS keys retained for client/UI continuity.
	// Both were removed from Marauder firmware in v1.11.1+ and merged into
	// scanall, which produces both AP and STA rows. We send scanall on the
	// wire for both keys; the AP/STA parser pair is kept so the panel still
	// gets the appropriate filtered event stream per click.
	"scanap": {
		build: staticCmd("scanall"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseScanAP, "ap_seen"),
		kind:  "ap_seen",
		risk:  risk.Low,
	},
	"scansta": {
		build: staticCmd("scanall"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseScanSta, "sta_seen"),
		kind:  "sta_seen",
		risk:  risk.Low,
	},
	"sniffbeacon": {
		build: staticCmd("sniffbeacon"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseSniffBeacon, "beacon"),
		kind:  "beacon",
		risk:  risk.Low,
	},
	"sniffprobe": {
		build: staticCmd("sniffprobe"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseSniffProbe, "probe"),
		kind:  "probe",
		risk:  risk.Low,
	},
	"sniffraw": {
		build:      staticCmd("sniffraw"),
		mode:       modeBlock,
		emit:       emitBlockWith(parsers.ParseRawStats, "packet_rate"),
		kind:       "packet_rate",
		blockEvery: 10, // renderRawStats prints ~10 labelled lines per block
		risk:       risk.Low,
	},
	// Per-line variant of sniffraw for the "Sniff Raw" menu leaf — emits
	// every non-empty line as a `raw` event so the frontend list view can
	// scroll the live frame stream verbatim. The aggregate stats block
	// (renderRawStats) still arrives interleaved; ParseRaw passes those
	// lines through too so the operator sees the full firmware output.
	// Same underlying device command (`sniffraw`), different shape on the
	// wire — Packet Monitor uses `sniffraw`, Sniff Raw uses this entry.
	"sniffraw_lines": {
		build: staticCmd("sniffraw"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseRaw, "raw"),
		kind:  "raw",
		risk:  risk.Low,
	},
	"sniffdeauth": {
		build: staticCmd("sniffdeauth"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseSniffDeauth, "deauth_seen"),
		kind:  "deauth_seen",
		risk:  risk.High,
	},
	"packetcount": {
		build: staticCmd("packetcount"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParsePacketCount, "packet_rate"),
		kind:  "packet_rate",
		risk:  risk.Low,
	},

	// Attacks — same parser (rate ticker) + status events.
	"attack_deauth": {
		build: staticCmd("attack -t deauth"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseAttackStatus, "attack_status"),
		kind:  "attack_status",
		risk:  risk.Critical,
	},
	"attack_beacon_random": {
		build: staticCmd("attack -t beacon -r"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseAttackStatus, "attack_status"),
		kind:  "attack_status",
		risk:  risk.Critical,
	},
	"attack_beacon_list": {
		build: staticCmd("attack -t beacon -l"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseAttackStatus, "attack_status"),
		kind:  "attack_status",
		risk:  risk.Critical,
	},
	"attack_beacon_ap": {
		build: staticCmd("attack -t beacon -a"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseAttackStatus, "attack_status"),
		kind:  "attack_status",
		risk:  risk.Critical,
	},
	"attack_probe": {
		build: staticCmd("attack -t probe"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseAttackStatus, "attack_status"),
		kind:  "attack_status",
		risk:  risk.Critical,
	},
	"attack_rickroll": {
		build: staticCmd("attack -t rickroll"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseAttackStatus, "attack_status"),
		kind:  "attack_status",
		risk:  risk.Critical,
	},

	// Evil portal — start emits status updates as the firmware progresses.
	"evilportal_start": {
		build: staticCmd("evilportal -c start"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseEvilPortal, "portal_status"),
		kind:  "portal_status",
		risk:  risk.Critical,
	},

	// BLE — upstream firmware uses sniffbt / blespam / wardrive.
	"blescan": {
		// `sniffbt` with no -t triggers BT_SCAN_ALL.
		build: func(args map[string]any) (string, error) {
			t := strings.TrimSpace(stringArg(args, "target"))
			switch t {
			case "", "all":
				return "sniffbt", nil
			case "apple", "samsung", "flipper", "airtag", "flock", "meta":
				return "sniffbt -t " + t, nil
			default:
				return "", fmt.Errorf("invalid blescan target %q", t)
			}
		},
		mode: modeStream,
		emit: emitWith(parsers.ParseBLESniff, "ble_seen"),
		kind: "ble_seen",
		risk: risk.Low,
	},
	"blewardrive": {
		build: staticCmd("wardrive"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseBLEWardrive, "ble_wardrive"),
		kind:  "ble_wardrive",
		risk:  risk.Low,
	},
	"blespam": {
		build: func(args map[string]any) (string, error) {
			t := strings.TrimSpace(stringArg(args, "target"))
			switch t {
			case "apple", "google", "samsung", "windows", "flipper", "all":
				return "blespam -t " + t, nil
			default:
				return "", fmt.Errorf("invalid blespam target %q", t)
			}
		},
		mode: modeStream,
		emit: emitWith(parsers.ParseAttackStatus, "attack_status"),
		kind: "attack_status",
		risk: risk.High,
	},

	// GPS.
	"gpsdata": {
		build:           staticCmd("gpsdata"),
		mode:            modeBlock,
		emit:            emitBlockWith(parsers.ParseGPSData, "gps"),
		kind:            "gps",
		blockTerminator: "==== GPS Data ====",
		risk:            risk.Low,
	},
	"nmea": {
		build: staticCmd("nmea"),
		mode:  modeStream,
		emit:  emitWith(parsers.ParseRaw, "nmea_line"),
		kind:  "nmea_line",
		risk:  risk.Low,
	},

	// Storage.
	"ls": {
		build: func(args map[string]any) (string, error) {
			path := strings.TrimSpace(stringArg(args, "path"))
			if path == "" {
				path = "/"
			}
			// Same sanitisation surface as marauder.StorageLS — strip
			// CR / LF / NUL / quote so a hostile path can't break out
			// of the quoted form.
			path = sanitizePath(path)
			return fmt.Sprintf(`ls "%s"`, path), nil
		},
		mode:    modeStream,
		emit:    emitWith(parsers.ParseLs, "ls_entry"),
		kind:    "ls_entry",
		timeout: 5 * time.Second,
		risk:    risk.Low,
	},

	// LED — one-shot, no per-event payload, just an ack/done.
	"led_set": {
		build: func(args map[string]any) (string, error) {
			hex := strings.TrimSpace(stringArg(args, "hex"))
			hex = strings.TrimPrefix(strings.TrimPrefix(hex, "#"), "0x")
			if len(hex) != 6 || !isHex6(hex) {
				return "", fmt.Errorf("invalid led hex %q", hex)
			}
			return "led -s " + hex, nil
		},
		mode:    modeExec,
		kind:    "led_ack",
		timeout: 5 * time.Second,
		risk:    risk.Low,
	},
	"led_rainbow": {
		build:   staticCmd("led -p rainbow"),
		mode:    modeExec,
		kind:    "led_ack",
		timeout: 5 * time.Second,
		risk:    risk.Low,
	},

	// Universal stop — the registry entry is here so stop maps to the
	// same dispatch surface, but handleMarauderCmd short-circuits and
	// cancels the running stream first.
	"stop": {
		build:   staticCmd("stopscan"),
		mode:    modeExec,
		kind:    "stopped",
		timeout: 5 * time.Second,
		risk:    risk.Low,
	},
}

// staticCmd returns a build func that always emits literalCmd unchanged.
func staticCmd(literalCmd string) func(map[string]any) (string, error) {
	return func(_ map[string]any) (string, error) { return literalCmd, nil }
}

// stringArg pulls a string-valued field from args; returns "" on miss.
func stringArg(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	v, ok := args[key]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// sanitizePath strips bytes that would break out of the `ls "<path>"` quoting.
// Keeps spaces (SD paths legitimately contain them); strips CR/LF/NUL/quote.
func sanitizePath(s string) string {
	repl := strings.NewReplacer("\r", "", "\n", "", "\x00", "", `"`, "")
	return repl.Replace(s)
}

// isHex6 reports whether s is exactly 6 hex characters.
func isHex6(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// emitWith adapts a per-line parser into an emit func.
func emitWith[T any](parser func(string) (T, bool), kind string) func(*Server, *sessionConn, string, string, []string) {
	return func(s *Server, c *sessionConn, _, line string, _ []string) {
		ev, ok := parser(line)
		if !ok {
			return
		}
		s.sendTo(c, map[string]any{
			"type":    "marauder_event",
			"kind":    kind,
			"payload": ev,
		})
	}
}

// emitBlockWith adapts a block parser into an emit func that reads the block
// param.
func emitBlockWith[T any](parser func([]string) (T, bool), kind string) func(*Server, *sessionConn, string, string, []string) {
	return func(s *Server, c *sessionConn, _, _ string, block []string) {
		ev, ok := parser(block)
		if !ok {
			return
		}
		s.sendTo(c, map[string]any{
			"type":    "marauder_event",
			"kind":    kind,
			"payload": ev,
		})
	}
}

// ---- WS handlers ----

// handleMarauderAcquire registers c as the synth-panel holder. The Marauder
// mirror coexists with the Flipper mirror; the only mutual-exclusion is
// against another Marauder hold. Sends an initial `marauder_status` so the
// client can render the connection / port / firmware pill at panel open.
func (s *Server) handleMarauderAcquire(c *sessionConn) {
	if s.marauder == nil {
		s.sendTo(c, map[string]any{
			"type":    "marauder_error",
			"cmd":     "",
			"message": "no marauder attached",
		})
		return
	}
	s.marauderMu.Lock()
	if s.marauderHolder != nil && s.marauderHolder != c {
		holderID := s.marauderHolder.id
		s.marauderMu.Unlock()
		s.sendTo(c, map[string]any{
			"type":              "marauder_error",
			"cmd":               "",
			"message":           "marauder already in use",
			"holder_session_id": holderID,
		})
		return
	}
	// Set marauderHolder and marauderActive together under
	// marauderMu so they transition atomically — mirrors the v0.143
	// fix on the Flipper screen mirror. Previously
	// marauderActive.Store(true) ran after Unlock, opening a window
	// where a racing releaseMarauder's trailing Store(false) could
	// stomp this Store(true) and leave marauderHolder!=nil but
	// marauderActive==false.
	s.marauderHolder = c
	s.marauderActive.Store(true)
	s.marauderMu.Unlock()

	port, fw := "", ""
	s.marauderInfoMu.Lock()
	port = s.marauderPort
	fw = s.marauderFirmware
	s.marauderInfoMu.Unlock()

	s.sendTo(c, map[string]any{
		"type":      "marauder_status",
		"connected": s.marauderOn.Load(),
		"port":      port,
		"firmware":  fw,
	})
}

// handleMarauderRelease releases c if it is the current holder. Idempotent
// when called by a non-holder.
func (s *Server) handleMarauderRelease(c *sessionConn) {
	s.marauderMu.Lock()
	if s.marauderHolder != c {
		s.marauderMu.Unlock()
		return
	}
	s.marauderMu.Unlock()
	s.releaseMarauder("released")
}

// handleMarauderCmd dispatches a marauder_cmd. action ∈ {"start", "once",
// "stop"}; defaults to "start". Errors are reported back as marauder_error.
func (s *Server) handleMarauderCmd(c *sessionConn, cmdKey, action string, args map[string]any) {
	if s.marauder == nil {
		s.sendTo(c, map[string]any{
			"type":    "marauder_error",
			"cmd":     cmdKey,
			"message": "no marauder attached",
		})
		return
	}
	s.marauderMu.Lock()
	holder := s.marauderHolder
	s.marauderMu.Unlock()
	if holder != c {
		s.sendTo(c, map[string]any{
			"type":    "marauder_error",
			"cmd":     cmdKey,
			"message": "not marauder holder; send marauder_acquire first",
		})
		return
	}

	// `stop` short-circuits: cancel any running stream, then send a fresh
	// stopscan so the device returns to its idle prompt.
	if action == "stop" {
		s.cancelMarauderStream()
		// Best-effort send a stopscan; ignore errors.
		_, _ = s.marauder.Exec("stopscan", 2*time.Second)
		s.sendTo(c, map[string]any{
			"type": "marauder_done",
			"cmd":  cmdKey,
		})
		return
	}

	entry, ok := marauderRegistry[cmdKey]
	if !ok {
		s.sendTo(c, map[string]any{
			"type":    "marauder_error",
			"cmd":     cmdKey,
			"message": fmt.Sprintf("unknown command %q", cmdKey),
		})
		return
	}

	cliCmd, err := entry.build(args)
	if err != nil {
		s.sendTo(c, map[string]any{
			"type":    "marauder_error",
			"cmd":     cmdKey,
			"message": err.Error(),
		})
		return
	}

	start := time.Now()

	// Gate risk≥High behind operator consent before touching the device.
	if entry.risk >= risk.High {
		if !s.marauderConfirmGate(c, cmdKey, entry.risk, args, start) {
			return
		}
	}

	// Audit the allowed dispatch.
	if s.auditLog != nil {
		s.auditLog.RecordCtx(context.Background(), "web.marauder."+cmdKey, args, "", entry.risk.String(), audit.LevelAction, time.Since(start), true)
	}

	switch entry.mode {
	case modeExec:
		go s.runMarauderExec(c, cmdKey, cliCmd, entry)
	case modeStream:
		// Cancel any prior stream first; only one streaming command at a
		// time per holder.
		s.cancelMarauderStream()
		go s.runMarauderStream(c, cmdKey, cliCmd, entry, false)
	case modeBlock:
		s.cancelMarauderStream()
		go s.runMarauderStream(c, cmdKey, cliCmd, entry, true)
	}
}

// marauderConfirmGate blocks until the operator approves or denies the command
// via the WebSocket confirm round-trip. It reuses s.confirms (same channel map
// as chat-driven confirms) so the existing deliverConfirm path routes responses
// here automatically.
//
// Returns true when the operator approves after the minimum delay has elapsed.
// On denial, timeout, or a too-fast approval it audits the attempt with
// success=false, sends marauder_error to the client, and returns false.
func (s *Server) marauderConfirmGate(c *sessionConn, cmdKey string, lvl risk.Level, args map[string]any, start time.Time) bool {
	nonce := newID()
	ch := make(chan agent.ConfirmResponse, 1)
	s.mu.Lock()
	s.confirms[nonce] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.confirms, nonce)
		s.mu.Unlock()
	}()

	// Emit the confirm request and start the minimum-delay gate.
	gate := agent.NewConfirmDelayGate(agent.MinimumConfirmDelay)
	s.sendTo(c, map[string]any{
		"type":       "marauder_confirm_request",
		"cmd":        cmdKey,
		"risk":       lvl.String(),
		"confirm_id": nonce,
	})
	gate.Show()

	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	deny := func(msg string) bool {
		if s.auditLog != nil {
			s.auditLog.RecordCtx(context.Background(), "web.marauder."+cmdKey, args, "", lvl.String(), audit.LevelAction, time.Since(start), false)
		}
		s.sendTo(c, map[string]any{"type": "marauder_error", "cmd": cmdKey, "message": msg})
		return false
	}

	select {
	case resp := <-ch:
		if resp.Decision == agent.DecisionApprove || resp.Decision == agent.DecisionApproveAll {
			if !gate.Open() {
				return deny("confirm rejected — minimum delay not elapsed")
			}
			return true
		}
		return deny("command denied")
	case <-timer.C:
		return deny("confirm timeout")
	}
}

// runMarauderExec runs a one-shot Exec, optionally parses the result, and
// emits marauder_event + marauder_done.
func (s *Server) runMarauderExec(c *sessionConn, cmdKey, cliCmd string, entry commandEntry) {
	timeout := entry.timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	out, err := s.marauder.Exec(cliCmd, timeout)
	if err != nil {
		s.sendTo(c, map[string]any{
			"type":    "marauder_error",
			"cmd":     cmdKey,
			"message": err.Error(),
		})
		return
	}
	if entry.emit != nil {
		// For Exec the body is the full multi-line response. Treat it as
		// either a block (block-style emit) or per-line (line emit).
		lines := splitLines(out)
		// Heuristic: if the entry uses an emit built by emitBlockWith
		// (block parser), call it once with the whole block. We can't
		// easily distinguish that at the call site, so the convention
		// is: line-style emit functions call parser on each line; block
		// emits call the parser once with the full block. The wrappers
		// (emitWith vs emitBlockWith) handle the distinction internally:
		// a line emit ignores `block`, a block emit ignores `line`.
		entry.emit(s, c, entry.kind, "", lines)
		for _, l := range lines {
			entry.emit(s, c, entry.kind, l, nil)
		}
	}
	s.sendTo(c, map[string]any{
		"type": "marauder_done",
		"cmd":  cmdKey,
	})
}

// runMarauderStream opens a Stream and pumps lines into the per-line or
// block emit. Closes on ctx.Done; the marauder package writes stopscan
// automatically when its done channel closes.
func (s *Server) runMarauderStream(c *sessionConn, cmdKey, cliCmd string, entry commandEntry, blockMode bool) {
	ctx, cancel := context.WithCancel(context.Background())
	s.marauderMu.Lock()
	s.marauderCancel = cancel
	s.marauderRunning = cmdKey
	s.marauderMu.Unlock()

	defer func() {
		s.marauderMu.Lock()
		// Only clear if we're still the active stream; a stop / new
		// command may have rotated it under us.
		if s.marauderRunning == cmdKey {
			s.marauderRunning = ""
			s.marauderCancel = nil
		}
		s.marauderMu.Unlock()
		s.sendTo(c, map[string]any{
			"type": "marauder_done",
			"cmd":  cmdKey,
		})
	}()

	lines, done, err := s.marauder.Stream(cliCmd)
	if err != nil {
		s.sendTo(c, map[string]any{
			"type":    "marauder_error",
			"cmd":     cmdKey,
			"message": err.Error(),
		})
		cancel()
		return
	}

	// Ensure done is closed exactly once; the stream's defer needs that
	// signal so it sends `stopscan` and tears down its goroutine.
	doneClosed := false
	closeDone := func() {
		if doneClosed {
			return
		}
		doneClosed = true
		close(done)
	}
	defer closeDone()

	var block []string
	for {
		select {
		case <-ctx.Done():
			closeDone()
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			if entry.emit == nil {
				continue
			}
			if !blockMode {
				entry.emit(s, c, entry.kind, line, nil)
				continue
			}
			// Block-mode path: accumulate, flush on terminator or every-N.
			if entry.blockTerminator != "" && strings.HasPrefix(strings.TrimSpace(line), entry.blockTerminator) {
				if len(block) > 0 {
					entry.emit(s, c, entry.kind, "", block)
					block = block[:0]
				}
				continue
			}
			block = append(block, line)
			if entry.blockEvery > 0 && len(block) >= entry.blockEvery {
				entry.emit(s, c, entry.kind, "", block)
				block = block[:0]
			}
		}
	}
}

// cancelMarauderStream cancels the running stream goroutine if any.
func (s *Server) cancelMarauderStream() {
	s.marauderMu.Lock()
	cancel := s.marauderCancel
	s.marauderCancel = nil
	s.marauderRunning = ""
	s.marauderMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// releaseMarauder is the single funnel for all release paths: explicit
// release, holder disconnect, error during acquire. Idempotent.
func (s *Server) releaseMarauder(reason string) {
	s.marauderMu.Lock()
	if s.marauderHolder == nil {
		s.marauderMu.Unlock()
		return
	}
	cancel := s.marauderCancel
	s.marauderHolder = nil
	s.marauderCancel = nil
	s.marauderRunning = ""
	// Clear marauderActive inside marauderMu so it transitions
	// atomically with the holder reset — same v0.143 contract used
	// for the Flipper screen mirror. The previous form stored false
	// after Unlock, letting a racing handleMarauderAcquire's
	// Store(true) land in between and then be stomped.
	s.marauderActive.Store(false)
	s.marauderMu.Unlock()
	if cancel != nil {
		cancel()
	}
	_ = reason // reserved for audit hookup later
}

// splitLines normalises CRLF and splits the response body into non-empty
// trimmed lines.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	parts := strings.Split(s, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimRight(p, " \t\r")
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
