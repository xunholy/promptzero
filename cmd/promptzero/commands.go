package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/mqtt"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/validator"
	"github.com/xunholy/promptzero/internal/version"
	"github.com/xunholy/promptzero/internal/voice"
	"github.com/xunholy/promptzero/internal/watch"
	"github.com/xunholy/promptzero/internal/webhook"
)

// REPLDeps bundles the subsystem handles and UI references the REPL loop
// and its slash-command dispatcher share. Populated in run() once every
// subsystem is wired, then passed by pointer so dispatchSlashCommand and
// enterREPL don't need 20-arg signatures.
//
// Fields split into two groups by lifetime: the inputs (ctx..watchPaths)
// are set before enterREPL is entered, and the REPL-owned fields
// (ed, watchMgr, busy) are populated by enterREPL itself once the
// editor and watch goroutines are live.
type REPLDeps struct {
	ctx           context.Context
	sh            *signalHandler
	cfg           *config.Config
	ai            *agent.Agent
	flip          *flipper.Flipper
	genLLM        provider.Provider
	hasMarauder   bool
	voiceEngine   *voice.Engine
	voiceMode     bool
	auditLog      *audit.Log
	rec           *obs.Recorder
	activePersona *persona.Persona
	personas      *persona.Registry
	costTracker   *cost.Tracker
	wh            webhook.Dispatcher
	mqttBridge    *mqtt.Bridge
	ruleEngine    *rules.Engine
	gateEnabled   bool
	watchPaths    []string

	// REPL-owned (populated inside enterREPL).
	ed       *lineEditor
	watchMgr *watch.Watcher
	busy     func() bool
}

// hasVoice reports whether the voice engine is configured.
func (d *REPLDeps) hasVoice() bool { return d.voiceEngine != nil }

// dispatchSlashCommand routes an already-trimmed REPL line to the matching
// slash-command handler. Returns (handled, shouldExit): handled=true means
// the caller should skip the turn-dispatch path; shouldExit=true means the
// REPL should tear down. Non-slash input falls through with handled=false.
func dispatchSlashCommand(input string, deps *REPLDeps) (handled bool, shouldExit bool) {
	ed := deps.ed
	lower := strings.ToLower(input)
	switch lower {
	case "/quit", "/exit", "quit", "exit", "q":
		ed.writeOutput(func() {
			fmt.Fprintf(os.Stderr, "\n  %sShutting down.%s\n\n", dim, reset)
		})
		return true, true
	case "/reset", "/clear", "reset", "clear":
		deps.ai.Reset()
		ed.writeOutput(func() {
			fmt.Fprintf(os.Stderr, "  %s● Conversation cleared.%s\n\n", green, reset)
		})
		return true, false
	case "/help", "?":
		ed.writeOutput(func() { printHelp() })
		return true, false
	case "/status":
		ed.writeOutput(func() {
			printStatus(deps.cfg, deps.ai, deps.genLLM, deps.hasMarauder, deps.hasVoice(), deps.auditLog, deps.flip, deps.busy)
		})
		return true, false
	case "/sessions":
		ed.writeOutput(func() { printSessions(deps.ai) })
		return true, false
	case "/debug":
		ed.writeOutput(func() {
			renderDebugSnapshot(os.Stderr, deps.cfg, deps.rec, deps.activePersona, deps.flip, deps.hasMarauder, deps.auditLog, deps.ai, deps.costTracker)
		})
		return true, false
	case "/cost":
		ed.writeOutput(func() {
			s := deps.costTracker.Snapshot()
			fmt.Fprintf(os.Stderr, "  %s\n", s.Format())
		})
		return true, false
	case "/reconnect":
		// Force-reconnect to the Flipper. The SetReconnectCallback
		// registered in the REPL surfaces phase messages in the
		// output area; we just need to call it. Short ctx so a stuck
		// reconnect doesn't wedge the REPL indefinitely.
		go func() {
			reCtx, cancelRe := context.WithTimeout(deps.ctx, 15*time.Second)
			defer cancelRe()
			if err := deps.flip.Reconnect(reCtx); err != nil {
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "  %s● reconnect failed: %v%s\n", red, err, reset)
				})
			}
		}()
		return true, false
	}

	fields := strings.Fields(input)
	if len(fields) == 0 {
		return false, false
	}
	head := strings.ToLower(fields[0])
	if !strings.HasPrefix(head, "/") {
		return false, false
	}
	switch head {
	case "/history":
		n := 20
		if len(fields) > 1 {
			if parsed, err := strconv.Atoi(fields[1]); err == nil && parsed > 0 {
				n = parsed
			}
		}
		ed.writeOutput(func() { printHistory(deps.auditLog, n) })
		return true, false
	case "/audit":
		ed.writeOutput(func() { handleAudit(deps.auditLog, fields[1:]) })
		return true, false
	case "/persona":
		ed.writeOutput(func() { handlePersona(deps.ai, deps.personas, fields[1:]) })
		return true, false
	case "/watch":
		ed.writeOutput(func() { handleWatchCmd(deps.watchMgr, fields[1:]) })
		return true, false
	case "/webhooks":
		ed.writeOutput(func() { handleWebhooksCmd(deps.wh, fields[1:]) })
		return true, false
	case "/mqtt":
		ed.writeOutput(func() { handleMQTTCmd(deps.mqttBridge, fields[1:]) })
		return true, false
	case "/rules":
		ed.writeOutput(func() { handleRulesCmd(deps.ruleEngine, fields[1:]) })
		return true, false
	case "/tools":
		filter := ""
		if len(fields) > 1 {
			filter = fields[1]
		}
		ed.writeOutput(func() { printTools(deps.hasMarauder, filter) })
		return true, false
	case "/resume":
		if len(fields) < 2 {
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %susage: /resume <session-id>%s\n", dim, reset)
			})
			return true, false
		}
		id := fields[1]
		ed.writeOutput(func() {
			if err := deps.ai.ResumeSession(id); err != nil {
				fmt.Fprintf(os.Stderr, "  %s● resume failed: %v%s\n", red, err, reset)
			} else {
				fmt.Fprintf(os.Stderr, "  %s● resumed session %s%s%s\n", green, bold, id, reset)
			}
		})
		return true, false
	case "/save":
		if len(fields) < 2 {
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %susage: /save <name>%s\n", dim, reset)
			})
			return true, false
		}
		name := fields[1]
		ed.writeOutput(func() {
			if err := deps.ai.SaveSessionAs(name); err != nil {
				fmt.Fprintf(os.Stderr, "  %s● save failed: %v%s\n", red, err, reset)
			} else {
				fmt.Fprintf(os.Stderr, "  %s● saved session as %s%s%s\n", green, bold, name, reset)
			}
		})
		return true, false
	case "/validate":
		if len(fields) < 2 {
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %susage: /validate <path-on-flipper>%s\n", dim, reset)
			})
			return true, false
		}
		path := fields[1]
		ed.writeOutput(func() { handleValidate(deps.flip, path) })
		return true, false
	}
	return false, false
}

// handleValidate reads a BadUSB/DuckyScript payload off the Flipper SD card
// and prints the validator Report. Gives operators a way to triage a script
// before running it — without spinning up badusb_run just to see the gate.
func handleValidate(flip *flipper.Flipper, path string) {
	if flip == nil {
		fmt.Fprintf(os.Stderr, "  %s● /validate needs a connected Flipper%s\n", red, reset)
		return
	}
	raw, err := flip.StorageRead(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● read %s failed: %v%s\n", red, path, err, reset)
		return
	}
	rep := validator.Validate(path, raw)
	label := green + "●"
	switch rep.Severity {
	case validator.SeverityWarn:
		label = yellow + "●"
	case validator.SeverityCritical:
		label = red + "●"
	}
	fmt.Fprintf(os.Stderr, "  %s%s %s\n", label, reset, strings.TrimRight(rep.RenderText(), "\n"))
}

// --- /help ---------------------------------------------------------------

func printHelp() {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  %s%sCommands%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "  %sConversation%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %s/help%s, %s?%s            Show this help\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/reset%s, %s/clear%s      Clear conversation history\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/quit%s, %s/exit%s, %sq%s    Exit promptzero\n", cyan, reset, cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %sSession%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %s/sessions%s              List saved sessions\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/resume <id>%s           Resume a saved session by id\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/save <name>%s           Save current conversation under <name>\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %sInfo%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %s/status%s                Connection, capabilities, Flipper telemetry\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/tools [filter]%s        Enumerate registered tools (grouped)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/history [N]%s           Show last N audit rows (default 20)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit stats%s           Session audit summary\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit find k=v ...%s    Query rows (tool, risk, since, until, contains, success, limit, offset)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit tail%s            Live tail of new audit rows (Ctrl+C or Enter to stop)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit top tools|risks%s Top-N aggregations (since=24h etc.)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit session <id>%s    Dump a specific session\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit export <path>%s   Write session audit JSON to <path>\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %sOperator%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %s/persona [name]%s        Show or switch active persona (resets conversation)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/watch [pause|resume]%s  Show watched paths, pause/resume FS triggers\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/webhooks [test <name>]%s List outbound webhooks with recent deliveries\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/mqtt [test]%s           Show MQTT bridge status (and publish a synthetic ping)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/validate <path>%s       Lint a BadUSB .txt payload on the Flipper SD card\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %sDevice%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %s/reconnect%s             Force reconnect to the Flipper (after replug / USB hiccup)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %sInput%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %sEnter%s (blank, voice)   In voice mode, records; otherwise no-op\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sCtrl+C%s                 Cancel in-flight turn (press again within 2s to exit)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sCtrl+D%s                 Exit on empty input\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sCtrl+L%s                 Clear screen\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sUp%s/%sDown%s                 Browse history\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sCtrl+A%s/%sCtrl+E%s          Move cursor to line start / end\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sFlipper device feedback%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s●%s Blue LED on          Flipper is actively scanning (RFID/NFC/SubGHz/IR/iButton)\n", blue, reset)
	fmt.Fprintf(os.Stderr, "    %s●%s Vibration buzz       Tag/signal detected and read successfully\n", green, reset)
	fmt.Fprintf(os.Stderr, "    %s●%s Idle                 Scan timed out (nothing detected)\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %sCLI commands like `rfid read` do NOT launch an on-screen app on the Flipper.%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %sTheir only visible indicator is the LED/vibro feedback above.%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sAgent / tool-call legend%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s▸%s tool {args}          Tool is executing\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s◦%s tool (1.3s)          Tool completed\n", green, reset)
	fmt.Fprintf(os.Stderr, "    %s✗%s tool (15s)           Tool errored or timed out\n", red, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sRisk confirmation%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s⚠%s tool {args}          Awaiting approval (high/critical risk)\n", yellow, reset)
	fmt.Fprintf(os.Stderr, "    %sy%s approve · %sN%s / Enter deny (default) · type %sall%s + Enter to approve all remaining\n",
		bold+green, reset, bold+red, reset, bold+cyan, reset)
	fmt.Fprintf(os.Stderr, "    Use %s--yolo%s to disable, or %s--confirm-risk=<level>%s to adjust threshold.\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "\n")
}

// --- /status --------------------------------------------------------------

func printStatus(cfg *config.Config, ai *agent.Agent, genLLM provider.Provider, wifi bool, hasVoice bool, auditLog *audit.Log, flip *flipper.Flipper, busy func() bool) {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  %s%sStatus%s\n", bold, white, reset)
	if tx := flip.Transport(); tx != nil {
		statusOK(fmt.Sprintf("Flipper Zero on %s (%s)", tx.Identity(), tx.Kind()))
	} else {
		statusOK(fmt.Sprintf("Flipper Zero on %s", cfg.Serial.Port))
	}
	statusOK(fmt.Sprintf("Agent model: %s", cfg.Model))
	statusOK(fmt.Sprintf("Generation: %s", genLLM.Name()))
	if wifi {
		statusOK(fmt.Sprintf("Marauder on %s", cfg.Marauder.Port))
	} else {
		statusWarn("Marauder not connected (use --wifi)")
	}
	if hasVoice {
		statusOK("Voice input (Whisper)")
	} else {
		statusWarn("Voice not configured (set OPENAI_API_KEY)")
	}
	if auditLog != nil {
		statusOK(fmt.Sprintf("Audit session: %s", auditLog.SessionID()))
	} else {
		statusWarn("Audit logging disabled")
	}
	if p := ai.Persona(); p != nil {
		if len(p.Tools) == 0 {
			statusOK(fmt.Sprintf("Persona: %s (all tools)", p.Name))
		} else {
			statusOK(fmt.Sprintf("Persona: %s (%d tools allowed)", p.Name, len(p.Tools)))
		}
	} else {
		statusInfo("Persona: default")
	}

	fmt.Fprintf(os.Stderr, "\n  %s%sDevice%s\n", bold, white, reset)
	if flip == nil {
		statusWarn("Flipper unavailable")
	} else {
		summary := cachedDeviceSummary(flip, busy)
		fmt.Fprintf(os.Stderr, "  %s%s%s\n", dim, summary, reset)
	}
	fmt.Fprintf(os.Stderr, "\n")
}

// --- Device telemetry cache (P6) -----------------------------------------

var deviceCache struct {
	sync.Mutex
	at      time.Time
	summary string
}

const deviceCacheTTL = 5 * time.Second

func cachedDeviceSummary(flip *flipper.Flipper, busy func() bool) string {
	deviceCache.Lock()
	defer deviceCache.Unlock()
	if time.Since(deviceCache.at) < deviceCacheTTL && deviceCache.summary != "" {
		return deviceCache.summary
	}
	if busy != nil && busy() {
		if deviceCache.summary != "" {
			return deviceCache.summary + "  (stale, turn in flight)"
		}
		return "(turn in flight — skipping device fetch)"
	}
	s := deviceSummary(flip)
	deviceCache.at = time.Now()
	deviceCache.summary = s
	return s
}

func deviceSummary(flip *flipper.Flipper) string {
	var parts []string
	// PowerInfoMap normalises dot-separated keys (info power on
	// Xtreme/Momentum emits `charge.level`; stock/Unleashed's power_info
	// uses `charge_level`). Reading from the map means the REPL battery
	// line works on every fork, whereas scanning raw text only matched
	// stock-style underscores.
	if kv, err := flip.PowerInfoMap(); err == nil {
		if pct := kv["charge_level"]; pct != "" {
			parts = append(parts, "Battery "+pct+"%")
		} else if pct := kv["battery_charge"]; pct != "" {
			parts = append(parts, "Battery "+pct+"%")
		}
	}
	if raw, err := flip.DeviceInfo(); err == nil {
		if fw := parseKVField(raw, "firmware_version"); fw != "" {
			parts = append(parts, "FW "+fw)
		} else if fw := parseKVField(raw, "hardware_model"); fw != "" {
			parts = append(parts, "HW "+fw)
		}
	}
	if raw, err := flip.StorageStat("/ext"); err == nil {
		line := strings.TrimSpace(firstLine(raw))
		if line != "" {
			parts = append(parts, "SD "+line)
		}
	}
	if len(parts) == 0 {
		return "no telemetry available"
	}
	return strings.Join(parts, " · ")
}

// parseKVField scans a Flipper CLI key/value dump for "<key>: <value>" or
// "<key> : <value>" lines and returns the trimmed value. Empty string if
// the key is absent.
func parseKVField(raw, key string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(trim, key) {
			continue
		}
		rest := strings.TrimPrefix(trim, key)
		rest = strings.TrimLeft(rest, " \t:")
		rest = strings.TrimSpace(rest)
		if rest != "" {
			return rest
		}
	}
	return ""
}

// --- /history + /audit ----------------------------------------------------

func printHistory(auditLog *audit.Log, n int) {
	if auditLog == nil {
		fmt.Fprintf(os.Stderr, "  %saudit log not available%s\n", dim, reset)
		return
	}
	if n <= 0 {
		n = 20
	}
	entries, err := auditLog.Query(n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● history error: %v%s\n", red, err, reset)
		return
	}
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "  %sno audit entries yet%s\n", dim, reset)
		return
	}
	for _, e := range entries {
		ts := e.Timestamp.Local().Format("15:04:05")
		input := collapseWS(e.Input)
		if len(input) > 40 {
			input = input[:39] + "…"
		}
		errMark := ""
		if !e.Success {
			errMark = " " + red + "✗" + reset
		}
		color := riskColor(e.Risk)
		risk := e.Risk
		if risk == "" {
			risk = "-"
		}
		fmt.Fprintf(os.Stderr, "  %s  %s[%s]%s  %s  %s(%dms)%s%s  %s%s%s\n",
			ts, color, risk, reset, e.Tool, dim, e.Duration, reset, errMark, dim, input, reset)
	}
}

func handleAudit(auditLog *audit.Log, args []string) {
	if auditLog == nil {
		fmt.Fprintf(os.Stderr, "  %saudit log not available%s\n", dim, reset)
		return
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "  %susage: /audit stats|find|tail|top|session|query|export%s\n", dim, reset)
		return
	}
	switch strings.ToLower(args[0]) {
	case "stats":
		s, err := auditLog.Stats()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● audit stats error: %v%s\n", red, err, reset)
			return
		}
		for _, line := range strings.Split(s, "\n") {
			fmt.Fprintf(os.Stderr, "  %s\n", line)
		}
	case "find":
		f, err := parseAuditFilter(mergeQuoted(args[1:]))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● find: %v%s\n", red, err, reset)
			return
		}
		entries, err := auditLog.QueryFiltered(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● find: %v%s\n", red, err, reset)
			return
		}
		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "  %sno matches%s\n", dim, reset)
			return
		}
		for _, e := range entries {
			printAuditEntry(e)
		}
	case "tail":
		tailAudit(auditLog)
	case "top":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %susage: /audit top tools|risks [since=24h]%s\n", dim, reset)
			return
		}
		var since time.Time
		for _, a := range args[2:] {
			if strings.HasPrefix(a, "since=") {
				t, err := parseWhen(strings.TrimPrefix(a, "since="))
				if err != nil {
					fmt.Fprintf(os.Stderr, "  %s● top: %v%s\n", red, err, reset)
					return
				}
				since = t
			}
		}
		switch strings.ToLower(args[1]) {
		case "tools":
			rows, err := auditLog.TopTools(since, 10)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %s● top tools: %v%s\n", red, err, reset)
				return
			}
			if len(rows) == 0 {
				fmt.Fprintf(os.Stderr, "  %sno data%s\n", dim, reset)
				return
			}
			for _, r := range rows {
				fmt.Fprintf(os.Stderr, "  %s%-24s%s  %d\n", cyan, r.Tool, reset, r.Count)
			}
		case "risks":
			rows, err := auditLog.TopRisks(since)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %s● top risks: %v%s\n", red, err, reset)
				return
			}
			if len(rows) == 0 {
				fmt.Fprintf(os.Stderr, "  %sno data%s\n", dim, reset)
				return
			}
			for _, r := range rows {
				label := r.Risk
				if label == "" {
					label = "-"
				}
				fmt.Fprintf(os.Stderr, "  %s[%-8s]%s  %d\n", riskColor(r.Risk), label, reset, r.Count)
			}
		default:
			fmt.Fprintf(os.Stderr, "  %sunknown /audit top target %q (want tools|risks)%s\n", dim, args[1], reset)
		}
	case "session":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %susage: /audit session <id>%s\n", dim, reset)
			return
		}
		entries, err := auditLog.QueryBySession(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● session: %v%s\n", red, err, reset)
			return
		}
		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "  %sno entries for session %s%s\n", dim, args[1], reset)
			return
		}
		for _, e := range entries {
			printAuditEntry(e)
		}
	case "query":
		n := 20
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
				n = v
			}
		}
		printHistory(auditLog, n)
	case "export":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %susage: /audit export <path>%s\n", dim, reset)
			return
		}
		path := args[1]
		data, err := auditLog.Export()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● export error: %v%s\n", red, err, reset)
			return
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "  %s● write error: %v%s\n", red, err, reset)
			return
		}
		fmt.Fprintf(os.Stderr, "  %s●%s wrote %s\n", green, reset, path)
	default:
		fmt.Fprintf(os.Stderr, "  %sunknown /audit subcommand %q%s\n", dim, args[0], reset)
	}
}

// mergeQuoted re-stitches tokens that were split inside a double-quoted
// value. The REPL splits on whitespace, so `contains="bank card"` arrives
// as `contains="bank` and `card"` — this rejoins them and strips the
// wrapping quotes once the closing quote is seen.
func mergeQuoted(in []string) []string {
	var out []string
	var buf []string
	inside := false
	for _, tok := range in {
		if !inside {
			if strings.Count(tok, "\"")%2 == 1 {
				inside = true
				buf = append(buf[:0], tok)
				continue
			}
			out = append(out, strings.ReplaceAll(tok, "\"", ""))
			continue
		}
		buf = append(buf, tok)
		if strings.Count(tok, "\"")%2 == 1 {
			inside = false
			joined := strings.Join(buf, " ")
			out = append(out, strings.ReplaceAll(joined, "\"", ""))
			buf = buf[:0]
		}
	}
	if len(buf) > 0 {
		out = append(out, strings.ReplaceAll(strings.Join(buf, " "), "\"", ""))
	}
	return out
}

// parseAuditFilter turns `k=v` tokens into an audit.Filter. Unknown keys
// error out so typos don't silently match nothing. Caller should pass
// tokens already run through mergeQuoted so quoted values survive.
func parseAuditFilter(tokens []string) (audit.Filter, error) {
	var f audit.Filter
	for _, t := range tokens {
		eq := strings.IndexByte(t, '=')
		if eq <= 0 {
			return f, fmt.Errorf("expected k=v, got %q", t)
		}
		k := strings.ToLower(strings.TrimSpace(t[:eq]))
		v := strings.TrimSpace(t[eq+1:])
		switch k {
		case "tool":
			f.Tool = v
		case "risk":
			f.Risk = v
		case "session":
			f.Session = v
		case "contains":
			f.Contains = v
		case "since":
			when, err := parseWhen(v)
			if err != nil {
				return f, fmt.Errorf("since: %w", err)
			}
			f.Since = when
		case "until":
			when, err := parseWhen(v)
			if err != nil {
				return f, fmt.Errorf("until: %w", err)
			}
			f.Until = when
		case "success":
			switch strings.ToLower(v) {
			case "true", "1", "yes":
				b := true
				f.Success = &b
			case "false", "0", "no":
				b := false
				f.Success = &b
			default:
				return f, fmt.Errorf("success=%s: want true|false", v)
			}
		case "limit":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return f, fmt.Errorf("limit=%s: want positive int", v)
			}
			f.Limit = n
		case "offset":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return f, fmt.Errorf("offset=%s: want non-negative int", v)
			}
			f.Offset = n
		default:
			return f, fmt.Errorf("unknown key %q", k)
		}
	}
	return f, nil
}

// parseWhen accepts either a relative duration expression like "30m",
// "2h", "7d" (interpreted as "time ago from now") or a full RFC3339
// timestamp. Returned times are always UTC-normalised by the caller
// before being bound to the SQL query.
func parseWhen(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	if n := len(s); n > 1 && (s[n-1] == 'd' || s[n-1] == 'D') {
		days, err := strconv.Atoi(s[:n-1])
		if err == nil && days >= 0 {
			return time.Now().Add(-time.Duration(days) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("cannot parse %q as duration or RFC3339 timestamp", s)
}

// printAuditEntry renders one audit row in the same compact format used
// by /history but prefixed with the row id so /audit find output is
// self-referential for follow-up queries.
func printAuditEntry(e audit.Entry) {
	ts := e.Timestamp.Local().Format("2006-01-02 15:04:05")
	input := collapseWS(e.Input)
	if len(input) > 40 {
		input = input[:39] + "…"
	}
	errMark := ""
	if !e.Success {
		errMark = " " + red + "✗" + reset
	}
	risk := e.Risk
	if risk == "" {
		risk = "-"
	}
	fmt.Fprintf(os.Stderr, "  %s#%-5d%s  %s  %s[%s]%s  %s  %s(%dms)%s%s  %s%s%s\n",
		dim, e.ID, reset, ts, riskColor(e.Risk), risk, reset,
		e.Tool, dim, e.Duration, reset, errMark, dim, input, reset)
}

// tailAudit polls for new audit rows and streams them. Stops on Ctrl+C.
// Poll cadence matches the 500ms target spec.
func tailAudit(auditLog *audit.Log) {
	start, err := auditLog.MaxID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● tail: %v%s\n", red, err, reset)
		return
	}
	fmt.Fprintf(os.Stderr, "  %stailing audit from id %d (Ctrl+C to stop)…%s\n", dim, start, reset)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	after := start
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "  %stail stopped%s\n", dim, reset)
			return
		case <-ticker.C:
			entries, err := auditLog.QuerySince(after)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %s● tail: %v%s\n", red, err, reset)
				return
			}
			for _, e := range entries {
				printAuditEntry(e)
				if e.ID > after {
					after = e.ID
				}
			}
		}
	}
}

func riskColor(r string) string {
	switch strings.ToLower(r) {
	case "low":
		return green
	case "medium":
		return yellow
	case "high":
		return red
	case "critical":
		return bold + red
	default:
		return gray
	}
}

func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// --- /sessions ------------------------------------------------------------

func printSessions(ai *agent.Agent) {
	sessions, err := ai.ListSessions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● sessions: %v%s\n", red, err, reset)
		return
	}
	if len(sessions) == 0 {
		fmt.Fprintf(os.Stderr, "  %sno sessions%s\n", dim, reset)
		return
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].UpdatedAt.After(sessions[j].UpdatedAt)
	})
	for _, s := range sessions {
		fmt.Fprintf(os.Stderr, "  %s%s%s  %s  %s%d msg%s\n",
			bold, s.ID, reset,
			s.UpdatedAt.Local().Format("2006-01-02 15:04"),
			dim, len(s.Messages), reset)
	}
}

// --- /tools ---------------------------------------------------------------

const toolsMaxRows = 40

func printTools(hasMarauder bool, filter string) {
	catalog := agent.ToolCatalog(hasMarauder)
	filtered := catalog
	lowerFilter := strings.ToLower(filter)
	if lowerFilter != "" {
		filtered = filtered[:0:0]
		for _, e := range catalog {
			if strings.Contains(strings.ToLower(e.Name), lowerFilter) {
				filtered = append(filtered, e)
			}
		}
	}
	if len(filtered) == 0 {
		if filter != "" {
			fmt.Fprintf(os.Stderr, "  %sno tools match %q%s\n", dim, filter, reset)
		} else {
			fmt.Fprintf(os.Stderr, "  %sno tools registered%s\n", dim, reset)
		}
		return
	}

	groups := map[string][]agent.ToolCatalogEntry{}
	var order []string
	for _, e := range filtered {
		g := toolGroup(e.Name)
		if _, ok := groups[g]; !ok {
			order = append(order, g)
		}
		groups[g] = append(groups[g], e)
	}
	sort.Strings(order)

	shown := 0
	fmt.Fprintln(os.Stderr)
outer:
	for _, g := range order {
		fmt.Fprintf(os.Stderr, "  %s%s%s%s\n", bold, white, g, reset)
		for _, e := range groups[g] {
			if shown >= toolsMaxRows {
				break outer
			}
			fmt.Fprintf(os.Stderr, "    %s%s%s  %s%s%s\n", cyan, e.Name, reset, dim, toolDescSummary(e.Description), reset)
			shown++
		}
	}
	if shown < len(filtered) {
		hint := "/tools <filter>"
		if filter != "" {
			hint = "use a narrower filter"
		}
		fmt.Fprintf(os.Stderr, "  %s… and %d more, try %s%s\n", dim, len(filtered)-shown, hint, reset)
	}
	fmt.Fprintln(os.Stderr)
}

// toolDescSummary returns the leading sentence of a tool description,
// trimmed to ~60 chars for use next to the tool name.
func toolDescSummary(desc string) string {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		return ""
	}
	if i := strings.Index(desc, ". "); i > 0 {
		desc = desc[:i]
	}
	desc = collapseWS(desc)
	const max = 60
	if len(desc) > max {
		desc = desc[:max-1] + "…"
	}
	return desc
}

func toolGroup(name string) string {
	if i := strings.Index(name, "_"); i > 0 {
		return name[:i]
	}
	return "misc"
}

// --- Misc helpers ---------------------------------------------------------

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// plural returns "s" for counts other than 1 — keeps log lines grammatical
// without pulling in an inflection library.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// --- /rules ---------------------------------------------------------------

// buildRule converts a config.RuleConfig to a rules.Rule. Returns an
// error when Cooldown can't parse or the action list is empty.
func buildRule(rc config.RuleConfig) (rules.Rule, error) {
	if rc.Name == "" {
		return rules.Rule{}, fmt.Errorf("rule missing name")
	}
	if len(rc.Then) == 0 {
		return rules.Rule{}, fmt.Errorf("rule %q has no actions", rc.Name)
	}
	var cooldown time.Duration
	if rc.Cooldown != "" {
		d, err := time.ParseDuration(rc.Cooldown)
		if err != nil {
			return rules.Rule{}, fmt.Errorf("cooldown %q: %w", rc.Cooldown, err)
		}
		cooldown = d
	}
	actions := make([]rules.Action, 0, len(rc.Then))
	for _, a := range rc.Then {
		actions = append(actions, rules.Action{
			Kind:    rules.ActionKind(a.Type),
			Webhook: a.Webhook,
			Topic:   a.Topic,
			Tool:    a.Tool,
			Params:  a.Params,
		})
	}
	return rules.Rule{
		Name:        rc.Name,
		Description: rc.Description,
		Match: rules.Match{
			Tool:           rc.When.Tool,
			Risk:           rc.When.Risk,
			Level:          rc.When.Level,
			OutputContains: rc.When.OutputContains,
		},
		Actions:  actions,
		Cooldown: cooldown,
		Enabled:  true,
	}, nil
}

// handleRulesCmd serves the /rules REPL command: list, pause <name>,
// resume <name>, test <name>. Writes directly to stderr through the
// provided style fields so it plays nicely with the line-editor's
// writeOutput batching.
func handleRulesCmd(eng *rules.Engine, args []string) {
	if eng == nil {
		fmt.Fprintf(os.Stderr, "  %srules engine unavailable%s\n", dim, reset)
		return
	}
	if len(args) == 0 {
		snaps := eng.List()
		if len(snaps) == 0 {
			fmt.Fprintf(os.Stderr, "  %sno rules registered%s\n", dim, reset)
			return
		}
		for _, s := range snaps {
			state := green + "●" + reset
			if !s.Enabled {
				state = yellow + "○" + reset
			}
			fmt.Fprintf(os.Stderr, "  %s %s %s(fires=%d)%s", state, s.Name, dim, s.Fires, reset)
			if s.Description != "" {
				fmt.Fprintf(os.Stderr, " — %s", s.Description)
			}
			fmt.Fprintln(os.Stderr)
		}
		return
	}
	sub := strings.ToLower(args[0])
	switch sub {
	case "pause":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %susage: /rules pause <name>%s\n", dim, reset)
			return
		}
		if !eng.Pause(args[1]) {
			fmt.Fprintf(os.Stderr, "  %s● rule %q not found%s\n", red, args[1], reset)
			return
		}
		fmt.Fprintf(os.Stderr, "  %s● paused %s%s\n", yellow, args[1], reset)
	case "resume":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %susage: /rules resume <name>%s\n", dim, reset)
			return
		}
		if !eng.Resume(args[1]) {
			fmt.Fprintf(os.Stderr, "  %s● rule %q not found%s\n", red, args[1], reset)
			return
		}
		fmt.Fprintf(os.Stderr, "  %s● resumed %s%s\n", green, args[1], reset)
	case "test":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %susage: /rules test <name>%s\n", dim, reset)
			return
		}
		sample := audit.Entry{
			Tool: "example_tool", Risk: "high", Level: audit.LevelWarning,
			Output: "sample output", SessionID: "test-session", TraceID: "deadbeefdeadbeef",
		}
		out, err := eng.Test(args[1], sample)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● %v%s\n", red, err, reset)
			return
		}
		for _, line := range out {
			fmt.Fprintf(os.Stderr, "  %s  %s%s\n", dim, line, reset)
		}
	default:
		fmt.Fprintf(os.Stderr, "  %sunknown /rules subcommand %q (want list|pause|resume|test)%s\n", dim, sub, reset)
	}
}

// renderDebugSnapshot collects local state into an obs.DebugSnapshot and
// writes the boxed /debug view to w. Fields that the caller can't populate
// (offline recorder, missing audit log) fall through as zero values and are
// hidden by the renderer.
func renderDebugSnapshot(w io.Writer, cfg *config.Config, rec *obs.Recorder, p *persona.Persona, flip *flipper.Flipper, hasMarauder bool, auditLog *audit.Log, ai *agent.Agent, tracker *cost.Tracker) {
	goroutines, heapMB, sysMB, lastGC, goVer, plat := obs.CollectRuntime()
	snap := obs.DebugSnapshot{
		BuildVersion: version.Version,
		GoVersion:    goVer,
		Platform:     plat,
		Goroutines:   goroutines,
		HeapMB:       heapMB,
		SysMB:        sysMB,
		LastGCAgo:    lastGC,
		FlipperPort:  cfg.Serial.Port,
		FlipperUp:    flip != nil,
	}
	if rec != nil {
		snap.Uptime = time.Since(rec.UptimeStart())
		snap.LastTools = rec.LastTools()
	}
	if tracker != nil {
		snap.OfflineMode = tracker.Snapshot().Offline
	}
	if p != nil {
		snap.PersonaName = p.Name
		snap.PersonaTools = len(agent.ToolNames(hasMarauder))
		snap.PersonaAllow = len(p.Tools)
		if snap.PersonaAllow == 0 {
			snap.PersonaAllow = snap.PersonaTools
		}
	}
	if caps, err := flip.DetectCapabilities(); err == nil {
		snap.FlipperModel = strings.TrimSpace(caps.FriendlyFork() + " " + caps.FirmwareVersion)
	}
	if hasMarauder {
		snap.MarauderPort = cfg.Marauder.Port
		snap.MarauderUp = true
	} else if cfg.Marauder.Port != "" {
		snap.MarauderPort = cfg.Marauder.Port
	}
	if auditLog != nil {
		snap.AuditDBPath = filepath.Join(os.Getenv("HOME"), ".promptzero", "audit.db")
		if max, err := auditLog.MaxID(); err == nil {
			snap.AuditRows = max
		}
		snap.SessionID = auditLog.SessionID()
	} else if ai != nil {
		snap.SessionID = ai.SessionID()
	}
	snap.Render(w, 72)
}

// --- /persona / /watch / /webhooks / /mqtt --------------------------------

// handlePersona implements /persona. With no args it prints the active
// persona's summary plus the catalogue of alternatives. With a name it
// switches personas and resets the conversation so the new system prompt
// starts a fresh context.
func handlePersona(ai *agent.Agent, reg *persona.Registry, args []string) {
	if len(args) == 0 {
		cur := ai.Persona()
		if cur == nil {
			fmt.Fprintf(os.Stderr, "  %sno persona active%s\n", dim, reset)
		} else {
			count := len(cur.Tools)
			scope := fmt.Sprintf("%d tools allowed", count)
			if count == 0 {
				scope = "all tools"
			}
			fmt.Fprintf(os.Stderr, "  %s●%s active: %s%s%s %s(%s)%s\n",
				green, reset, bold, cur.Name, reset, dim, scope, reset)
			if cur.Description != "" {
				fmt.Fprintf(os.Stderr, "  %s%s%s\n", dim, cur.Description, reset)
			}
		}
		fmt.Fprintf(os.Stderr, "  %savailable:%s %s\n", dim, reset, strings.Join(reg.Names(), ", "))
		return
	}
	name := args[0]
	p, ok := reg.Get(name)
	if !ok {
		fmt.Fprintf(os.Stderr, "  %s● unknown persona %q%s — available: %s\n", red, name, reset, strings.Join(reg.Names(), ", "))
		return
	}
	ai.SetPersona(p)
	ai.Reset()
	count := len(p.Tools)
	scope := fmt.Sprintf("%d tools", count)
	if count == 0 {
		scope = "all tools"
	}
	fmt.Fprintf(os.Stderr, "  %s●%s persona switched to %s%s%s %s(%s)%s\n",
		green, reset, bold, p.Name, reset, dim, scope, reset)
}

// handleWatchCmd implements /watch. With no args it summarises watched
// paths, rule count, and the last few events. "pause" / "resume" toggle
// dispatch without tearing down the watcher.
func handleWatchCmd(w *watch.Watcher, args []string) {
	if w == nil {
		fmt.Fprintf(os.Stderr, "  %swatch not active — pass --watch <path>%s\n", dim, reset)
		return
	}
	if len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "pause":
			w.Pause()
			fmt.Fprintf(os.Stderr, "  %s●%s watch paused\n", yellow, reset)
			return
		case "resume":
			w.Resume()
			fmt.Fprintf(os.Stderr, "  %s●%s watch resumed\n", green, reset)
			return
		default:
			fmt.Fprintf(os.Stderr, "  %susage: /watch [pause|resume]%s\n", dim, reset)
			return
		}
	}
	state := "active"
	if w.Paused() {
		state = "paused"
	}
	fmt.Fprintf(os.Stderr, "  %s●%s watch %s\n", green, reset, state)
	for _, p := range w.Paths() {
		fmt.Fprintf(os.Stderr, "    %s•%s %s\n", dim, reset, p)
	}
	rules := w.Rules()
	fmt.Fprintf(os.Stderr, "  %s%d rule%s configured%s\n", dim, len(rules), plural(len(rules)), reset)
	for _, r := range rules {
		prefix := r.Pattern
		if r.Persona != "" {
			prefix += " @" + r.Persona
		}
		fmt.Fprintf(os.Stderr, "    %s•%s %s → %s\n", dim, reset, prefix, collapseWS(r.Prompt))
	}
	recent := w.Recent(5)
	if len(recent) == 0 {
		fmt.Fprintf(os.Stderr, "  %sno events yet%s\n", dim, reset)
		return
	}
	fmt.Fprintf(os.Stderr, "  %srecent events:%s\n", dim, reset)
	for _, ev := range recent {
		ts := ev.At.Local().Format("15:04:05")
		errMark := ""
		if ev.Error != nil {
			errMark = " " + red + "✗" + reset
		}
		fmt.Fprintf(os.Stderr, "    %s%s%s  %s  %s(%s)%s%s\n",
			dim, ts, reset, ev.Path, dim, ev.Rule.Pattern, reset, errMark)
	}
}

// handleWebhooksCmd implements /webhooks. No args lists configured
// subscriptions, their event filters, and the most recent delivery
// attempts. `/webhooks test <name>` fires a synthetic session_started
// payload so operators can verify endpoint reachability without waiting
// for a real event.
func handleWebhooksCmd(wh webhook.Dispatcher, args []string) {
	if len(args) > 0 && strings.EqualFold(args[0], "test") {
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %susage: /webhooks test <name>%s\n", dim, reset)
			return
		}
		name := args[1]
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := wh.TestSubscription(ctx, name); err != nil {
			fmt.Fprintf(os.Stderr, "  %s● test %s failed: %v%s\n", red, name, err, reset)
			return
		}
		fmt.Fprintf(os.Stderr, "  %s●%s test %s%s%s delivered\n", green, reset, bold, name, reset)
		return
	}
	subs := wh.Subscriptions()
	if len(subs) == 0 {
		fmt.Fprintf(os.Stderr, "  %sno webhooks configured%s\n", dim, reset)
		return
	}
	fmt.Fprintf(os.Stderr, "  %s●%s %d subscription%s\n", green, reset, len(subs), plural(len(subs)))
	for _, s := range subs {
		filter := "all events"
		if len(s.Events) > 0 {
			names := make([]string, 0, len(s.Events))
			for _, e := range s.Events {
				names = append(names, string(e))
			}
			filter = strings.Join(names, ",")
		}
		signed := ""
		if s.Secret != "" {
			signed = " " + dim + "(signed)" + reset
		}
		fmt.Fprintf(os.Stderr, "    %s•%s %s%s%s → %s %s[%s]%s%s\n",
			dim, reset, bold, s.Name, reset, s.URL, dim, filter, reset, signed)
		for _, r := range wh.RecentResults(s.Name) {
			ts := r.At.Local().Format("15:04:05")
			if r.Err != nil {
				fmt.Fprintf(os.Stderr, "      %s%s%s  %s  %s✗%s %v\n",
					dim, ts, reset, r.Event, red, reset, r.Err)
				continue
			}
			icon := green + "◦" + reset
			if r.StatusCode >= 400 {
				icon = red + "✗" + reset
			}
			fmt.Fprintf(os.Stderr, "      %s%s%s  %s  %s %d\n",
				dim, ts, reset, r.Event, icon, r.StatusCode)
		}
	}
}

// handleMQTTCmd implements /mqtt. With no args it shows the bridge's
// enabled/connected state plus the most recent connection error (if any).
// `/mqtt test` fires a synthetic event on <base>/events/test so operators
// can verify topic routing from the broker side.
func handleMQTTCmd(br *mqtt.Bridge, args []string) {
	if br == nil || !br.Enabled() {
		fmt.Fprintf(os.Stderr, "  %sMQTT bridge disabled%s\n", dim, reset)
		return
	}
	if len(args) > 0 && strings.EqualFold(args[0], "test") {
		br.PublishEvent("test", map[string]any{
			"ts":   time.Now().UTC(),
			"note": "synthetic ping from /mqtt test",
		})
		fmt.Fprintf(os.Stderr, "  %s●%s test event published to %s/events/test\n", green, reset, br.BasePath())
		return
	}
	state := red + "disconnected" + reset
	if br.Connected() {
		state = green + "connected" + reset
	}
	fmt.Fprintf(os.Stderr, "  %s●%s MQTT %s %s(base: %s/)%s\n",
		green, reset, state, dim, br.BasePath(), reset)
	if err := br.LastError(); err != nil {
		fmt.Fprintf(os.Stderr, "    %slast error:%s %v\n", dim, reset, err)
	}
}
