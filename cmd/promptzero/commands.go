package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/campaign"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/mode"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/report"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/snapshot"
	"github.com/xunholy/promptzero/internal/trainset"
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
	case "/stats":
		ed.writeOutput(func() { handleStats(deps, nil) })
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
	case "/rewind":
		ed.writeOutput(func() { handleRewind(deps, strings.TrimSpace(strings.Join(fields[1:], " "))) })
		return true, false
	case "/report":
		ed.writeOutput(func() { handleReport(deps, fields[1:]) })
		return true, false
	case "/attack":
		ed.writeOutput(func() { handleAttack(deps, fields[1:]) })
		return true, false
	case "/campaign":
		ed.writeOutput(func() { handleCampaign(deps, fields[1:]) })
		return true, false
	case "/export":
		ed.writeOutput(func() { handleExport(deps.auditLog, fields[1:]) })
		return true, false
	case "/stats":
		ed.writeOutput(func() { handleStats(deps, fields[1:]) })
		return true, false
	case "/budget":
		ed.writeOutput(func() { handleBudget(deps, fields[1:]) })
		return true, false
	case "/persona":
		ed.writeOutput(func() { handlePersona(deps.ai, deps.personas, fields[1:]) })
		return true, false
	case "/mode":
		ed.writeOutput(func() { handleMode(deps.ai, fields[1:]) })
		return true, false
	case "/watch":
		ed.writeOutput(func() { handleWatchCmd(deps.watchMgr, fields[1:]) })
		return true, false
	case "/webhooks":
		ed.writeOutput(func() { handleWebhooksCmd(deps.wh, fields[1:]) })
		return true, false
	case "/rules":
		ed.writeOutput(func() { handleRulesCmd(deps.ruleEngine, fields[1:]) })
		return true, false
	case "/tools":
		filter := ""
		page := 1
		if len(fields) > 1 {
			if strings.ToLower(fields[1]) == "page" {
				if len(fields) > 2 {
					if n, err := strconv.Atoi(fields[2]); err == nil && n > 0 {
						page = n
					}
				}
			} else {
				filter = fields[1]
			}
		}
		ed.writeOutput(func() { printTools(deps.hasMarauder, filter, page) })
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
	case "/forget":
		if len(fields) < 2 {
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %susage: /forget <session-id>%s\n", dim, reset)
				fmt.Fprintf(os.Stderr, "  %srun /sessions to see ids%s\n", dim, reset)
			})
			return true, false
		}
		id := fields[1]
		ed.writeOutput(func() {
			if err := deps.ai.DeleteSession(id); err != nil {
				fmt.Fprintf(os.Stderr, "  %s● forget failed: %v%s\n", red, err, reset)
			} else {
				fmt.Fprintf(os.Stderr, "  %s● forgot session %s%s%s (snapshots purged)\n", green, bold, id, reset)
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
	// Unmatched but shaped like "/<word>" — almost certainly a
	// slash-command typo. Without this guard the REPL falls through
	// and sends e.g. "/budgett" verbatim to Claude as a question.
	// Catch it locally with a hint at /help. We require all-letters
	// after the leading "/" so a leading file path like /dev/sda or
	// numeric "/2" still passes through as a regular prompt.
	if looksLikeSlashCommand(head) {
		ed.writeOutput(func() {
			fmt.Fprintf(os.Stderr, "  %s● unknown command %q — type /help for the list%s\n", red, head, reset)
		})
		return true, false
	}
	return false, false
}

// looksLikeSlashCommand reports whether s has the shape "/<letters>"
// — exactly one leading slash and the rest alphabetic. Used by the
// dispatcher to discriminate between operator typos (catch with a
// hint) and incidental leading slashes like file paths "/dev/sda" or
// expressions "/2 of these" that should pass through to the agent.
func looksLikeSlashCommand(s string) bool {
	if len(s) < 2 || s[0] != '/' {
		return false
	}
	for _, r := range s[1:] {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
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
	fmt.Fprintf(os.Stderr, "  %s%sConversation%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s/help%s, %s?%s            Show this help\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/reset%s, %s/clear%s      Clear conversation history\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/quit%s, %s/exit%s, %sq%s    Exit promptzero\n", cyan, reset, cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sSession%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s/sessions%s              List saved sessions\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/resume <id>%s           Resume a saved session by id\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/save <name>%s           Save current conversation under <name>\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/forget <id>%s           Delete a saved session and purge its snapshots\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sInfo%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s/status%s                Connection, capabilities, Flipper telemetry\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/tools [filter]%s        Enumerate registered tools (grouped)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/history [N]%s           Show last N audit rows (default 20)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit stats%s           Session audit summary\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit query [N]%s       Recent N entries (default 20)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit find k=v ...%s    Filter by tool, risk, success, session (and more)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit tail%s            Live tail of new audit rows (Ctrl+C or Enter to stop)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit top tools|risks%s Top-N aggregations (since=24h etc.)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit session <id>%s    Dump a specific session\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit export <path>%s   Write session audit JSON to <path>\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/export training-set <path>%s  Export audit as JSONL fine-tuning dataset (--format=chat --success-only)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/stats [section]%s       Session cost summary (tokens, spend, cache hit-rate)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/cost%s                  Current cost snapshot\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/budget [set <USD>|off]%s  Show or update session budget cap\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/debug%s                 Diagnostic snapshot (config, transport, agent state)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sOperator%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s/persona [name]%s        Show or switch active persona (resets conversation)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/mode [name]%s           Show or switch operation mode (standard|recon|intel|stealth|assault)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/watch [pause|resume]%s  Show watched paths, pause/resume FS triggers\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/webhooks [test <name>]%s List outbound webhooks with recent deliveries\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/validate <path>%s       Lint a BadUSB .txt payload on the Flipper SD card\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/attack [set|clear] <techniques>%s  ATT&CK technique constraint for the session\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/campaign validate|run <file>%s  Validate or execute a multi-step campaign file\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/rewind [snapshot]%s    Undo SD card writes to a named or latest snapshot\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/report [session] [json] [save]%s  Engagement report with ATT&CK heatmap (md default; json for tooling; save writes to ~/.promptzero/reports/)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/rules%s                 List automation rules and fire counts\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sDevice%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s/reconnect%s             Force reconnect to the Flipper (after replug / USB hiccup)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sInput%s\n", bold, white, reset)
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
	fmt.Fprintf(os.Stderr, "    %sHigh risk:%s     %sy%s approve · %sN%s / Enter deny · type %sall%s + Enter to approve all remaining\n",
		bold, reset, bold+green, reset, bold+red, reset, bold+cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sCritical risk:%s type %sconfirm%s + Enter to approve · %sN%s / Enter deny · no blanket approve-all\n",
		bold, reset, bold+green, reset, bold+red, reset)
	fmt.Fprintf(os.Stderr, "    Use %s--yolo%s to disable, or %s--confirm-risk=<level>%s to adjust threshold.\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "\n")
}

// --- /status --------------------------------------------------------------

func printStatus(cfg *config.Config, ai *agent.Agent, genLLM provider.Provider, wifi bool, hasVoice bool, auditLog *audit.Log, flip *flipper.Flipper, busy func() bool) {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  %s%sStatus%s\n", bold, white, reset)
	if flip != nil && flip.IsSuspended() {
		statusWarn(fmt.Sprintf("Flipper Zero suspended — %s", flip.SuspensionReason()))
	} else if tx := flip.Transport(); tx != nil {
		statusOK(fmt.Sprintf("Flipper Zero on %s (%s)", tx.Identity(), tx.Kind()))
	} else {
		statusOK(fmt.Sprintf("Flipper Zero on %s", cfg.Serial.Port))
	}
	statusOK(fmt.Sprintf("Agent model: %s", cfg.Model))
	statusOK(fmt.Sprintf("Generation: %s", genLLM.Name()))
	if wifi {
		if cfg.Marauder.Bridge {
			if flip != nil && flip.IsSuspended() {
				statusOK(fmt.Sprintf("Marauder via Flipper UART bridge on %s", cfg.Serial.Port))
				statusWarn("Flipper CLI suspended — UART bridge active (flipper_* tools disabled)")
			} else {
				statusOK(fmt.Sprintf("Marauder via Flipper UART bridge on %s (hybrid; Flipper CLI on BLE)", cfg.Marauder.Port))
			}
		} else {
			statusOK(fmt.Sprintf("Marauder on %s", cfg.Marauder.Port))
		}
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
		// Tools field is deprecated in v0.19.0; keeping the read so
		// legacy user personas (~/.promptzero/personas/*.yaml) that
		// still define tool allowlists render correctly until v0.20.0.
		if len(p.Tools) == 0 { //nolint:staticcheck // back-compat through v0.19.0
			statusOK(fmt.Sprintf("Persona: %s (all tools)", p.Name))
		} else {
			statusOK(fmt.Sprintf("Persona: %s (%d tools allowed)", p.Name, len(p.Tools))) //nolint:staticcheck // back-compat through v0.19.0
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

// handleRewind services the /rewind REPL command. Supported forms:
//
//	/rewind                 — list snapshots for the current session
//	/rewind list            — same as above
//	/rewind <n>             — pop the N most recent snapshots (1-99)
//	/rewind <id>            — restore the snapshot with the given ID
//	/rewind <id|n> dry-run  — show what restore would do, no write
//
// Per roadmap P1-09 snapshots are captured before any write through
// fileformat_edit; this command lets the operator pop recent ones
// back onto the Flipper without replaying the whole turn.
func handleRewind(deps *REPLDeps, rawArgs string) {
	mgr := deps.ai.SnapshotManager()
	if mgr == nil {
		fmt.Fprintf(os.Stderr, "  %srewind: snapshot manager not configured%s\n", dim, reset)
		return
	}
	sessionID := deps.ai.SessionID()
	if sessionID == "" {
		fmt.Fprintf(os.Stderr, "  %srewind: no active session — start one with /save <name>%s\n", dim, reset)
		return
	}

	args := strings.Fields(rawArgs)
	cmd := "list"
	if len(args) > 0 {
		cmd = args[0]
	}

	// Pop-N mode: a pure positive integer arg restores the N most
	// recent snapshots (newest first). Capped at 99 because anything
	// bigger is almost certainly a session-wide rollback and the
	// operator should /rewind list first.
	if n, err := strconv.Atoi(cmd); err == nil && n >= 1 && n <= 99 {
		rewindSteps(deps, mgr, sessionID, n, hasDryRunFlag(args[1:]))
		return
	}

	switch cmd {
	case "list", "":
		entries, err := mgr.List(sessionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● rewind list: %v%s\n", red, err, reset)
			return
		}
		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "  %sno snapshots for session %s%s\n", dim, sessionID, reset)
			return
		}
		fmt.Fprintf(os.Stderr, "  %sSnapshots (newest first, %d total):%s\n", dim, len(entries), reset)
		for _, e := range entries {
			fmt.Fprintf(os.Stderr, "    %s  %s  (%d bytes)  %s\n", e.ID, e.TakenAt.Format(time.RFC3339), e.SizeBytes, e.OriginalPath)
		}
		fmt.Fprintf(os.Stderr, "  %s(use /rewind <id> or /rewind <n> to restore)%s\n", dim, reset)
	default:
		// Any non-"list" arg is treated as a snapshot ID.
		id := cmd
		dryRun := false
		for _, a := range args[1:] {
			if strings.EqualFold(a, "dry-run") {
				dryRun = true
			}
		}
		entry, content, err := mgr.Restore(sessionID, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● rewind: %v%s\n", red, err, reset)
			return
		}
		if dryRun {
			fmt.Fprintf(os.Stderr, "  %sdry-run: would write %d bytes to %s%s\n", dim, len(content), entry.OriginalPath, reset)
			return
		}
		ctx, cancel := context.WithTimeout(deps.ctx, 30*time.Second)
		defer cancel()
		if err := deps.flip.WriteFileCtx(ctx, entry.OriginalPath, content); err != nil {
			fmt.Fprintf(os.Stderr, "  %s● rewind write failed: %v%s\n", red, err, reset)
			return
		}
		fmt.Fprintf(os.Stderr, "  %s✓ restored %s (%d bytes) from snapshot %s%s\n", green, entry.OriginalPath, len(content), entry.ID, reset)
	}
}

// handleCampaign services the /campaign REPL command. Implements
// the operator-facing slice of roadmap P2-19. Supported forms:
//
//	/campaign                    — usage hint
//	/campaign validate <file>    — parse + cross-check a YAML file
//	/campaign run <file>         — execute the campaign end-to-end
//
// Campaign execution does NOT bypass the risk gate — each step
// invokes the agent's normal dispatch which still consults the
// confirm callback. This keeps the human-in-the-loop model intact
// even when declarative runs issue back-to-back high-risk tools.
func handleCampaign(deps *REPLDeps, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "  %susage: /campaign validate|run <file>%s\n", dim, reset)
		return
	}
	switch strings.ToLower(args[0]) {
	case "validate":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %s● validate: file path required%s\n", red, reset)
			return
		}
		c, err := campaign.Load(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● validate: %v%s\n", red, err, reset)
			return
		}
		fmt.Fprintf(os.Stderr, "  %s✓ campaign %q valid (%d steps)%s\n", green, c.Name, len(c.Steps), reset)
	case "run":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %s● run: file path required%s\n", red, reset)
			return
		}
		c, err := campaign.Load(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● run: %v%s\n", red, err, reset)
			return
		}
		runner := campaign.NewRunner(campaign.AgentExecutor{Dispatcher: deps.ai})
		ctx, cancel := context.WithTimeout(deps.ctx, 10*time.Minute)
		defer cancel()
		result := runner.Run(ctx, c)
		renderCampaignResult(result)
	default:
		fmt.Fprintf(os.Stderr, "  %s● campaign: unknown subcommand %q%s\n", red, args[0], reset)
	}
}

// renderCampaignResult prints a compact Markdown-ish summary of a
// RunResult to stderr. The operator gets a quick read of which
// steps ran, which skipped, which errored, and the total hands-on
// time. A proper /report-integrated renderer is future work.
func renderCampaignResult(r campaign.RunResult) {
	fmt.Fprintf(os.Stderr, "\n  %scampaign %q — %s%s\n", dim, r.Campaign, r.Duration().Round(time.Millisecond), reset)
	for _, s := range r.StepResults {
		switch {
		case s.Skipped:
			fmt.Fprintf(os.Stderr, "    %s— skipped %s%s  %s%s%s\n", dim, s.StepID, reset, dim, s.SkipReason, reset)
		case s.Err != nil:
			fmt.Fprintf(os.Stderr, "    %s✗ %s%s  (%s)  %s%v%s\n", red, s.StepID, reset, s.Duration.Round(time.Millisecond), dim, s.Err, reset)
		default:
			fmt.Fprintf(os.Stderr, "    %s✓ %s%s  (%s)%s\n", green, s.StepID, reset, s.Duration.Round(time.Millisecond), reset)
		}
	}
	if r.Succeeded() {
		fmt.Fprintf(os.Stderr, "  %s✓ campaign succeeded%s\n\n", green, reset)
	} else {
		fmt.Fprintf(os.Stderr, "  %s✗ campaign completed with failures%s\n\n", red, reset)
	}
}

// handleExport services the /export training-set REPL command. Produces
// a JSONL fine-tuning dataset from the audit log, ready to feed into a
// LoRA/QLoRA pipeline or a Hugging Face Datasets loader.
//
//	/export training-set <path>                              jsonl, all entries
//	/export training-set <path> --format=chat                OpenAI chat format
//	/export training-set <path> --success-only               drop failed calls
//	/export training-set <path> --min-level=warning          critical + warnings only
func handleExport(auditLog *audit.Log, args []string) {
	if auditLog == nil {
		fmt.Fprintf(os.Stderr, "  %s● audit log not initialised — nothing to export%s\n", red, reset)
		return
	}
	if len(args) < 2 || strings.ToLower(args[0]) != "training-set" {
		fmt.Fprintf(os.Stderr, "  %susage: /export training-set <path> [--format=chat] [--success-only] [--min-level=warning|critical]%s\n", dim, reset)
		return
	}
	path := args[1]
	opts := trainset.Options{Format: trainset.FormatJSONL}
	for _, a := range args[2:] {
		switch {
		case a == "--success-only":
			opts.SuccessOnly = true
		case strings.HasPrefix(a, "--format="):
			opts.Format = trainset.Format(strings.TrimPrefix(a, "--format="))
		case strings.HasPrefix(a, "--min-level="):
			opts.MinLevel = audit.Level(strings.TrimPrefix(a, "--min-level="))
		case strings.HasPrefix(a, "--system-prompt="):
			opts.SystemPrompt = strings.TrimPrefix(a, "--system-prompt=")
		default:
			fmt.Fprintf(os.Stderr, "  %s● unknown flag %q%s\n", red, a, reset)
			return
		}
	}
	// Pull the whole log — operators use this after a session, not
	// at scale. One million rows is orders of magnitude beyond any
	// realistic single-session capture; log sizes that approach this
	// deserve a dedicated streaming path, not a bigger cap.
	entries, err := auditLog.Query(1_000_000)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● read audit: %v%s\n", red, err, reset)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● open %s: %v%s\n", red, path, err, reset)
		return
	}
	defer f.Close()
	n, err := trainset.Export(entries, f, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● export: %v%s\n", red, err, reset)
		return
	}
	fmt.Fprintf(os.Stderr, "  %s●%s wrote %d rows (%s) → %s\n", green, reset, n, opts.Format, path)
}

// handleStats services the /stats REPL command. The no-arg form
// prints a summary of every tracked counter; subcommands drill into
// one surface so operators who only care about cache health or
// token spend don't have to eyeball the wider dump.
//
//	/stats              — full summary
//	/stats cache        — prompt-cache reads/writes/hit rate (P0-01)
//	/stats tokens       — input/output/cache token totals
func handleStats(deps *REPLDeps, args []string) {
	if deps.costTracker == nil {
		fmt.Fprintf(os.Stderr, "  %sstats: cost tracker not installed%s\n", dim, reset)
		return
	}
	snap := deps.costTracker.Snapshot()
	section := ""
	if len(args) > 0 {
		section = strings.ToLower(args[0])
	}
	switch section {
	case "cache":
		renderCacheStats(snap)
	case "tokens":
		renderTokenStats(snap)
	case "", "all":
		renderTokenStats(snap)
		renderCacheStats(snap)
	default:
		fmt.Fprintf(os.Stderr, "  %s● stats: unknown section %q (expected cache|tokens|all)%s\n", red, section, reset)
	}
}

func renderCacheStats(snap cost.Snapshot) {
	if snap.CacheReadTokens == 0 && snap.CacheCreationTokens == 0 {
		fmt.Fprintf(os.Stderr, "  %scache: no prompt-cache traffic yet (set ANTHROPIC_API_KEY and run a turn)%s\n", dim, reset)
		return
	}
	hitRate := snap.CacheHitRate() * 100
	fmt.Fprintf(os.Stderr, "  prompt cache:\n")
	fmt.Fprintf(os.Stderr, "    cache_read_tokens:     %d\n", snap.CacheReadTokens)
	fmt.Fprintf(os.Stderr, "    cache_creation_tokens: %d\n", snap.CacheCreationTokens)
	fmt.Fprintf(os.Stderr, "    hit_rate:              %.1f%%\n", hitRate)
}

func renderTokenStats(snap cost.Snapshot) {
	fmt.Fprintf(os.Stderr, "  tokens:\n")
	fmt.Fprintf(os.Stderr, "    input:  %d\n", snap.InputTokens)
	fmt.Fprintf(os.Stderr, "    output: %d\n", snap.OutputTokens)
	fmt.Fprintf(os.Stderr, "    cost:   $%.4f\n", snap.TotalUSD)
}

// handleAttack services the /attack REPL command. Manages the agent's
// ATT&CK constraint set — an optional filter that limits the per-turn
// tool catalog to tools tagged with one or more MITRE technique IDs
// (see internal/attack + P1-07). Supported forms:
//
//	/attack                 — show the active constraint and any
//	                          available technique IDs
//	/attack set T1557.004 T1499   — pin the session to those techniques
//	/attack clear           — remove the constraint
//
// normaliseAttackIDs validates and uppercases ATT&CK technique IDs.
// MITRE format is `T` + 4 digits, optionally `.` + 3 digits for the
// sub-technique. Operators sometimes type t1557 lowercase or paste
// values with surrounding whitespace; this lenient pass tolerates
// both. Truly malformed input (typos like "T155", "BogusID") gets a
// clear error rather than producing a constraint that filters out
// every tool silently.
var attackIDRE = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func normaliseAttackIDs(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		if !attackIDRE.MatchString(id) {
			return nil, fmt.Errorf("invalid technique id %q (want format like T1557 or T1557.004)", raw)
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one technique id required")
	}
	return out, nil
}

func handleAttack(deps *REPLDeps, args []string) {
	if len(args) == 0 {
		cur := deps.ai.AttackConstraint()
		if len(cur) == 0 {
			fmt.Fprintf(os.Stderr, "  %sattack: no constraint set (all tools allowed)%s\n", dim, reset)
		} else {
			fmt.Fprintf(os.Stderr, "  %sattack constraint: %s%s\n", dim, strings.Join(cur, ", "), reset)
		}
		fmt.Fprintf(os.Stderr, "  %s(usage: /attack set T1557.004 [T1499 ...] | /attack clear)%s\n", dim, reset)
		return
	}
	switch strings.ToLower(args[0]) {
	case "set":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %s● attack set: at least one technique id required%s\n", red, reset)
			return
		}
		ids, err := normaliseAttackIDs(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● attack set: %v%s\n", red, err, reset)
			return
		}
		deps.ai.SetAttackConstraint(ids)
		fmt.Fprintf(os.Stderr, "  %s✓ attack constraint set: %s%s\n", green, strings.Join(deps.ai.AttackConstraint(), ", "), reset)
	case "clear":
		deps.ai.SetAttackConstraint(nil)
		fmt.Fprintf(os.Stderr, "  %s✓ attack constraint cleared%s\n", green, reset)
	default:
		fmt.Fprintf(os.Stderr, "  %s● attack: unknown subcommand %q (expected set|clear)%s\n", red, args[0], reset)
	}
}

// rewindSteps is the pop-N implementation: restores the `n` newest
// snapshots in reverse-chronological order. A dry-run flag shows
// what each restore would do without touching the Flipper. The
// operation is best-effort — a single failed restore logs an error
// and continues so a partially-reversible batch doesn't strand the
// operator at an intermediate state.
func rewindSteps(deps *REPLDeps, mgr *snapshot.Manager, sessionID string, n int, dryRun bool) {
	entries, err := mgr.List(sessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● rewind list: %v%s\n", red, err, reset)
		return
	}
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "  %sno snapshots to rewind%s\n", dim, reset)
		return
	}
	if n > len(entries) {
		n = len(entries)
	}
	target := entries[:n]

	fmt.Fprintf(os.Stderr, "  %srewinding %d snapshot(s)%s\n", dim, n, reset)
	for _, e := range target {
		entry, content, err := mgr.Restore(sessionID, e.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● %s restore: %v%s\n", red, e.ID, err, reset)
			continue
		}
		if dryRun {
			fmt.Fprintf(os.Stderr, "  %sdry-run: would write %d bytes to %s%s\n", dim, len(content), entry.OriginalPath, reset)
			continue
		}
		ctx, cancel := context.WithTimeout(deps.ctx, 30*time.Second)
		if err := deps.flip.WriteFileCtx(ctx, entry.OriginalPath, content); err != nil {
			cancel()
			fmt.Fprintf(os.Stderr, "  %s● %s write failed: %v%s\n", red, entry.OriginalPath, err, reset)
			continue
		}
		cancel()
		fmt.Fprintf(os.Stderr, "  %s✓ restored %s (%d bytes) from %s%s\n", green, entry.OriginalPath, len(content), entry.ID, reset)
	}
}

// hasDryRunFlag scans args for a case-insensitive "dry-run" marker.
// Returns true when found. Used by both /rewind <id> and /rewind <n>
// so the flag semantics stay identical.
func hasDryRunFlag(args []string) bool {
	for _, a := range args {
		if strings.EqualFold(a, "dry-run") {
			return true
		}
	}
	return false
}

// handleReport services the /report REPL command.
//
//	/report                 — render markdown for the current session
//	/report <session-id>    — render markdown for a specific session
//	/report <id> save       — write the report to ~/.promptzero/reports/<id>.md
//	/report json            — render JSON for the current session
//	/report json save       — write JSON to ~/.promptzero/reports/<id>.json
//
// "json" can appear in any position alongside an id and "save"; the
// argument parser is order-independent.
func handleReport(deps *REPLDeps, args []string) {
	if deps.auditLog == nil {
		fmt.Fprintf(os.Stderr, "  %sreport: audit log not available%s\n", dim, reset)
		return
	}

	sessionID := deps.ai.SessionID()
	save := false
	jsonOut := false
	for _, a := range args {
		switch strings.ToLower(a) {
		case "save":
			save = true
			continue
		case "json":
			jsonOut = true
			continue
		}
		if a != "" {
			sessionID = a
		}
	}
	if sessionID == "" {
		fmt.Fprintf(os.Stderr, "  %sreport: no active session; start one with /save <name>%s\n", dim, reset)
		return
	}

	entries, err := deps.auditLog.QueryBySession(sessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● report query failed: %v%s\n", red, err, reset)
		return
	}

	summary := report.Summarise(sessionID, entries, attack.NewDefaultIndex())

	var (
		body []byte
		ext  string
	)
	if jsonOut {
		body, err = report.JSONRenderer{}.Render(summary)
		ext = ".json"
	} else {
		body, err = report.MarkdownRenderer{}.Render(summary)
		ext = ".md"
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● report render failed: %v%s\n", red, err, reset)
		return
	}

	if save {
		// Sanitise sessionID before using it as a filename. /report can
		// accept an arbitrary session id from the operator; without
		// this, "/report ../../etc/passwd save" would escape the
		// reports dir. The whitelist matches how session IDs are
		// actually generated (timestamp + random suffix) — anything
		// with path separators or dot-segments gets rejected.
		if !isSafeReportID(sessionID) {
			fmt.Fprintf(os.Stderr, "  %s● report: session id %q contains unsafe characters%s\n", red, sessionID, reset)
			return
		}
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● resolving home dir: %v%s\n", red, err, reset)
			return
		}
		dir := filepath.Join(home, ".promptzero", "reports")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "  %s● mkdir reports: %v%s\n", red, err, reset)
			return
		}
		outPath := filepath.Join(dir, sessionID+ext)
		if err := os.WriteFile(outPath, body, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "  %s● write report: %v%s\n", red, err, reset)
			return
		}
		fmt.Fprintf(os.Stderr, "  %s✓ report saved to %s (%d bytes)%s\n", green, outPath, len(body), reset)
		return
	}

	// Print to stderr so the report is visible above the REPL prompt.
	// The report is authored — operators can pipe / copy it.
	_, _ = os.Stderr.Write(body)
}

// isSafeReportID returns true when sessionID is composed only of
// characters that are safe to use as a filename segment. Rejects
// path separators, dot-segments, control bytes, and whitespace. The
// accepted set (alphanumeric + dash + underscore) covers every
// session ID PromptZero produces today and every legal
// user-provided name for /session save.
func isSafeReportID(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	if sessionID == "." || sessionID == ".." || strings.Contains(sessionID, "..") {
		return false
	}
	for _, r := range sessionID {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '_':
			continue
		default:
			return false
		}
	}
	return true
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

// maxAuditLimit caps the per-query row count. The audit DB grows
// without bound across sessions; an operator typing limit=1000000 by
// accident (or as a stress test) would tie up SQLite for seconds and
// flood the terminal. 10k is generous for any reasonable triage flow
// — operators wanting more should use offset to paginate.
const maxAuditLimit = 10000

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
			lv := strings.ToLower(v)
			switch lv {
			case "low", "medium", "high", "critical":
				f.Risk = lv
			default:
				return f, fmt.Errorf("risk=%s: want low|medium|high|critical", v)
			}
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
			if n > maxAuditLimit {
				return f, fmt.Errorf("limit=%d exceeds max %d", n, maxAuditLimit)
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
	// Sanity check: since must precede until. The SQL clause is
	// `timestamp >= since AND timestamp <= until` — a swapped pair
	// returns 0 rows silently. Surface the typo with a clear error.
	if !f.Since.IsZero() && !f.Until.IsZero() && f.Since.After(f.Until) {
		return f, fmt.Errorf("since (%s) is after until (%s) — swap the values",
			f.Since.Format(time.RFC3339), f.Until.Format(time.RFC3339))
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
		// Reject negative durations. "since=-30m" produced
		// time.Now()+30m — a timestamp in the future — which then
		// matches no past audit rows. The shape "negative duration"
		// has no sensible reading for since/until ("how long ago").
		if d < 0 {
			return time.Time{}, fmt.Errorf("negative duration %q (use e.g. \"30m\" not \"-30m\")", s)
		}
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
	fmt.Fprintf(os.Stderr, "  %s/resume <id>  /forget <id>%s\n", dim, reset)
}

// --- /tools ---------------------------------------------------------------

const toolsMaxRows = 40

func printTools(hasMarauder bool, filter string, page int) {
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

	type flatEntry struct {
		group string
		entry agent.ToolCatalogEntry
	}
	var flat []flatEntry
	for _, g := range order {
		for _, e := range groups[g] {
			flat = append(flat, flatEntry{g, e})
		}
	}

	if page < 1 {
		page = 1
	}
	start := (page - 1) * toolsMaxRows
	if start >= len(flat) {
		totalPages := (len(flat) + toolsMaxRows - 1) / toolsMaxRows
		fmt.Fprintf(os.Stderr, "  %spage %d out of range — total pages: %d%s\n", dim, page, totalPages, reset)
		return
	}
	end := start + toolsMaxRows
	if end > len(flat) {
		end = len(flat)
	}

	fmt.Fprintln(os.Stderr)
	lastGroup := ""
	for _, item := range flat[start:end] {
		if item.group != lastGroup {
			fmt.Fprintf(os.Stderr, "  %s%s%s%s\n", bold, white, item.group, reset)
			lastGroup = item.group
		}
		fmt.Fprintf(os.Stderr, "    %s%s%s  %s%s%s\n", cyan, item.entry.Name, reset, dim, toolDescSummary(item.entry.Description), reset)
	}
	if end < len(flat) {
		hint := fmt.Sprintf("/tools page %d", page+1)
		if filter != "" {
			hint = "use a narrower filter"
		}
		fmt.Fprintf(os.Stderr, "  %s… and %d more, try %s%s\n", dim, len(flat)-end, hint, reset)
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
			Success:        rc.When.Success,
		},
		Actions:  actions,
		Cooldown: cooldown,
		Enabled:  true,
	}, nil
}

// humanSince renders the duration since t in a terse, eyeball-friendly
// form: "12s", "3m", "2h", "1d". Drops sub-unit precision so the
// /rules list output stays compact even for rules that fire often.
// Returns "now" for sub-second intervals.
func humanSince(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Second:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
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
			fmt.Fprintf(os.Stderr, "  %s %s %s(fires=%d", state, s.Name, dim, s.Fires)
			if !s.LastFire.IsZero() {
				fmt.Fprintf(os.Stderr, ", last %s ago", humanSince(s.LastFire))
			}
			fmt.Fprintf(os.Stderr, ")%s", reset)
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
		snap.PersonaAllow = len(p.Tools) //nolint:staticcheck // back-compat through v0.19.0
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

// --- /persona / /watch / /webhooks ----------------------------------------

// handlePersona implements /persona. With no args it prints the active
// persona's summary plus the catalogue of alternatives. With a name it
// switches personas and resets the conversation so the new system prompt
// starts a fresh context.
func handlePersona(ai *agent.Agent, reg *persona.Registry, args []string) {
	if len(args) == 0 {
		cur := ai.Persona()
		if cur != nil {
			count := len(cur.Tools) //nolint:staticcheck // back-compat through v0.19.0
			scope := fmt.Sprintf("%d tools", count)
			if count == 0 {
				scope = "all tools"
			}
			fmt.Fprintf(os.Stderr, "  %s●%s active: %s%s%s %s(%s)%s\n",
				green, reset, bold, cur.Name, reset, dim, scope, reset)
			if cur.Description != "" {
				fmt.Fprintf(os.Stderr, "  %s%s%s\n", dim, cur.Description, reset)
			}
		}
		alts := reg.Names()
		fmt.Fprintf(os.Stderr, "  %salternatives:%s %s\n", dim, reset, strings.Join(alts, ", "))
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
	count := len(p.Tools) //nolint:staticcheck // back-compat through v0.19.0
	scope := fmt.Sprintf("%d tools", count)
	if count == 0 {
		scope = "all tools"
	}
	fmt.Fprintf(os.Stderr, "  %s●%s persona switched to %s%s%s %s(%s)%s\n",
		green, reset, bold, p.Name, reset, dim, scope, reset)
}

// handleMode implements /mode. With no args it prints the active mode
// plus the catalogue of alternatives and their descriptions. With a
// name it switches modes; the agent enforces the new allow-list on
// the next dispatch. Unknown modes echo a self-correcting error
// listing the supported names.
func handleMode(ai *agent.Agent, args []string) {
	if len(args) == 0 {
		current := ai.Mode()
		fmt.Fprintf(os.Stderr, "  %s●%s active: %s%s%s %s· %s%s\n",
			green, reset, bold, current.DisplayName(), reset,
			dim, current.Description(), reset)
		fmt.Fprintf(os.Stderr, "  %savailable modes:%s\n", dim, reset)
		for _, m := range mode.All() {
			marker := " "
			if m == current {
				marker = "*"
			}
			fmt.Fprintf(os.Stderr, "    %s%s%s %s%-9s%s %s%s%s\n",
				dim, marker, reset,
				bold, m.DisplayName(), reset,
				dim, m.Description(), reset)
		}
		return
	}
	name := args[0]
	target, err := mode.ParseMode(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● %v%s\n", red, err, reset)
		return
	}
	ai.SetMode(target) //nolint:staticcheck // back-compat through v0.19.0
	fmt.Fprintf(os.Stderr, "  %s●%s mode switched to %s%s%s %s· %s%s\n",
		green, reset, bold, target.DisplayName(), reset,
		dim, target.Description(), reset)
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

// handleBudget services the /budget REPL command. Operators bumped the
// cap mid-session before by exiting and restarting with --budget;
// after v0.21 the agent enforces the cap at dispatch, so a one-line
// surface is required.
//
//	/budget               — show spend, cap, remaining, percent
//	/budget set <USD>     — change cap (preserves existing warn/hit cbs)
//	/budget off           — disable the cap (sets to 0)
func handleBudget(deps *REPLDeps, args []string) {
	if deps.costTracker == nil {
		fmt.Fprintf(os.Stderr, "  %sbudget: cost tracker not installed%s\n", dim, reset)
		return
	}
	if len(args) == 0 {
		printBudget(deps.costTracker.Snapshot())
		return
	}
	sub := strings.ToLower(args[0])
	switch sub {
	case "set":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %susage: /budget set <USD>%s\n", dim, reset)
			return
		}
		raw := strings.TrimPrefix(args[1], "$")
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil || v < 0 {
			fmt.Fprintf(os.Stderr, "  %s● budget: %q is not a non-negative number%s\n", red, args[1], reset)
			return
		}
		deps.costTracker.UpdateBudgetCap(v)
		fmt.Fprintf(os.Stderr, "  %s● budget cap set to $%.2f%s\n", green, v, reset)
		printBudget(deps.costTracker.Snapshot())
	case "off", "clear", "disable":
		deps.costTracker.UpdateBudgetCap(0)
		fmt.Fprintf(os.Stderr, "  %s● budget cap disabled%s\n", green, reset)
	default:
		fmt.Fprintf(os.Stderr, "  %sunknown subcommand %q (expected set|off)%s\n", dim, sub, reset)
	}
}

func printBudget(s cost.Snapshot) {
	if s.BudgetUSD <= 0 {
		fmt.Fprintf(os.Stderr, "  budget: %sdisabled%s  (spent $%.4f)\n", dim, reset, s.TotalUSD)
		fmt.Fprintf(os.Stderr, "  %sset one with /budget set <USD>%s\n", dim, reset)
		return
	}
	pct := (s.TotalUSD / s.BudgetUSD) * 100
	remaining := s.BudgetUSD - s.TotalUSD
	if remaining < 0 {
		remaining = 0
	}
	bar := green
	switch {
	case pct >= 100:
		bar = red
	case pct >= 80:
		bar = yellow
	}
	fmt.Fprintf(os.Stderr, "  budget:    %s$%.4f / $%.2f%s  (%.0f%%)\n", bar, s.TotalUSD, s.BudgetUSD, reset, pct)
	fmt.Fprintf(os.Stderr, "  remaining: $%.4f\n", remaining)
}
