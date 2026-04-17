package obs

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// DebugSnapshot is the state bag /debug renders. Each field is optional
// — callers fill what they can from their local surface. The Render
// method turns this into the boxed multi-line text the REPL prints.
type DebugSnapshot struct {
	BuildVersion    string
	GoVersion       string
	Platform        string
	Uptime          time.Duration
	TraceID         string
	PersonaName     string
	PersonaTools    int
	PersonaAllow    int
	FlipperPort     string
	FlipperUp       bool
	FlipperModel    string
	MarauderPort    string
	MarauderUp      bool
	AuditDBPath     string
	AuditRows       int64
	SessionID       string
	Goroutines      int
	HeapMB          float64
	SysMB           float64
	LastGCAgo       time.Duration
	LastTools       []ToolSample
	OfflineMode     bool
}

// Render draws the snapshot as a box of rows. Width is the inner box
// width in columns; 68 is a sensible default that fits most terminals
// without wrapping. Uses only ASCII box-drawing characters so NO_COLOR
// environments still render.
func (s DebugSnapshot) Render(w io.Writer, width int) {
	if width < 40 {
		width = 40
	}
	hr := strings.Repeat("─", width)
	fmt.Fprintf(w, "┌%s┐\n", hr)

	section(w, width, "Runtime")
	kv(w, width, "Build", s.BuildVersion)
	kv(w, width, "Go", s.GoVersion)
	kv(w, width, "Platform", s.Platform)
	kv(w, width, "Uptime", humanDuration(s.Uptime))
	if s.TraceID != "" {
		kv(w, width, "Trace ID", s.TraceID+" (current turn)")
	}

	section(w, width, "State")
	persona := s.PersonaName
	if persona == "" {
		persona = "default"
	}
	if s.PersonaTools > 0 {
		persona = fmt.Sprintf("%s (allowlist %d/%d tools)", persona, s.PersonaAllow, s.PersonaTools)
	}
	kv(w, width, "Persona", persona)
	kv(w, width, "Flipper", formatTransport(s.FlipperPort, s.FlipperUp, s.FlipperModel))
	kv(w, width, "Marauder", formatTransport(s.MarauderPort, s.MarauderUp, ""))
	if s.AuditDBPath != "" {
		kv(w, width, "Audit DB", fmt.Sprintf("%s (%d entries)", s.AuditDBPath, s.AuditRows))
	}
	if s.SessionID != "" {
		kv(w, width, "Session", s.SessionID)
	}
	if s.OfflineMode {
		kv(w, width, "Mode", "OFFLINE — Anthropic API unreachable")
	}

	section(w, width, "Goroutines")
	kv(w, width, "", fmt.Sprintf("count: %-4d (last GC %s ago; heap %.1f MB / sys %.1f MB)",
		s.Goroutines, humanDuration(s.LastGCAgo), s.HeapMB, s.SysMB))

	if len(s.LastTools) > 0 {
		section(w, width, "Last tool calls")
		for _, t := range s.LastTools {
			mark := "◦"
			if t.Err {
				mark = "✗"
			}
			line := fmt.Sprintf("%s %s  %-24s  %s  [%s]",
				t.At.Local().Format("15:04:05"),
				mark,
				t.Tool,
				t.Duration.Round(time.Millisecond),
				t.Risk,
			)
			kv(w, width, "", line)
		}
	}

	fmt.Fprintf(w, "└%s┘\n", hr)
}

// section writes a "├──── Title ─────┤" divider.
func section(w io.Writer, width int, title string) {
	label := fmt.Sprintf(" %s ", title)
	remaining := width - len(label) - 1
	if remaining < 1 {
		remaining = 1
	}
	fmt.Fprintf(w, "├─%s%s┤\n", label, strings.Repeat("─", remaining-1))
}

// kv writes one "│ label: value" row padded to width.
func kv(w io.Writer, width int, key, val string) {
	var body string
	if key == "" {
		body = " " + val
	} else {
		body = fmt.Sprintf(" %-12s %s", key+":", val)
	}
	if runeLen(body) > width {
		body = truncateRunes(body, width-1) + "…"
	}
	pad := width - runeLen(body)
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(w, "│%s%s│\n", body, strings.Repeat(" ", pad))
}

func formatTransport(port string, up bool, extra string) string {
	if port == "" {
		return "not configured"
	}
	state := "not connected"
	if up {
		state = "connected"
	}
	out := fmt.Sprintf("%s %s", port, state)
	if extra != "" {
		out += " (" + extra + ")"
	}
	return out
}

func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Second {
		return d.String()
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func runeLen(s string) int   { return len([]rune(s)) }

// truncateRunes preserves multibyte boundaries when clipping to n runes.
func truncateRunes(s string, n int) string {
	rr := []rune(s)
	if n >= len(rr) {
		return s
	}
	if n < 0 {
		n = 0
	}
	return string(rr[:n])
}

// CollectRuntime pulls goroutine / heap / GC stats into a partial
// DebugSnapshot so callers only need to add their own
// Persona/Flipper/Audit state. Split out so tests can exercise the
// rendering layer without touching the process.
func CollectRuntime() (goroutines int, heapMB, sysMB float64, lastGCAgo time.Duration, version, plat string) {
	goroutines = runtime.NumGoroutine()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	heapMB = float64(m.HeapAlloc) / (1024 * 1024)
	sysMB = float64(m.Sys) / (1024 * 1024)
	if m.LastGC > 0 {
		lastGCAgo = time.Since(time.Unix(0, int64(m.LastGC)))
	}
	version = runtime.Version()
	plat = runtime.GOOS + "/" + runtime.GOARCH

	// Try to pick up a build revision from debug.BuildInfo. Released
	// binaries may have this stripped, hence the zero-value fallback.
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				version = version + "/" + shortSHA(s.Value)
			}
		}
	}
	return
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}
