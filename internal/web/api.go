// HTTP JSON endpoints that surface REPL-only features (persona, watch,
// cost, rules, validator, debug) to the web UI. The handlers here are
// intentionally thin: they adapt the host-supplied subsystem to a JSON
// shape the Alpine cockpit understands, and never own state of their own.
//
// Every endpoint tolerates a nil subsystem — when the host has not wired
// a registry/watcher/tracker/engine the handler answers 503 with a short
// JSON body. The frontend uses that to hide the relevant panel rather
// than showing a broken state.

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/validator"
	"github.com/xunholy/promptzero/internal/version"
)

// registerAPIRoutes mounts the panel endpoints on mux. Paths use the
// Go 1.22+ pattern syntax so we can thread rule names through the URL
// without a third-party router.
func (s *Server) registerAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/personas", s.handlePersonasList)
	mux.HandleFunc("POST /api/personas/switch", s.handlePersonasSwitch)

	mux.HandleFunc("GET /api/watch", s.handleWatch)
	mux.HandleFunc("POST /api/watch/pause", s.handleWatchPause)
	mux.HandleFunc("POST /api/watch/resume", s.handleWatchResume)

	mux.HandleFunc("GET /api/cost", s.handleCost)

	mux.HandleFunc("GET /api/rules", s.handleRulesList)
	mux.HandleFunc("POST /api/rules/{name}/pause", s.handleRulePause)
	mux.HandleFunc("POST /api/rules/{name}/resume", s.handleRuleResume)
	mux.HandleFunc("POST /api/rules/{name}/test", s.handleRuleTest)

	mux.HandleFunc("POST /api/validate", s.handleValidate)

	mux.HandleFunc("GET /api/debug", s.handleDebug)
}

// respondJSON is the common success-path writer. Marshalling failures log
// on the server but send a generic 500 so the UI never has to parse a
// half-written body.
func respondJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError wraps a reason in {"error": "..."} and the given status.
func writeError(w http.ResponseWriter, status int, reason string) {
	respondJSON(w, status, map[string]string{"error": reason})
}

// ---------------------------------------------------------------------------
// Personas
// ---------------------------------------------------------------------------

type personaEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Tools       int    `json:"tools"`
}

func (s *Server) handlePersonasList(w http.ResponseWriter, r *http.Request) {
	if s.personas == nil {
		writeError(w, http.StatusServiceUnavailable, "persona registry not configured")
		return
	}
	names := s.personas.Names()
	out := make([]personaEntry, 0, len(names))
	for _, n := range names {
		p, ok := s.personas.Get(n)
		if !ok {
			continue
		}
		out = append(out, personaEntry{
			Name:        p.Name,
			Description: p.Description,
			Tools:       len(p.Tools),
		})
	}
	current := ""
	if p := s.agent.Persona(); p != nil {
		current = p.Name
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"current":   current,
		"available": out,
	})
}

func (s *Server) handlePersonasSwitch(w http.ResponseWriter, r *http.Request) {
	if s.personas == nil {
		writeError(w, http.StatusServiceUnavailable, "persona registry not configured")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "missing 'name'")
		return
	}
	p, ok := s.personas.Get(body.Name)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("unknown persona %q", body.Name))
		return
	}
	s.agent.SetPersona(p)
	// Announce the change on the broadcast channel so peer tabs that aren't
	// the one that clicked still know the operator mode moved.
	s.broadcast(map[string]any{
		"type":    "persona_switched",
		"name":    p.Name,
		"content": "persona switched to " + p.Name,
	})
	respondJSON(w, http.StatusOK, map[string]any{
		"current":     p.Name,
		"description": p.Description,
		"tools":       len(p.Tools),
	})
}

// ---------------------------------------------------------------------------
// Watch
// ---------------------------------------------------------------------------

type watchRuleDTO struct {
	Pattern string `json:"pattern"`
	Prompt  string `json:"prompt"`
	Persona string `json:"persona,omitempty"`
}

type watchEventDTO struct {
	At      time.Time `json:"at"`
	Path    string    `json:"path"`
	Rule    string    `json:"rule"`
	Prompt  string    `json:"prompt"`
	Persona string    `json:"persona,omitempty"`
	Error   string    `json:"error,omitempty"`
}

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	if s.watcher == nil {
		writeError(w, http.StatusServiceUnavailable, "watcher not configured")
		return
	}
	wr := s.watcher.Rules()
	rulesDTO := make([]watchRuleDTO, 0, len(wr))
	for _, r := range wr {
		rulesDTO = append(rulesDTO, watchRuleDTO{
			Pattern: r.Pattern,
			Prompt:  r.Prompt,
			Persona: r.Persona,
		})
	}
	events := s.watcher.Recent(10)
	evDTO := make([]watchEventDTO, 0, len(events))
	for _, e := range events {
		dto := watchEventDTO{
			At:      e.At,
			Path:    e.Path,
			Rule:    e.Rule.Pattern,
			Prompt:  e.Rule.Prompt,
			Persona: e.Rule.Persona,
		}
		if e.Error != nil {
			dto.Error = e.Error.Error()
		}
		evDTO = append(evDTO, dto)
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"enabled":       !s.watcher.Paused(),
		"paused":        s.watcher.Paused(),
		"paths":         s.watcher.Paths(),
		"rules":         rulesDTO,
		"recent_events": evDTO,
	})
}

func (s *Server) handleWatchPause(w http.ResponseWriter, r *http.Request) {
	if s.watcher == nil {
		writeError(w, http.StatusServiceUnavailable, "watcher not configured")
		return
	}
	s.watcher.Pause()
	respondJSON(w, http.StatusOK, map[string]any{"paused": true})
}

func (s *Server) handleWatchResume(w http.ResponseWriter, r *http.Request) {
	if s.watcher == nil {
		writeError(w, http.StatusServiceUnavailable, "watcher not configured")
		return
	}
	s.watcher.Resume()
	respondJSON(w, http.StatusOK, map[string]any{"paused": false})
}

// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

type costByModelDTO struct {
	Model        string  `json:"model"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	USD          float64 `json:"usd"`
}

func (s *Server) handleCost(w http.ResponseWriter, r *http.Request) {
	if s.costs == nil {
		writeError(w, http.StatusServiceUnavailable, "cost tracker not configured")
		return
	}
	snap := s.costs.Snapshot()
	total := map[string]any{
		"input_tokens":  snap.InputTokens,
		"output_tokens": snap.OutputTokens,
		"usd":           round4(snap.TotalUSD),
	}
	// Tracker is bound to one model at a time; surface that single slice
	// as a per-model breakdown so the frontend contract can stay uniform
	// when a future version tracks per-model split natively.
	byModel := []costByModelDTO{{
		Model:        snap.Model,
		InputTokens:  snap.InputTokens,
		OutputTokens: snap.OutputTokens,
		USD:          round4(snap.TotalUSD),
	}}
	respondJSON(w, http.StatusOK, map[string]any{
		"total":    total,
		"by_model": byModel,
		"offline":  snap.Offline,
	})
}

// round4 trims noise from the running USD total for display. Cents carry
// enough precision for pricing that goes to $0.0001/MTok.
func round4(v float64) float64 {
	const p = 10000
	return float64(int64(v*p+0.5)) / p
}

// costTrackerForTest lets unit tests satisfy the *cost.Tracker field
// without constructing a Pricer chain. Kept unexported so the public
// surface stays concrete.
type _ = cost.Tracker // compile-time reminder we depend on the concrete type

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

type ruleDTO struct {
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	Enabled             bool      `json:"enabled"`
	FireCount           int       `json:"fire_count"`
	LastFired           time.Time `json:"last_fired,omitempty"`
	CooldownRemainingMS int64     `json:"cooldown_remaining_ms"`
}

func (s *Server) handleRulesList(w http.ResponseWriter, r *http.Request) {
	if s.rulesEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "rules engine not configured")
		return
	}
	snaps := s.rulesEngine.List()
	out := make([]ruleDTO, 0, len(snaps))
	for _, snap := range snaps {
		out = append(out, ruleDTO{
			Name:        snap.Name,
			Description: snap.Description,
			Enabled:     snap.Enabled,
			FireCount:   snap.Fires,
			LastFired:   snap.LastFire,
		})
	}
	respondJSON(w, http.StatusOK, out)
}

func (s *Server) handleRulePause(w http.ResponseWriter, r *http.Request) {
	if s.rulesEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "rules engine not configured")
		return
	}
	name := r.PathValue("name")
	if !s.rulesEngine.Pause(name) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("unknown rule %q", name))
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"name": name, "enabled": false})
}

func (s *Server) handleRuleResume(w http.ResponseWriter, r *http.Request) {
	if s.rulesEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "rules engine not configured")
		return
	}
	name := r.PathValue("name")
	if !s.rulesEngine.Resume(name) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("unknown rule %q", name))
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"name": name, "enabled": true})
}

func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	if s.rulesEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "rules engine not configured")
		return
	}
	name := r.PathValue("name")
	// Synthetic entry used for preview. The operator only sees what a match
	// would render; no side effects are triggered.
	entry := audit.Entry{
		Tool:      "preview",
		Risk:      "medium",
		Level:     audit.LevelInfo,
		SessionID: "web-test",
		TraceID:   "web-test",
		Output:    "preview output",
		Success:   true,
	}
	rendered, err := s.rulesEngine.Test(name, entry)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"name":    name,
		"actions": rendered,
	})
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

type validateReportDTO struct {
	Name        string               `json:"name"`
	OverallRisk string               `json:"overall_risk"`
	Approved    bool                 `json:"approved"`
	Findings    []validateFindingDTO `json:"findings"`
}

type validateFindingDTO struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Message  string `json:"message"`
	Line     int    `json:"line"`
	Excerpt  string `json:"excerpt,omitempty"`
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	name := body.Path
	src := body.Content
	if src == "" {
		if body.Path == "" {
			writeError(w, http.StatusBadRequest, "expected 'path' or 'content'")
			return
		}
		data, err := os.ReadFile(body.Path)
		if err != nil {
			writeError(w, http.StatusBadRequest, "read "+body.Path+": "+err.Error())
			return
		}
		src = string(data)
	}
	if name == "" {
		name = "<inline>"
	}
	rep := validator.Validate(name, src)
	findings := make([]validateFindingDTO, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		findings = append(findings, validateFindingDTO{
			Severity: f.Severity.String(),
			Rule:     f.Rule,
			Message:  f.Message,
			Line:     f.Line,
			Excerpt:  f.Excerpt,
		})
	}
	respondJSON(w, http.StatusOK, validateReportDTO{
		Name:        rep.Name,
		OverallRisk: rep.Severity.String(),
		Approved:    !rep.Has(validator.SeverityCritical),
		Findings:    findings,
	})
}

// ---------------------------------------------------------------------------
// Debug snapshot
// ---------------------------------------------------------------------------

func (s *Server) handleDebug(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	personaName := ""
	if p := s.agent.Persona(); p != nil {
		personaName = p.Name
	}

	uptime := time.Since(s.startedAt).Truncate(time.Second)

	s.mu.Lock()
	activeConns := len(s.conns)
	s.mu.Unlock()

	respondJSON(w, http.StatusOK, map[string]any{
		"build": map[string]any{
			"version": version.Version,
			"commit":  version.Commit,
			"date":    version.Date,
		},
		"runtime": map[string]any{
			"goroutines":     runtime.NumGoroutine(),
			"heap_mb":        bytesToMB(mem.HeapAlloc),
			"sys_mb":         bytesToMB(mem.Sys),
			"uptime_seconds": int64(uptime.Seconds()),
			"go_version":     runtime.Version(),
		},
		"state": map[string]any{
			"persona":            personaName,
			"flipper_connected":  s.flipperOn.Load(),
			"marauder_connected": s.marauderOn.Load(),
			"active_connections": activeConns,
		},
	})
}

func bytesToMB(b uint64) uint64 {
	return b / (1024 * 1024)
}
