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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/campaign"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/mode"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/report"
	"github.com/xunholy/promptzero/internal/validator"
	"github.com/xunholy/promptzero/internal/version"
)

// registerAPIRoutes mounts the panel endpoints on mux. Paths use the
// Go 1.22+ pattern syntax so we can thread rule names through the URL
// without a third-party router. Every handler is wrapped in requireAuth
// so a configured bearer token is enforced uniformly; /api/auth exists
// as the one open endpoint so the frontend can distinguish "no token
// configured" (skip the login prompt) from "wrong token" (re-prompt).
func (s *Server) registerAPIRoutes(mux *http.ServeMux) {
	// Open: lets the frontend detect whether auth is required before it
	// sends any credentials. Returns {"required": bool}.
	mux.HandleFunc("GET /api/auth", s.handleAuthInfo)

	mux.HandleFunc("GET /api/personas", s.requireAuth(s.handlePersonasList))
	mux.HandleFunc("POST /api/personas/switch", s.requireAuth(s.handlePersonasSwitch))

	mux.HandleFunc("GET /api/mode", s.requireAuth(s.handleModeGet))
	mux.HandleFunc("POST /api/mode", s.requireAuth(s.handleModeSet))

	mux.HandleFunc("GET /api/attack", s.requireAuth(s.handleAttackGet))
	mux.HandleFunc("POST /api/attack", s.requireAuth(s.handleAttackSet))
	mux.HandleFunc("DELETE /api/attack", s.requireAuth(s.handleAttackClear))

	mux.HandleFunc("GET /api/tools", s.requireAuth(s.handleToolsList))
	mux.HandleFunc("GET /api/webhooks", s.requireAuth(s.handleWebhooksList))
	mux.HandleFunc("POST /api/webhooks/test", s.requireAuth(s.handleWebhooksTest))
	mux.HandleFunc("POST /api/reconnect", s.requireAuth(s.handleReconnect))

	mux.HandleFunc("GET /api/report", s.requireAuth(s.handleReport))

	mux.HandleFunc("GET /api/rewind", s.requireAuth(s.handleRewindList))
	mux.HandleFunc("POST /api/rewind/restore", s.requireAuth(s.handleRewindRestore))

	mux.HandleFunc("POST /api/campaign/validate", s.requireAuth(s.handleCampaignValidate))
	mux.HandleFunc("POST /api/campaign/run", s.requireAuth(s.handleCampaignRun))

	mux.HandleFunc("GET /api/watch", s.requireAuth(s.handleWatch))
	mux.HandleFunc("POST /api/watch/pause", s.requireAuth(s.handleWatchPause))
	mux.HandleFunc("POST /api/watch/resume", s.requireAuth(s.handleWatchResume))

	mux.HandleFunc("GET /api/cost", s.requireAuth(s.handleCost))
	mux.HandleFunc("GET /api/budget", s.requireAuth(s.handleBudgetGet))
	mux.HandleFunc("PUT /api/budget", s.requireAuth(s.handleBudgetPut))

	mux.HandleFunc("GET /api/audit/stats", s.requireAuth(s.handleAuditStats))
	mux.HandleFunc("GET /api/audit/query", s.requireAuth(s.handleAuditQuery))
	mux.HandleFunc("GET /api/audit/find", s.requireAuth(s.handleAuditFind))
	mux.HandleFunc("GET /api/audit/session/{id}", s.requireAuth(s.handleAuditSession))
	mux.HandleFunc("GET /api/audit/top", s.requireAuth(s.handleAuditTop))
	mux.HandleFunc("GET /api/audit/export", s.requireAuth(s.handleAuditExport))

	mux.HandleFunc("GET /api/rules", s.requireAuth(s.handleRulesList))
	mux.HandleFunc("POST /api/rules/{name}/pause", s.requireAuth(s.handleRulePause))
	mux.HandleFunc("POST /api/rules/{name}/resume", s.requireAuth(s.handleRuleResume))
	mux.HandleFunc("POST /api/rules/{name}/test", s.requireAuth(s.handleRuleTest))

	mux.HandleFunc("POST /api/validate", s.requireAuth(s.handleValidate))

	mux.HandleFunc("GET /api/debug", s.requireAuth(s.handleDebug))

	mux.HandleFunc("GET /api/device", s.requireAuth(s.handleDevice))

	mux.HandleFunc("GET /api/fs/list", s.requireAuth(s.handleFSList))
	mux.HandleFunc("GET /api/fs/read", s.requireAuth(s.handleFSRead))
	mux.HandleFunc("GET /api/fs/stat", s.requireAuth(s.handleFSStat))
	mux.HandleFunc("POST /api/fs/upload", s.requireAuth(s.handleFSUpload))
	mux.HandleFunc("POST /api/fs/delete", s.requireAuth(s.handleFSDelete))
	mux.HandleFunc("POST /api/fs/mkdir", s.requireAuth(s.handleFSMkdir))
	mux.HandleFunc("POST /api/fs/rename", s.requireAuth(s.handleFSRename))

	mux.HandleFunc("POST /api/input/send", s.requireAuth(s.handleInputSend))

	mux.HandleFunc("GET /api/sessions", s.requireAuth(s.handleSessionList))
	mux.HandleFunc("POST /api/sessions", s.requireAuth(s.handleSessionNew))
	mux.HandleFunc("GET /api/sessions/{id}", s.requireAuth(s.handleSessionGet))
	mux.HandleFunc("POST /api/sessions/{id}/resume", s.requireAuth(s.handleSessionResume))
	mux.HandleFunc("PATCH /api/sessions/{id}", s.requireAuth(s.handleSessionPatch))
	mux.HandleFunc("DELETE /api/sessions/{id}", s.requireAuth(s.handleSessionDelete))
}

// handleAuthInfo reports whether the server requires a bearer token.
// Always unauthenticated — it carries no tool metadata, just a bool the
// frontend needs to decide whether to show a token-entry prompt.
func (s *Server) handleAuthInfo(w http.ResponseWriter, _ *http.Request) {
	respondJSON(w, http.StatusOK, map[string]bool{"required": s.token != ""})
}

// respondJSON is the common success-path writer. Encode errors are
// rare in practice (they imply a malformed body shape rather than a
// network problem) but worth logging when they happen — silent
// failures here would surface to the operator as a half-written
// response with no server-side breadcrumb.
//
// The header + status are already written before encode runs, so we
// can't switch to a 500 mid-flight; the next-best thing is a warn
// log so the misbehaving handler is visible. Callers can avoid the
// case entirely by passing JSON-friendly types.
func respondJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		obs.Default().Warn("web_respond_json_encode_failed", "status", status, "err", err)
	}
}

// writeError wraps a reason in {"error": "..."} and the given status.
func writeError(w http.ResponseWriter, status int, reason string) {
	respondJSON(w, status, map[string]string{"error": reason})
}

// maxJSONBodyBytes caps the body size for /api/* JSON endpoints.
// Operator-driven JSON payloads in this surface are small (persona
// name, mode name, attack ID list, etc.) — 64 KiB is plenty of
// headroom. The cap guards against a malicious or buggy client
// streaming an unbounded body and exhausting server memory before
// the JSON parser runs.
const maxJSONBodyBytes = 64 * 1024

// decodeJSONBody is the shared JSON-body reader. Wraps r.Body in
// http.MaxBytesReader before decoding so an oversized POST returns
// 413 (clean classify) instead of being silently buffered. On
// any error it writes the appropriate status (413 for oversize
// via http.MaxBytesError detection, 400 for malformed JSON) and
// returns false. Callers use the bool to decide whether to
// continue.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	err := json.NewDecoder(r.Body).Decode(dst)
	if err == nil {
		return true
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("body exceeds %d bytes", maxJSONBodyBytes))
		return false
	}
	writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
	return false
}

// ---------------------------------------------------------------------------
// Personas
// ---------------------------------------------------------------------------

type personaEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Tools is the length of the persona's explicit tool allowlist. An
	// empty (or nil) allowlist is treated as "no restriction" by
	// persona.FilterTools, so Tools==0 without Unrestricted is a
	// zero-capability persona rather than an all-access one.
	Tools        int  `json:"tools"`
	Unrestricted bool `json:"unrestricted"`
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
			Name:         p.Name,
			Description:  p.Description,
			Tools:        len(p.Tools),
			Unrestricted: p.IsUnrestricted(),
		})
	}
	current := ""
	if p := s.agent.PersonaSnapshot(); p != nil {
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
	if !decodeJSONBody(w, r, &body) {
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
	switchID := newID()
	// Announce the change on the broadcast channel so peer tabs that aren't
	// the one that clicked still know the operator mode moved. switch_id lets
	// the originating tab suppress its own echo.
	s.broadcast(map[string]any{
		"type":      "persona_switched",
		"name":      p.Name,
		"content":   "persona switched to " + p.Name,
		"switch_id": switchID,
	})
	respondJSON(w, http.StatusOK, map[string]any{
		"current":      p.Name,
		"description":  p.Description,
		"tools":        len(p.Tools),
		"unrestricted": p.IsUnrestricted(),
		"switch_id":    switchID,
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
		"input_tokens":          snap.InputTokens,
		"output_tokens":         snap.OutputTokens,
		"cache_read_tokens":     snap.CacheReadTokens,
		"cache_creation_tokens": snap.CacheCreationTokens,
		"cache_hit_rate":        snap.CacheHitRate(),
		"usd":                   round4(snap.TotalUSD),
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
	body := map[string]any{
		"total":    total,
		"by_model": byModel,
		"offline":  snap.Offline,
	}
	// Budget block is omitted when no cap is configured so the
	// frontend can render "budget: disabled" without disambiguating
	// 0-the-cap from 0-the-spent. Same shape as the /cost CLI
	// rendering: cap, spent, remaining (clamped at 0), pct.
	if snap.BudgetUSD > 0 {
		spent := snap.TotalUSD
		remaining := snap.BudgetUSD - spent
		if remaining < 0 {
			remaining = 0
		}
		body["budget"] = map[string]any{
			"cap_usd":       round4(snap.BudgetUSD),
			"spent_usd":     round4(spent),
			"remaining_usd": round4(remaining),
			"percent":       round4((spent / snap.BudgetUSD) * 100),
		}
	}
	respondJSON(w, http.StatusOK, body)
}

// maxCampaignBodyBytes caps the YAML body the campaign endpoints
// accept. Realistic campaign files are a few hundred bytes to a
// few KB; 256 KiB is generous headroom while bounding an obvious
// DoS vector (unbounded io.ReadAll on a POST body).
const maxCampaignBodyBytes = 256 * 1024

// handleCampaignValidate parses the request body as a campaign YAML
// and reports the result. Body is the raw YAML text; Content-Type
// is not enforced (the CLI accepts paths, the web accepts inline
// text). Mirrors CLI `/campaign validate <file>` minus the file-
// read half — clients embed the YAML in the request body directly.
func (s *Server) handleCampaignValidate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCampaignBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("body exceeds %d bytes or read failed: %v", maxCampaignBodyBytes, err))
		return
	}
	c, err := campaign.ParseYAML(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid campaign: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"valid":      true,
		"name":       c.Name,
		"step_count": len(c.Steps),
	})
}

// handleCampaignRun parses the request body as a campaign YAML and
// executes it synchronously against the agent's tool dispatch.
// Mirrors CLI `/campaign run <file>` semantics, including the 10-
// minute total-time budget. Returns the full RunResult envelope —
// step results, durations, error per step.
//
// Synchronous on purpose: campaigns are operator-driven workflows
// where mid-run aborts already happen via ctx cancellation
// (closing the HTTP connection cancels ctx; the runner honours it
// between steps). Async/SSE wiring is future work — for now the
// timeout mirrors the CLI.
func (s *Server) handleCampaignRun(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil {
		writeError(w, http.StatusServiceUnavailable, "agent not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCampaignBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("body exceeds %d bytes or read failed: %v", maxCampaignBodyBytes, err))
		return
	}
	c, err := campaign.ParseYAML(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid campaign: "+err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	runner := campaign.NewRunner(campaign.AgentExecutor{Dispatcher: s.agent})
	result := runner.Run(ctx, c)

	// Project StepResult into JSON-friendly DTOs (the campaign
	// package uses time.Time and *Step fields we don't want
	// exposed verbatim).
	steps := make([]map[string]any, 0, len(result.StepResults))
	for _, sr := range result.StepResults {
		row := map[string]any{
			"step_id":     sr.StepID,
			"tool":        sr.Tool,
			"started_at":  sr.StartedAt.UTC().Format(time.RFC3339),
			"duration_ms": sr.Duration.Milliseconds(),
			"output":      sr.Output,
			"skipped":     sr.Skipped,
		}
		if sr.SkipReason != "" {
			row["skip_reason"] = sr.SkipReason
		}
		if sr.Err != nil {
			row["error"] = sr.Err.Error()
		}
		steps = append(steps, row)
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"campaign":     result.Campaign,
		"succeeded":    result.Succeeded(),
		"started_at":   result.StartedAt.UTC().Format(time.RFC3339),
		"ended_at":     result.EndedAt.UTC().Format(time.RFC3339),
		"duration_ms":  result.Duration().Milliseconds(),
		"step_results": steps,
	})
}

// handleRewindList returns the per-session snapshot entries newest-
// first. Mirrors CLI `/rewind` (no-args) listing. The entry IDs are
// timestamp-prefixed so string-sort matches chronological order;
// the cockpit can render them as-is.
func (s *Server) handleRewindList(w http.ResponseWriter, _ *http.Request) {
	if s.agent == nil {
		writeError(w, http.StatusServiceUnavailable, "agent not configured")
		return
	}
	mgr := s.agent.SnapshotManager()
	if mgr == nil {
		writeError(w, http.StatusServiceUnavailable, "snapshot manager not configured")
		return
	}
	sessionID := s.agent.SessionID()
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "no active session — start one before listing snapshots")
		return
	}
	entries, err := mgr.List(sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "snapshot list: "+err.Error())
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"id":            e.ID,
			"taken_at":      e.TakenAt.UTC().Format(time.RFC3339),
			"size_bytes":    e.SizeBytes,
			"original_path": e.OriginalPath,
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"entries":    out,
	})
}

// handleRewindRestore restores a snapshot onto the Flipper. Body:
//
//	{"id": "<snapshot-id>", "dry_run": false}
//
// Mirrors CLI `/rewind <id> [dry-run]`. Pop-N mode (CLI's
// `/rewind <n>`) is intentionally NOT exposed here — it's a
// multi-write batch operation where partial failure is confusing
// over an HTTP single-response. Cockpit can issue N restore calls
// from the GET listing instead.
func (s *Server) handleRewindRestore(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil {
		writeError(w, http.StatusServiceUnavailable, "agent not configured")
		return
	}
	mgr := s.agent.SnapshotManager()
	if mgr == nil {
		writeError(w, http.StatusServiceUnavailable, "snapshot manager not configured")
		return
	}
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "no Flipper attached")
		return
	}
	sessionID := s.agent.SessionID()
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "no active session")
		return
	}
	var body struct {
		ID     string `json:"id"`
		DryRun bool   `json:"dry_run"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.ID) == "" {
		writeError(w, http.StatusBadRequest, "missing 'id'")
		return
	}
	entry, content, err := mgr.Restore(sessionID, body.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "snapshot restore: "+err.Error())
		return
	}
	if body.DryRun {
		respondJSON(w, http.StatusOK, map[string]any{
			"dry_run":       true,
			"id":            entry.ID,
			"original_path": entry.OriginalPath,
			"would_write":   len(content),
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.flipper.WriteFileCtx(ctx, entry.OriginalPath, content); err != nil {
		writeError(w, http.StatusBadGateway, "snapshot write: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"id":            entry.ID,
		"original_path": entry.OriginalPath,
		"bytes":         len(content),
	})
}

// handleReport renders an engagement report for a session.
// Query params:
//   - format=md|json (default md)
//   - session=<id> (default: the audit log's current session)
//
// The response is the raw rendered body (text/markdown or
// application/json) with the appropriate Content-Type so the
// cockpit can render in-place or save-as. Mirrors CLI
// `/report [session] [json] [save]` minus the file-save half —
// web clients save the response body themselves.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if s.auditLog == nil {
		writeError(w, http.StatusServiceUnavailable, "audit log not configured")
		return
	}
	q := r.URL.Query()
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format == "" {
		format = "md"
	}
	if format != "md" && format != "json" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("format=%s: want md|json", format))
		return
	}
	sessionID := strings.TrimSpace(q.Get("session"))
	if sessionID == "" {
		sessionID = s.auditLog.SessionID()
	}
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "no active session; pass ?session=<id>")
		return
	}
	entries, err := s.auditLog.QueryBySession(sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report query: "+err.Error())
		return
	}
	summary := report.Summarise(sessionID, entries, attack.NewDefaultIndex())
	var (
		body []byte
		ct   string
	)
	if format == "json" {
		body, err = report.JSONRenderer{}.Render(summary)
		ct = "application/json"
	} else {
		body, err = report.MarkdownRenderer{}.Render(summary)
		ct = "text/markdown; charset=utf-8"
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report render: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleToolsList returns every registered tool with name +
// description. Optional ?filter=<substring> narrows by name (case-
// insensitive), matching CLI `/tools [filter]`. Always returns the
// full set in one response (no pagination); the cockpit can do
// client-side narrowing or this endpoint can add pagination later
// if the catalogue grows past ~300 entries.
func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request) {
	hasMarauder := s.marauderOn.Load()
	cat := agent.ToolCatalog(hasMarauder)
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("filter")))
	out := make([]map[string]any, 0, len(cat))
	for _, e := range cat {
		if filter != "" && !strings.Contains(strings.ToLower(e.Name), filter) {
			continue
		}
		out = append(out, map[string]any{
			"name":        e.Name,
			"description": e.Description,
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"count":        len(out),
		"total":        len(cat),
		"has_marauder": hasMarauder,
		"tools":        out,
	})
}

// handleWebhooksList returns every configured webhook subscription
// plus its recent delivery results, same surface as CLI `/webhooks`.
// Secrets are NEVER returned; the cockpit shows "(signed)" badge
// based on the `signed` boolean we project from non-empty Secret.
func (s *Server) handleWebhooksList(w http.ResponseWriter, _ *http.Request) {
	if s.webhooks == nil {
		writeError(w, http.StatusServiceUnavailable, "webhook dispatcher not configured")
		return
	}
	subs := s.webhooks.Subscriptions()
	out := make([]map[string]any, 0, len(subs))
	for _, sub := range subs {
		events := make([]string, 0, len(sub.Events))
		for _, e := range sub.Events {
			events = append(events, string(e))
		}
		recent := s.webhooks.RecentResults(sub.Name)
		results := make([]map[string]any, 0, len(recent))
		for _, r := range recent {
			row := map[string]any{
				"event":       string(r.Event),
				"at":          r.At.UTC().Format(time.RFC3339),
				"status_code": r.StatusCode,
			}
			if r.Err != nil {
				row["error"] = r.Err.Error()
			}
			results = append(results, row)
		}
		out = append(out, map[string]any{
			"name":           sub.Name,
			"url":            sub.URL,
			"events":         events,
			"signed":         sub.Secret != "",
			"recent_results": results,
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
}

// handleWebhooksTest fires a synthetic session_started payload at
// the named subscription so operators can verify reachability
// without waiting for a real event. Body: {"name": "ops"}.
// Mirrors CLI `/webhooks test <name>`.
func (s *Server) handleWebhooksTest(w http.ResponseWriter, r *http.Request) {
	if s.webhooks == nil {
		writeError(w, http.StatusServiceUnavailable, "webhook dispatcher not configured")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "missing 'name'")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.webhooks.TestSubscription(ctx, body.Name); err != nil {
		writeError(w, http.StatusBadGateway, "test delivery failed: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"name": body.Name, "delivered": true})
}

// handleReconnect force-reconnects the Flipper, identical to the
// CLI's `/reconnect`. 15-second timeout matches the REPL's handler.
// 503 when no Flipper is attached.
func (s *Server) handleReconnect(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "no Flipper attached")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.flipper.Reconnect(ctx); err != nil {
		writeError(w, http.StatusBadGateway, "reconnect failed: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"reconnected": true})
}

// attackIDRE is the same regex the CLI's normaliseAttackIDs uses
// (commands.go:909). MITRE format: T + 4 digits, optionally a
// 3-digit sub-technique suffix.
var attackIDRE = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// normaliseAttackIDsWeb mirrors the CLI's normaliseAttackIDs.
// Uppercase + trim, reject empties via final length check, reject
// any token that doesn't match the MITRE shape with a clear error.
// Same vocabulary as the CLI so operators don't relearn.
func normaliseAttackIDsWeb(in []string) ([]string, error) {
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

// handleAttackGet returns the active ATT&CK technique constraint.
// Empty list means "no constraint" (all tools allowed). Mirrors the
// CLI's `/attack` (no-args) listing.
func (s *Server) handleAttackGet(w http.ResponseWriter, _ *http.Request) {
	if s.agent == nil {
		writeError(w, http.StatusServiceUnavailable, "agent not configured")
		return
	}
	ids := s.agent.AttackConstraint()
	if ids == nil {
		ids = []string{}
	}
	respondJSON(w, http.StatusOK, map[string]any{"techniques": ids})
}

// handleAttackSet pins the session to the given ATT&CK technique
// IDs. Body: {"techniques": ["T1557.004", "T1499"]}. Empty list or
// missing key is rejected with 400 — to clear the constraint use
// DELETE /api/attack. Mirrors CLI `/attack set T1557.004 …`.
func (s *Server) handleAttackSet(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil {
		writeError(w, http.StatusServiceUnavailable, "agent not configured")
		return
	}
	var body struct {
		Techniques []string `json:"techniques"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	ids, err := normaliseAttackIDsWeb(body.Techniques)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.agent.SetAttackConstraint(ids)
	respondJSON(w, http.StatusOK, map[string]any{"techniques": s.agent.AttackConstraint()})
}

// handleAttackClear removes the constraint. Mirrors CLI
// `/attack clear`. DELETE is the more REST-idiomatic verb for
// "remove the resource" than POST with a magic body shape.
func (s *Server) handleAttackClear(w http.ResponseWriter, _ *http.Request) {
	if s.agent == nil {
		writeError(w, http.StatusServiceUnavailable, "agent not configured")
		return
	}
	s.agent.SetAttackConstraint(nil)
	respondJSON(w, http.StatusOK, map[string]any{"techniques": []string{}})
}

// auditEntryDTO mirrors audit.Entry but trims to the operator-relevant
// fields and renders the timestamp as RFC3339 for JSON consumers.
type auditEntryDTO struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	Tool       string `json:"tool"`
	Input      string `json:"input"`
	Output     string `json:"output,omitempty"`
	Risk       string `json:"risk,omitempty"`
	Level      string `json:"level,omitempty"`
	SessionID  string `json:"session_id"`
	DurationMs int64  `json:"duration_ms"`
	Success    bool   `json:"success"`
}

func auditEntriesToDTO(entries []audit.Entry) []auditEntryDTO {
	out := make([]auditEntryDTO, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditEntryDTO{
			ID:         e.ID,
			Timestamp:  e.Timestamp.UTC().Format(time.RFC3339),
			Tool:       e.Tool,
			Input:      e.Input,
			Output:     e.Output,
			Risk:       e.Risk,
			Level:      string(e.Level),
			SessionID:  e.SessionID,
			DurationMs: e.Duration,
			Success:    e.Success,
		})
	}
	return out
}

// parseWhenWebStr accepts either a relative duration ("30m", "2h",
// "7d") or an RFC3339 timestamp and returns the corresponding
// time.Time. Mirrors the CLI's parseWhen — both surfaces use the
// same vocabulary so operators don't have to learn two grammars.
func parseWhenWebStr(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	if n := len(s); n > 1 && (s[n-1] == 'd' || s[n-1] == 'D') {
		days, err := strconv.Atoi(s[:n-1])
		if err == nil {
			if days < 0 {
				return time.Time{}, fmt.Errorf("negative duration %q (use e.g. %q not %q)", s, s[1:], s)
			}
			return time.Now().Add(-time.Duration(days) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d < 0 {
			return time.Time{}, fmt.Errorf("negative duration %q (use e.g. %q not %q)", s, s[1:], s)
		}
		return time.Now().Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("cannot parse %q as duration or RFC3339 timestamp", s)
}

// handleAuditStats returns the session-level audit summary — same
// surface as the CLI's `/audit stats`.
func (s *Server) handleAuditStats(w http.ResponseWriter, _ *http.Request) {
	if s.auditLog == nil {
		writeError(w, http.StatusServiceUnavailable, "audit log not configured")
		return
	}
	stats, err := s.auditLog.Stats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit stats: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"session_id": s.auditLog.SessionID(),
		"stats":      stats,
	})
}

// handleAuditQuery returns the N most recent audit rows.
// ?n=20 (default 20, capped at audit.MaxQueryLimit). Mirrors
// `/audit query [N]`.
func (s *Server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	if s.auditLog == nil {
		writeError(w, http.StatusServiceUnavailable, "audit log not configured")
		return
	}
	n := 20
	if raw := r.URL.Query().Get("n"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			n = v
		}
	}
	if n > audit.MaxQueryLimit {
		n = audit.MaxQueryLimit
	}
	entries, err := s.auditLog.Query(n)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit query: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"entries": auditEntriesToDTO(entries),
	})
}

// handleAuditFind drives audit.QueryFiltered via URL query params:
// ?tool=…&risk=…&session=…&since=…&until=…&success=true|false
// &contains=…&limit=…&offset=…. Mirrors `/audit find k=v …` exactly,
// including the negative-duration rejection on since/until.
func (s *Server) handleAuditFind(w http.ResponseWriter, r *http.Request) {
	if s.auditLog == nil {
		writeError(w, http.StatusServiceUnavailable, "audit log not configured")
		return
	}
	q := r.URL.Query()
	var f audit.Filter
	f.Tool = q.Get("tool")
	if risk := strings.ToLower(q.Get("risk")); risk != "" {
		switch risk {
		case "low", "medium", "high", "critical":
			f.Risk = risk
		default:
			writeError(w, http.StatusBadRequest, fmt.Sprintf("risk=%s: want low|medium|high|critical", risk))
			return
		}
	}
	f.Session = q.Get("session")
	f.Contains = q.Get("contains")
	if since := q.Get("since"); since != "" {
		t, err := parseWhenWebStr(since)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since: "+err.Error())
			return
		}
		f.Since = t
	}
	if until := q.Get("until"); until != "" {
		t, err := parseWhenWebStr(until)
		if err != nil {
			writeError(w, http.StatusBadRequest, "until: "+err.Error())
			return
		}
		f.Until = t
	}
	if succ := q.Get("success"); succ != "" {
		switch strings.ToLower(succ) {
		case "true", "1", "yes":
			b := true
			f.Success = &b
		case "false", "0", "no":
			b := false
			f.Success = &b
		default:
			writeError(w, http.StatusBadRequest, fmt.Sprintf("success=%s: want true|false", succ))
			return
		}
	}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("limit=%s: want non-negative int", raw))
			return
		}
		if n > audit.MaxQueryLimit {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("limit=%d exceeds max %d", n, audit.MaxQueryLimit))
			return
		}
		f.Limit = n
	}
	if raw := q.Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("offset=%s: want non-negative int", raw))
			return
		}
		f.Offset = n
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && f.Since.After(f.Until) {
		writeError(w, http.StatusBadRequest, "since is after until — swap the values")
		return
	}
	entries, err := s.auditLog.QueryFiltered(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit find: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"entries": auditEntriesToDTO(entries),
	})
}

// handleAuditSession returns every entry for the given session id.
// Mirrors `/audit session <id>`.
func (s *Server) handleAuditSession(w http.ResponseWriter, r *http.Request) {
	if s.auditLog == nil {
		writeError(w, http.StatusServiceUnavailable, "audit log not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}
	entries, err := s.auditLog.QueryBySession(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit session: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"session_id": id,
		"entries":    auditEntriesToDTO(entries),
	})
}

// handleAuditTop runs the top-tools or top-risks aggregation.
// ?on=tools|risks (default tools) ?since=24h (optional). Mirrors
// `/audit top tools|risks [since=24h]`.
func (s *Server) handleAuditTop(w http.ResponseWriter, r *http.Request) {
	if s.auditLog == nil {
		writeError(w, http.StatusServiceUnavailable, "audit log not configured")
		return
	}
	q := r.URL.Query()
	on := strings.ToLower(q.Get("on"))
	if on == "" {
		on = "tools"
	}
	var since time.Time
	if raw := q.Get("since"); raw != "" {
		t, err := parseWhenWebStr(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since: "+err.Error())
			return
		}
		since = t
	}
	switch on {
	case "tools":
		rows, err := s.auditLog.TopTools(since, 10)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "top tools: "+err.Error())
			return
		}
		out := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			out = append(out, map[string]any{"tool": r.Tool, "count": r.Count})
		}
		respondJSON(w, http.StatusOK, map[string]any{"on": "tools", "rows": out})
	case "risks":
		rows, err := s.auditLog.TopRisks(since)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "top risks: "+err.Error())
			return
		}
		out := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			out = append(out, map[string]any{"risk": r.Risk, "count": r.Count})
		}
		respondJSON(w, http.StatusOK, map[string]any{"on": "risks", "rows": out})
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("on=%s: want tools|risks", on))
	}
}

// handleAuditExport returns the current session's full audit log as
// JSON. Mirrors `/audit export <path>` minus the file-write — web
// clients can save the response body themselves.
func (s *Server) handleAuditExport(w http.ResponseWriter, _ *http.Request) {
	if s.auditLog == nil {
		writeError(w, http.StatusServiceUnavailable, "audit log not configured")
		return
	}
	data, err := s.auditLog.Export()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit export: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(data))
}

// handleModeGet returns the active operation mode plus the catalogue
// of alternatives — same surface as the CLI's `/mode` (no-args)
// listing. Pre-v0.98 web operators couldn't see or change the mode
// at runtime; they had to relaunch with --mode <name>.
func (s *Server) handleModeGet(w http.ResponseWriter, _ *http.Request) {
	if s.agent == nil {
		writeError(w, http.StatusServiceUnavailable, "agent not configured")
		return
	}
	current := s.agent.Mode()
	all := mode.All()
	available := make([]map[string]any, 0, len(all))
	for _, m := range all {
		available = append(available, map[string]any{
			"name":             string(m),
			"display":          m.DisplayName(),
			"description":      m.Description(),
			"read_restrictive": m.IsReadRestrictive(),
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"active":             string(current),
		"active_display":     current.DisplayName(),
		"active_description": current.Description(),
		"read_only":          s.agent.ReadOnly(),
		"available":          available,
	})
}

// handleModeSet switches the active mode. Body: {"name": "recon"}.
// Read-restrictive modes (recon/intel/stealth) also engage the
// ReadOnly safety rail — mirrors handleMode's runtime behaviour
// (v0.80 fix) and setupMode's startup behaviour. Echoes the
// resulting state via handleModeGet so the cockpit header updates
// in a single round-trip.
func (s *Server) handleModeSet(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil {
		writeError(w, http.StatusServiceUnavailable, "agent not configured")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	target, err := mode.ParseMode(body.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.agent.SetMode(target)
	if target.IsReadRestrictive() {
		s.agent.SetReadOnly(true)
	}
	s.handleModeGet(w, r)
}

// handleBudgetGet returns the current session budget cap, spent, and
// remaining. Mirrors the CLI's `/budget` (no-args) summary. Returns
// `{"disabled": true}` when no cap is configured so the frontend can
// render the same "set one with PUT" hint the CLI prints.
func (s *Server) handleBudgetGet(w http.ResponseWriter, _ *http.Request) {
	if s.costs == nil {
		writeError(w, http.StatusServiceUnavailable, "cost tracker not configured")
		return
	}
	snap := s.costs.Snapshot()
	if snap.BudgetUSD <= 0 {
		respondJSON(w, http.StatusOK, map[string]any{
			"disabled":  true,
			"spent_usd": round4(snap.TotalUSD),
		})
		return
	}
	spent := snap.TotalUSD
	remaining := snap.BudgetUSD - spent
	if remaining < 0 {
		remaining = 0
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"disabled":      false,
		"cap_usd":       round4(snap.BudgetUSD),
		"spent_usd":     round4(spent),
		"remaining_usd": round4(remaining),
		"percent":       round4((spent / snap.BudgetUSD) * 100),
	})
}

// handleBudgetPut sets the session budget cap. Body: {"usd": 10.5}.
// usd=0 disables the cap (matches the CLI's `/budget off`). Negative
// values are rejected with 400 to mirror handleBudget's rejection of
// negative inputs.
//
// Callbacks (80% warn, 100% hit, agent pre-flight refuse) are wired by
// setupBudget at startup regardless of the initial cap (v0.81 fix), so
// updating via this endpoint reuses those callbacks — no need to re-
// install them on every PUT.
func (s *Server) handleBudgetPut(w http.ResponseWriter, r *http.Request) {
	if s.costs == nil {
		writeError(w, http.StatusServiceUnavailable, "cost tracker not configured")
		return
	}
	var body struct {
		USD float64 `json:"usd"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.USD < 0 {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("usd=%.2f is negative; pass 0 to disable", body.USD))
		return
	}
	s.costs.UpdateBudgetCap(body.USD)
	// Echo the resulting state in the same shape as handleBudgetGet so
	// the frontend doesn't need a second round-trip to reflect the
	// change in the header pill.
	s.handleBudgetGet(w, r)
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
	now := time.Now()
	out := make([]ruleDTO, 0, len(snaps))
	for _, snap := range snaps {
		var remaining int64
		if snap.Cooldown > 0 && !snap.LastFire.IsZero() {
			elapsed := now.Sub(snap.LastFire)
			if elapsed < snap.Cooldown {
				remaining = (snap.Cooldown - elapsed).Milliseconds()
			}
		}
		out = append(out, ruleDTO{
			Name:                snap.Name,
			Description:         snap.Description,
			Enabled:             snap.Enabled,
			FireCount:           snap.Fires,
			LastFired:           snap.LastFire,
			CooldownRemainingMS: remaining,
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
	if !decodeJSONBody(w, r, &body) {
		return
	}
	name := body.Path
	src := body.Content
	if src == "" {
		if body.Path == "" {
			writeError(w, http.StatusBadRequest, "expected 'path' or 'content'")
			return
		}
		resolved, err := s.resolveValidatePath(body.Path)
		if err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		data, err := os.ReadFile(resolved)
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

// resolveValidatePath refuses any /api/validate path read that isn't rooted
// under the configured safe base. Missing base → reject everything; that is
// the explicit "no filesystem reads" default callers opt out of with
// SetValidateBase.
//
// The check resolves the symlink chain on *both* the base and the candidate
// path: Clean-alone is not enough because `<base>/foo` could be a symlink to
// /etc/shadow and still pass a prefix-on-Clean test. EvalSymlinks forces the
// real filesystem location into the comparison.
func (s *Server) resolveValidatePath(p string) (string, error) {
	if s.validateBase == "" {
		return "", fmt.Errorf("path reads disabled: server has no validate base configured (send the script body in 'content' instead)")
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("invalid path %q: %w", p, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// File doesn't exist / permission error — surface as 403 rather
		// than leaking whether the path exists outside the safe base.
		return "", fmt.Errorf("path %q is outside the allowed base", p)
	}
	// filepath.Rel catches the prefix case AND the "../escape" case in one
	// comparison: a rel path that starts with ".." means we climbed out.
	rel, err := filepath.Rel(s.validateBase, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside the allowed base", p)
	}
	return resolved, nil
}

// ---------------------------------------------------------------------------
// Debug snapshot
// ---------------------------------------------------------------------------

func (s *Server) handleDebug(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	personaName := ""
	if p := s.agent.PersonaSnapshot(); p != nil {
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
			"mirror_active":      s.mirrorActive.Load(),
		},
	})
}

func bytesToMB(b uint64) uint64 {
	return b / (1024 * 1024)
}

// ---------------------------------------------------------------------------
// Device profile — full device_info + power_info surface
// ---------------------------------------------------------------------------

// handleDevice surfaces the Momentum-level device profile the Flipper mobile
// app shows on connect: firmware identity, hardware revision, radio stack,
// battery health, and storage usage. All fields are pulled from
// `device_info` + `power_info` and returned as both a structured JSON with
// grouped sections AND the raw key→value map so the UI can render fields
// we haven't explicitly modelled yet.
const deviceCacheTTL = 5 * time.Second

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "flipper not connected")
		return
	}
	if s.refuseIfMirrorActive(w) {
		return
	}

	// Serialize concurrent fetches so multiple tabs polling at the same time
	// do not stack serial commands — only one fetch runs per TTL window.
	s.deviceCacheMu.Lock()
	defer s.deviceCacheMu.Unlock()

	if time.Since(s.deviceCacheAt) < deviceCacheTTL && s.deviceCacheResp != nil {
		respondJSON(w, http.StatusOK, s.deviceCacheResp)
		return
	}

	devInfo, err := s.flipper.DeviceInfoMap()
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("device_info: %v", err))
		return
	}
	// power_info may duplicate fields already present in device_info on
	// Momentum firmware; that's fine — the final raw map just overlays.
	// Errors are non-fatal but surfaced in the response so the UI can
	// distinguish "command failed" from "command ran but returned no
	// battery fields".
	var powerInfoErrors []string
	powerInfo, perr := s.flipper.PowerInfoMap()
	if perr != nil {
		powerInfoErrors = []string{perr.Error()}
	} else {
		for k, v := range powerInfo {
			if _, ok := devInfo[k]; !ok {
				devInfo[k] = v
			}
		}
	}

	// device_info doesn't carry storage fields on any fork — the canonical
	// source is `storage info /ext` and `storage info /int`. Errors are
	// non-fatal: missing keys render as em-dash in the UI.
	var storageErrors []string
	if sd, err := s.flipper.StorageFSInfoMap("/ext"); err == nil {
		for k, v := range sd {
			devInfo["storage_sdcard_"+k] = v
		}
	} else {
		storageErrors = append(storageErrors, "/ext: "+err.Error())
	}
	if intFS, err := s.flipper.StorageFSInfoMap("/int"); err == nil {
		for k, v := range intFS {
			devInfo["storage_internal_"+k] = v
		}
	} else {
		storageErrors = append(storageErrors, "/int: "+err.Error())
	}

	// Group into logical sections the UI can render as panels. Every key
	// that maps into a section is still also present in `raw` so the
	// frontend can sanity-check or render the full dump in a debug view.
	firmware := pickFields(devInfo, []string{
		"firmware_origin_fork", "firmware_version", "firmware_branch",
		"firmware_commit", "firmware_commit_dirty", "firmware_build_date",
		"firmware_target", "firmware_api_major", "firmware_api_minor",
		"firmware_origin_git",
	})
	hardware := pickFields(devInfo, []string{
		"hardware_model", "hardware_name", "hardware_uid",
		"hardware_ver", "hardware_region", "hardware_region_provisioned",
		"hardware_target", "hardware_body", "hardware_connect",
		"hardware_display", "hardware_color", "hardware_otp_ver",
		"hardware_timestamp",
	})
	radio := pickFields(devInfo, []string{
		"radio_alive", "radio_mode",
		"radio_stack_major", "radio_stack_minor", "radio_stack_sub",
		"radio_stack_release", "radio_stack_branch", "radio_stack_type",
		"radio_stack_flash", "radio_stack_sram1", "radio_stack_sram2a", "radio_stack_sram2b",
		"radio_fus_major", "radio_fus_minor", "radio_fus_sub",
		"radio_fus_flash", "radio_fus_sram2a", "radio_fus_sram2b",
		"radio_ble_mac",
	})
	battery := pickFields(devInfo, []string{
		"charge_level", "charge_state", "charge_voltage_limit",
		"battery_voltage", "battery_current", "battery_temp", "battery_health",
		// Flipper firmware emits `capacity.remain` (normalised to
		// capacity_remain) — verified against Momentum's
		// furi_hal_power_info_get. `capacity_remaining` is never emitted.
		"capacity_remain", "capacity_full", "capacity_design",
		"gauge_is_ok",
	})
	storage := pickFields(devInfo, []string{
		"storage_sdcard_present", "storage_sdcard_label", "storage_sdcard_type",
		"storage_sdcard_totalSpace", "storage_sdcard_freeSpace", "storage_sdcard_error",
		"storage_internal_present", "storage_internal_label", "storage_internal_type",
		"storage_internal_totalSpace", "storage_internal_freeSpace",
	})
	system := pickFields(devInfo, []string{
		"protobuf_version_major", "protobuf_version_minor",
		"enclave_valid", "enclave_valid_keys",
		"system_debug", "system_lock", "system_log_level",
	})

	// batteryAny mirrors the existing battery map (string-typed Flipper
	// CLI fields) AND adds a numeric `percent` (0–100) for the status
	// bar's battery pill. Existing consumers reading `battery.charge_level`
	// keep working — only new keys are added on top.
	batteryAny := make(map[string]any, len(battery)+1)
	for k, v := range battery {
		batteryAny[k] = v
	}
	batteryAny["percent"] = parseBatteryPercent(devInfo)

	// New flat status-bar sections. None of these collide with the
	// existing `battery` / `storage` / `firmware` / `hardware` / `radio`
	// / `system` / `raw` / `*_errors` keys above, so existing consumers
	// of /api/device are unaffected.
	flipperSection := s.flipperStatusSection(devInfo)
	marauderSection := s.marauderStatusSection()
	bleSection := s.bleStatusSection()
	sdSection := parseSDSection(devInfo)

	resp := map[string]any{
		"firmware": firmware,
		"hardware": hardware,
		"radio":    radio,
		"battery":  batteryAny,
		"storage":  storage,
		"system":   system,
		"raw":      devInfo,
		"flipper":  flipperSection,
		"marauder": marauderSection,
		"ble":      bleSection,
		"sd":       sdSection,
	}
	if report := s.flipper.ConnectionReport(); report != nil {
		resp["connection_report"] = report.ToJSON()
	}
	if len(powerInfoErrors) > 0 {
		resp["power_info_errors"] = powerInfoErrors
	}
	if len(storageErrors) > 0 {
		resp["storage_info_errors"] = storageErrors
	}

	// Bridge state — surfaces the SetBridgeMode() flag so the cockpit
	// can render the "via Flipper bridge" Marauder subtitle and the
	// suspended Flipper pill. Closes the SPEC.md §6.3 / api.go TODO
	// from earlier; server-side state was already tracked, only the
	// JSON wiring was missing.
	bridge := map[string]any{
		"active": s.bridgeOn.Load(),
	}
	if r := s.bridgeReason.Load(); r != nil {
		bridge["reason"] = *r
	}
	resp["bridge"] = bridge

	s.deviceCacheAt = time.Now()
	s.deviceCacheResp = resp

	respondJSON(w, http.StatusOK, resp)
}

// pickFields returns a submap containing only the requested keys that
// exist in src. Missing keys are skipped — the UI handles absent fields
// by rendering em-dash placeholders. Order is preserved by the slice.
func pickFields(src map[string]string, keys []string) map[string]string {
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if v, ok := src[k]; ok {
			out[k] = v
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Status-bar sections
//
// The redesigned web UI's status bar binds to a small number of fixed,
// strongly-typed fields: `flipper.{connected,firmware,port}`,
// `marauder.{connected,firmware,port}`, `ble.state`,
// `battery.percent`, `sd.{free_bytes,total_bytes}`. The existing
// `firmware` / `hardware` / `battery` / `storage` maps stay as-is for
// the panel renderers that already consume them — these new fields sit
// alongside.
// ---------------------------------------------------------------------------

// deviceFlipperStatus is the status-bar Flipper pill payload. `port` is
// the transport identity ("/dev/ttyACM0" for serial, "ble://AA:BB:..."
// for BLE) — the UI renders it as-is.
type deviceFlipperStatus struct {
	Connected bool   `json:"connected"`
	Firmware  string `json:"firmware"`
	Port      string `json:"port"`
}

// deviceMarauderStatus is the status-bar Marauder pill payload. `port`
// and `firmware` are populated from setup-time info recorded via
// SetMarauderInfo; both are empty when no Marauder was wired (matches
// "don't fabricate values when hardware isn't present").
type deviceMarauderStatus struct {
	Connected bool   `json:"connected"`
	Firmware  string `json:"firmware"`
	Port      string `json:"port"`
}

// deviceBLEStatus reflects the Flipper-link BLE state — i.e., whether
// PromptZero is talking to the Flipper over a BLE transport. There is
// deliberately no probe of the OS-level Bluetooth adapter: that would
// require platform-specific privileged access (BlueZ / CoreBluetooth)
// that the project does not depend on. Status values:
//
//	"on"  — flipper transport kind == "ble"
//	"off" — flipper transport kind != "ble" (typically serial USB)
//	"err" — reserved for future use; never emitted today
type deviceBLEStatus struct {
	State string `json:"state"`
}

// deviceSDStatus is the status-bar SD-card pill payload. Bytes are
// uint64 (parsed from the existing `storage_sdcard_freeSpace`/
// `storage_sdcard_totalSpace` strings — both decimal byte counts).
// Zero values surface as "—" in the UI rather than "0 B free".
type deviceSDStatus struct {
	Present    bool   `json:"present"`
	FreeBytes  uint64 `json:"free_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
}

// flipperStatusSection builds the typed Flipper status pill. `connected`
// uses the same atomic the /api/debug snapshot reads, so the UI sees a
// consistent connectivity story across endpoints. `port` is sourced from
// the live transport's Identity() — empty when the transport isn't yet
// dialled (a transient state during reconnect).
func (s *Server) flipperStatusSection(devInfo map[string]string) deviceFlipperStatus {
	out := deviceFlipperStatus{
		Connected: s.flipperOn.Load(),
		Firmware:  devInfo["firmware_version"],
	}
	if s.flipper != nil {
		if tx := s.flipper.Transport(); tx != nil {
			out.Port = tx.Identity()
		}
	}
	return out
}

// marauderStatusSection builds the typed Marauder status pill from the
// values setup.go records via SetMarauderInfo. When no Marauder was
// wired the section is `{connected:false, firmware:"", port:""}` — the
// status-bar interprets empty strings as "unknown" and renders an em-dash.
func (s *Server) marauderStatusSection() deviceMarauderStatus {
	s.marauderInfoMu.Lock()
	port := s.marauderPort
	fw := s.marauderFirmware
	s.marauderInfoMu.Unlock()
	return deviceMarauderStatus{
		Connected: s.marauderOn.Load(),
		Firmware:  fw,
		Port:      port,
	}
}

// bleStatusSection derives the BLE state from the Flipper transport's
// Kind() telemetry tag. See deviceBLEStatus for the semantics rationale.
func (s *Server) bleStatusSection() deviceBLEStatus {
	state := "off"
	if s.flipper != nil {
		if tx := s.flipper.Transport(); tx != nil && tx.Kind() == "ble" {
			state = "on"
		}
	}
	return deviceBLEStatus{State: state}
}

// parseBatteryPercent extracts a 0–100 integer from devInfo's
// `charge_level` field (emitted by Flipper's power_info as the bare
// percentage, e.g. "91"). Returns 0 when the field is absent or
// unparseable — the status bar renders 0 as "—" rather than misleading
// the operator.
func parseBatteryPercent(devInfo map[string]string) int {
	v, ok := devInfo["charge_level"]
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 || n > 100 {
		return 0
	}
	return n
}

// parseSDSection turns the Flipper's SD `storage_sdcard_*` string fields
// into the typed SD pill. `present` follows the device's "true"/"false"
// string convention; byte counts are decoded from the decimal strings
// produced by parseKiBLine (see flipper.StorageFSInfoMap).
func parseSDSection(devInfo map[string]string) deviceSDStatus {
	out := deviceSDStatus{
		Present: devInfo["storage_sdcard_present"] == "true",
	}
	if v, ok := devInfo["storage_sdcard_freeSpace"]; ok {
		if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
			out.FreeBytes = n
		}
	}
	if v, ok := devInfo["storage_sdcard_totalSpace"]; ok {
		if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
			out.TotalBytes = n
		}
	}
	return out
}
