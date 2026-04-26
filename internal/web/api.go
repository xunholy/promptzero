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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/cost"
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

	mux.HandleFunc("GET /api/watch", s.requireAuth(s.handleWatch))
	mux.HandleFunc("POST /api/watch/pause", s.requireAuth(s.handleWatchPause))
	mux.HandleFunc("POST /api/watch/resume", s.requireAuth(s.handleWatchResume))

	mux.HandleFunc("GET /api/cost", s.requireAuth(s.handleCost))

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
}

// handleAuthInfo reports whether the server requires a bearer token.
// Always unauthenticated — it carries no tool metadata, just a bool the
// frontend needs to decide whether to show a token-entry prompt.
func (s *Server) handleAuthInfo(w http.ResponseWriter, _ *http.Request) {
	respondJSON(w, http.StatusOK, map[string]bool{"required": s.token != ""})
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
		return "", fmt.Errorf("invalid path %q: %v", p, err)
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
	if len(powerInfoErrors) > 0 {
		resp["power_info_errors"] = powerInfoErrors
	}
	if len(storageErrors) > 0 {
		resp["storage_info_errors"] = storageErrors
	}

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
