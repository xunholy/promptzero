// Package web serves the PromptZero browser UI and bridges the agent's
// streaming callbacks onto a WebSocket.
//
// # Event model
//
// The agent exposes three hooks — SetTextDeltaCallback, SetToolStatusCallback,
// SetConfirmCallback — that fire from the goroutine running agent.Run. The
// Server registers one adapter per hook and routes each event to the
// connections through per-conn writer goroutines. Callbacks must not touch
// the WebSocket directly: concurrent writes are undefined.
//
// Session isolation is by single-writer mutex. The agent has one slot per
// callback and its own internal lock, so it cannot genuinely host parallel
// sessions. Server.driverMu serialises Run invocations; the first connection
// to send a `text` drives the turn, others block until it finishes. Events
// are broadcast to every open connection tagged with `turn_id` (plus the
// owner's `session_id` on the initial status frame) so peer tabs stay in sync
// without fighting for control. `confirm_request` is the single exception —
// it is delivered only to the turn owner.
//
// Liveness uses WebSocket protocol-level ping/pong (ws.Ping), which the
// browser answers below the JS event loop — a backgrounded tab whose
// timers are throttled still responds. The JSON taxonomy below is strictly
// application payload; there are no `ping`/`pong` JSON frames.
//
// Outbound taxonomy: status, response, transcription, error (legacy),
// text_delta, tool_status, confirm_request, phase.
// Inbound taxonomy: text, audio, reset (legacy), confirm_response, cancel.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/voice"
	"github.com/xunholy/promptzero/internal/watch"
)

//go:embed static
var staticFiles embed.FS

// agentDriver is the narrow surface Server needs from *agent.Agent. Declared
// as an interface so tests can inject a fake without an anthropic client.
// *agent.Agent satisfies it by virtue of the existing method set.
type agentDriver interface {
	Run(ctx context.Context, input string) (string, error)
	Reset()
	SetTextDeltaCallback(f func(agent.TextDelta))
	SetToolStatusCallback(f func(agent.ToolEvent))
	SetConfirmCallback(f agent.ConfirmFunc)
	SetPersona(p *persona.Persona)
	Persona() *persona.Persona
	PersonaSnapshot() *persona.Persona
}

// outboundQueue bounds how many pending events a slow consumer may buffer.
// When full, enqueue drops rather than blocking the agent goroutine.
const outboundQueue = 64

type Server struct {
	agent agentDriver
	voice *voice.Engine
	addr  string

	// metrics, when non-nil, drives the /metrics Prom scrape route.
	// metricsPath is the mount path; defaults to "/metrics" when empty.
	metrics     *obs.Recorder
	metricsPath string

	// Timing knobs. Initialised by NewServer; tests override these fields on
	// the struct (not package-level vars) to stay race-safe across tests.
	//
	// heartbeatInterval: how often runHeartbeat issues a ws.Ping.
	// heartbeatTimeout:  deadline for a single Ping to receive its Pong.
	// writeTimeout:      deadline for a single outbound data frame.
	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration
	writeTimeout      time.Duration

	// driverMu serialises agent.Run invocations. The agent has a single lock
	// and a single callback slot per hook, so it cannot host parallel turns.
	// Holding driverMu across currentTurn assignment + Run makes callback
	// routing race-free.
	driverMu sync.Mutex

	mu          sync.Mutex
	conns       map[*sessionConn]struct{}
	currentTurn *turnState
	confirms    map[string]chan agent.ConfirmResponse

	// requestQueue bounds the number of concurrent agent-driving goroutines
	// across all connections. Since driverMu already serialises Run, this
	// primarily prevents a single malicious client from flooding the
	// handleText/handleAudio paths with a massive number of pending goroutines.
	requestQueue chan struct{}

	// Optional data sources for the REPL-parity panels. Nil when the host
	// process has not wired a given subsystem — handlers return 503 with a
	// short reason so the UI can hide or grey out the affected panel.
	personas    *persona.Registry
	watcher     *watch.Watcher
	costs       *cost.Tracker
	rulesEngine *rules.Engine
	flipper     *flipper.Flipper

	// startedAt records the time NewServer returned; /api/debug computes
	// uptime against it rather than os.StartTime so the number matches the
	// connection lifecycle the operator sees in the cockpit.
	startedAt time.Time

	// deviceCacheMu guards deviceCacheResp and deviceCacheAt. Held during
	// the flipper fetch so concurrent tab polls serialize rather than
	// stacking serial commands.
	deviceCacheMu   sync.Mutex
	deviceCacheAt   time.Time
	deviceCacheResp map[string]any

	// Device state surfaced in /api/debug. Updated by the host via
	// SetFlipperConnected / SetMarauderConnected on transport events.
	flipperOn  atomic.Bool
	marauderOn atomic.Bool

	// marauderInfo* fields back the status-bar Marauder pill. Both are
	// optional metadata captured at setup time via SetMarauderInfo; the
	// server itself never queries the Marauder directly because the only
	// firmware probe ("info") blocks the serial port for ~hundreds of ms.
	// Guarded by marauderInfoMu so the host can refresh either field on
	// reconnect without racing /api/device readers.
	marauderInfoMu   sync.Mutex
	marauderPort     string
	marauderFirmware string

	// token, when non-empty, is the shared bearer the server requires on
	// every /api and /ws request. Empty means auth disabled (dev mode);
	// the server prints a loud warning when the bind is also non-loopback.
	// Compared with subtle.ConstantTimeCompare to avoid timing side channels.
	token string
	// validateBase is the absolute, symlink-resolved directory the
	// /api/validate POST is allowed to read files under. Empty disables
	// filesystem reads for that endpoint — handleValidate refuses any path
	// request with a 403 rather than letting os.ReadFile wander into
	// /etc/shadow, ~/.ssh/id_rsa, or a /proc self-access leak.
	validateBase string
	// corsOrigins is the allow-list for the WebSocket Origin header. Empty
	// means same-origin only (the coder/websocket default). A literal "*"
	// is refused at Start() unless allowAnyOrigin is also set — a silent
	// wildcard would re-open every cross-origin tab to the agent bridge.
	corsOrigins []string
	// allowAnyOrigin opts in to a wildcard Origin match and is only
	// honoured when corsOrigins does NOT contain a literal "*". Operators
	// have to set the flag deliberately AND keep their allow-list free of
	// the footgun token; that makes the intent auditable from config.
	allowAnyOrigin bool
	// allowUnauthedPublic, when true, falls back to warn-and-continue when the
	// server is bound non-loopback without a token. Default false = fail-closed.
	allowUnauthedPublic bool

	// auditLog, when non-nil, records destructive FS and input-send operations.
	// Set via SetAuditLog. Nil means skip silently.
	auditLog *audit.Log

	// maxUploadBytes caps /api/fs/upload. Default 1 MiB.
	maxUploadBytes int64

	// latestUIContext carries the most recent ui_context frame from the browser.
	latestUIContext atomic.Pointer[uiContext]

	// onUIContext, when set, is called whenever a ui_context WebSocket frame
	// arrives. setup.go wires this to the agent.
	onUIContext func(view, path string)
}

type sessionConn struct {
	id  string
	ws  *websocket.Conn
	out chan []byte
}

// uiContext records the latest navigation state the browser reported.
type uiContext struct {
	View string
	Path string
}

type turnState struct {
	id        string
	owner     *sessionConn
	cancel    context.CancelFunc
	lastPhase string // dedupes repeated phase transitions
}

// wsInbound is the union of fields any client→server message may carry.
// Decoded once; each case reads only its own fields.
type wsInbound struct {
	Type      string `json:"type"`
	Content   string `json:"content,omitempty"`
	TurnID    string `json:"turn_id,omitempty"`
	ConfirmID string `json:"confirm_id,omitempty"`
	Decision  string `json:"decision,omitempty"`
	// Revision carries the operator's revision text when
	// Decision == "revise" (see agent.DecisionRevise). Empty for
	// every other decision kind.
	Revision string `json:"revision,omitempty"`
	T        string `json:"t,omitempty"`
	// View and Path carry the current UI view and path in ui_context frames.
	View   string `json:"view,omitempty"`
	FSPath string `json:"path,omitempty"`
}

// NewServer creates a web server bound to addr. If the host portion of addr
// is empty (":PORT") or the legacy hardcoded "0.0.0.0", the server defaults
// the bind to "127.0.0.1" and prints a one-line note to stderr explaining
// how to override via config.Web.Host. If the effective host is non-loopback,
// NewServer additionally prints a yellow warning on stderr: the web UI has
// no authentication, so a public bind must be explicit and visible.
func NewServer(addr string, ag agentDriver, v *voice.Engine) *Server {
	addr = applyLoopbackDefault(addr)
	s := &Server{
		agent:             ag,
		voice:             v,
		addr:              addr,
		conns:             make(map[*sessionConn]struct{}),
		confirms:          make(map[string]chan agent.ConfirmResponse),
		heartbeatInterval: 30 * time.Second,
		heartbeatTimeout:  60 * time.Second,
		writeTimeout:      30 * time.Second,
		requestQueue:      make(chan struct{}, 64),
		startedAt:         time.Now(),
	}
	s.attachAgentCallbacks()
	return s
}

// SetMetrics wires a Prometheus Recorder onto the server. When non-nil
// the server mounts the scrape handler at path (or "/metrics" when path
// is empty). Must be called before Start.
func (s *Server) SetMetrics(rec *obs.Recorder, path string) {
	s.metrics = rec
	s.metricsPath = path
}

// SetPersonaRegistry wires the persona catalogue into the server so
// /api/personas can list choices and /api/personas/switch can apply one.
// Safe to pass nil — the endpoints return 503 until a registry is set.
func (s *Server) SetPersonaRegistry(r *persona.Registry) { s.personas = r }

// SetWatcher wires the filesystem watcher into the server so /api/watch
// can surface its configured rules, recent events, and paused state.
func (s *Server) SetWatcher(w *watch.Watcher) { s.watcher = w }

// SetCostTracker wires the session cost tracker into the server so the
// header cost pill and /api/cost handler can render live totals.
func (s *Server) SetCostTracker(t *cost.Tracker) { s.costs = t }

// SetRulesEngine wires the reactive-rules engine into the server so
// /api/rules can list, pause, resume, and test rule fires.
func (s *Server) SetRulesEngine(e *rules.Engine) { s.rulesEngine = e }

// SetFlipperConnected records the current Flipper serial state for the
// /api/debug snapshot. Call on connect/disconnect transitions.
func (s *Server) SetFlipperConnected(v bool) { s.flipperOn.Store(v) }

// SetFlipper wires the live *flipper.Flipper into the server so
// /api/device can run device_info + power_info and surface the full
// Momentum-level profile to the web UI. Safe to pass nil — /api/device
// returns 503 until this is set.
func (s *Server) SetFlipper(f *flipper.Flipper) { s.flipper = f }

// SetAuditLog wires the audit log so destructive FS and input-send operations
// are recorded. Safe to pass nil — operations are skipped silently without one.
func (s *Server) SetAuditLog(l *audit.Log) { s.auditLog = l }

// SetMaxUploadBytes sets the upload size cap for /api/fs/upload.
// Default is 1 MiB. Must be called before Start.
func (s *Server) SetMaxUploadBytes(n int64) { s.maxUploadBytes = n }

// SetUIContext records the latest UI navigation state forwarded from the browser.
func (s *Server) SetUIContext(view, path string) {
	s.latestUIContext.Store(&uiContext{View: view, Path: path})
}

// UIContext returns the latest view+path the browser reported, or empty strings
// when no ui_context frame has arrived yet.
func (s *Server) UIContext() (view, path string) {
	if v := s.latestUIContext.Load(); v != nil {
		return v.View, v.Path
	}
	return "", ""
}

// OnUIContext installs a callback invoked whenever a ui_context WebSocket frame
// arrives. Use this to forward the navigation state to the agent.
func (s *Server) OnUIContext(fn func(view, path string)) { s.onUIContext = fn }

// setUIContextFromWS is called from the WebSocket read loop on ui_context
// frames. View is allowlisted so a hostile client cannot inject XML attributes
// into the agent prompt via buildUIContextBlock.
func (s *Server) setUIContextFromWS(view, path string) {
	switch view {
	case "", "agent", "files", "preview":
	default:
		return
	}
	if len(path) > 240 || strings.ContainsRune(path, 0) {
		return
	}
	s.SetUIContext(view, path)
	if s.onUIContext != nil {
		s.onUIContext(view, path)
	}
}

// SetMarauderConnected records the current Marauder serial state for the
// /api/debug snapshot. Call on connect/disconnect transitions.
func (s *Server) SetMarauderConnected(v bool) { s.marauderOn.Store(v) }

// SetMarauderInfo records the Marauder serial port name (e.g.
// "/dev/ttyACM1") and firmware version string for the /api/device
// status-bar pill. Either argument may be empty when the host doesn't
// know that field — the status bar renders empty strings as "—".
//
// Decoupled from SetMarauderConnected because the connect/disconnect
// callback fires on every transport event; the descriptive metadata is
// only known once at setup time (port from config, firmware from a
// one-shot "info" probe the host may add later).
func (s *Server) SetMarauderInfo(port, firmware string) {
	s.marauderInfoMu.Lock()
	defer s.marauderInfoMu.Unlock()
	s.marauderPort = port
	s.marauderFirmware = firmware
}

// SetAuthToken installs the shared bearer token for /api and /ws. Empty
// disables the check (dev-mode default). Must be called before Start —
// changing the token at runtime would leave open connections with stale
// credentials.
func (s *Server) SetAuthToken(t string) { s.token = t }

// SetValidateBase restricts /api/validate path reads to paths rooted under
// dir. The value is normalised to its symlink-resolved absolute form; an
// empty string (the default) disables path-based reads entirely so the
// endpoint 403s any request that isn't an inline `content` payload.
//
// Must be called before Start. Callers wanting the "no filesystem reads"
// default simply never call this.
func (s *Server) SetValidateBase(dir string) {
	if dir == "" {
		s.validateBase = ""
		return
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		s.validateBase = ""
		return
	}
	// EvalSymlinks matches the check handleValidate runs on the incoming
	// path; normalising both sides up front turns a symlink base (e.g.
	// /tmp -> /private/tmp on macOS) into a prefix that actually compares.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	s.validateBase = abs
}

// SetCORSOrigins sets the WebSocket Origin allow-list. Empty = same-origin
// only. Must be called before Start. A literal "*" entry is refused at Start
// (callers that really want wildcard semantics must drop "*" and set
// SetAllowAnyOrigin(true) instead).
func (s *Server) SetCORSOrigins(origins []string) { s.corsOrigins = origins }

// SetAllowAnyOrigin opts in to wildcard Origin matching for cross-origin
// WebSocket connections. Pairs with SetCORSOrigins: the allow-list must NOT
// contain "*" while this flag is set — the combination exists only so the
// operator has to remove the footgun token from config as part of enabling
// it. Must be called before Start.
func (s *Server) SetAllowAnyOrigin(v bool) { s.allowAnyOrigin = v }

// SetAllowUnauthedPublic opts in to warn-and-continue when the server is bound
// non-loopback without an auth token. When false (default) Start returns an error
// in that configuration. Must be called before Start.
func (s *Server) SetAllowUnauthedPublic(v bool) { s.allowUnauthedPublic = v }

// Addr returns the effective host:port the server will bind to, after any
// loopback-default rewrite applied in NewServer. Use this for display so the
// "Web UI at ..." status line matches the actual socket.
func (s *Server) Addr() string { return s.addr }

// applyLoopbackDefault enforces the local-first bind default: an EMPTY host
// is rewritten to "127.0.0.1" (i.e., user did not set web.host). Explicit
// 0.0.0.0 / other non-loopback hosts are RESPECTED and warned about so the
// user knows the network exposure is intentional.
func applyLoopbackDefault(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" {
		effective := net.JoinHostPort("127.0.0.1", port)
		fmt.Fprintf(os.Stderr, "\x1b[33m●\x1b[0m Web UI defaulting to loopback (%s); set web.host in config to bind publicly\n", effective)
		return effective
	}
	if !isLoopback(host) {
		fmt.Fprintf(os.Stderr, "\x1b[33m●\x1b[0m Web UI bound to %s - accessible from the network without authentication (intended for local pentesting only)\n", net.JoinHostPort(host, port))
	}
	return addr
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (s *Server) Start(ctx context.Context) error {
	if err := s.validateOriginConfig(); err != nil {
		return err
	}
	mux := http.NewServeMux()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("static files: %w", err)
	}

	if s.metrics != nil {
		path := s.metricsPath
		if path == "" {
			path = "/metrics"
		}
		// Metrics can leak tool inventory + activity patterns, so it
		// follows the same auth posture as /api.
		mux.Handle(path, s.requireAuth(s.metrics.Handler().ServeHTTP))
	}
	s.registerAPIRoutes(mux)
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/ws", s.handleWebSocket)

	if s.token == "" && !isLoopback(hostOf(s.addr)) {
		if !s.allowUnauthedPublic {
			return fmt.Errorf("refusing to bind %s without an auth token; set web.token, bind to 127.0.0.1, or set web.allow_unauthed_public=true to override", s.addr)
		}
		fmt.Fprintf(os.Stderr, "\x1b[31m\u25cf\x1b[0m Web UI bound non-loopback with NO TOKEN set — every /api + /ws is open. Set web.token or PROMPTZERO_WEB_TOKEN.\n")
	}

	srv := &http.Server{Addr: s.addr, Handler: mux}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	obs.Default().Info("web_ui_ready", "url", "http://"+s.addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// attachAgentCallbacks is called once at construction. The callbacks capture
// s and look up the current turn each time they fire; they never close over a
// specific connection, so a turn handoff does not require re-registration.
func (s *Server) attachAgentCallbacks() {
	s.agent.SetTextDeltaCallback(func(d agent.TextDelta) {
		ts := s.turn()
		if ts == nil {
			return
		}
		s.emitPhaseIfChanged(ts, "Responding")
		s.broadcast(map[string]any{
			"type":    "text_delta",
			"content": d.Text,
			"turn_id": ts.id,
		})
	})

	s.agent.SetToolStatusCallback(func(e agent.ToolEvent) {
		ts := s.turn()
		if ts == nil {
			return
		}
		m := map[string]any{
			"type":    "tool_status",
			"phase":   e.Phase,
			"name":    e.Name,
			"input":   rawOrEmpty(e.Input),
			"turn_id": ts.id,
		}
		if e.Phase == "finish" {
			m["duration_ms"] = e.Duration.Milliseconds()
			m["output"] = e.Output
			m["err"] = e.Err
		}
		s.broadcast(m)
		if e.Phase == "start" {
			s.emitPhaseIfChanged(ts, "Running "+e.Name)
		} else {
			s.emitPhaseIfChanged(ts, "Thinking")
		}
	})

	s.agent.SetConfirmCallback(func(ctx context.Context, req agent.ConfirmRequest) agent.ConfirmResponse {
		ts := s.turn()
		if ts == nil || ts.owner == nil {
			return agent.ConfirmResponse{Decision: agent.DecisionDeny}
		}
		id := newID()
		ch := make(chan agent.ConfirmResponse, 1)
		s.mu.Lock()
		s.confirms[id] = ch
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			delete(s.confirms, id)
			s.mu.Unlock()
		}()
		s.sendTo(ts.owner, map[string]any{
			"type":       "confirm_request",
			"tool":       req.Tool,
			"input":      rawOrEmpty(req.Input),
			"risk":       req.Risk.String(),
			"confirm_id": id,
			"turn_id":    ts.id,
		})
		select {
		case r := <-ch:
			return r
		case <-ctx.Done():
			return agent.ConfirmResponse{Decision: agent.DecisionDeny}
		}
	})
}

func (s *Server) turn() *turnState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentTurn
}

func (s *Server) setTurn(ts *turnState) {
	s.mu.Lock()
	s.currentTurn = ts
	s.mu.Unlock()
}

func (s *Server) clearTurn(ts *turnState) {
	s.mu.Lock()
	if s.currentTurn == ts {
		s.currentTurn = nil
	}
	s.mu.Unlock()
}

func (s *Server) broadcast(m map[string]any) {
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	s.mu.Lock()
	conns := make([]*sessionConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		enqueue(c, data)
	}
}

func (s *Server) sendTo(c *sessionConn, m map[string]any) {
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	enqueue(c, data)
}

// enqueue offers data to the connection's writer. If the queue is full the
// event is dropped silently — we must never block the agent goroutine on a
// slow client. Writer goroutines drain until connCtx cancels.
func enqueue(c *sessionConn, data []byte) {
	select {
	case c.out <- data:
	default:
	}
}

func (s *Server) emitPhaseIfChanged(ts *turnState, verb string) {
	s.mu.Lock()
	if ts.lastPhase == verb {
		s.mu.Unlock()
		return
	}
	ts.lastPhase = verb
	s.mu.Unlock()
	s.broadcast(map[string]any{
		"type":    "phase",
		"verb":    verb,
		"turn_id": ts.id,
	})
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Auth: clients send `Sec-WebSocket-Protocol: bearer, <token>`; on a match
	// the server echoes `bearer` back, completing subprotocol negotiation.
	// Tokens must not travel in the URL query string (request logs / referrer).
	supplied, hasBearer := bearerFromWSProtocol(r.Header.Values("Sec-WebSocket-Protocol"))
	if !s.checkAuth(r, supplied) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	opts := &websocket.AcceptOptions{
		OriginPatterns: s.effectiveOriginPatterns(),
	}
	if hasBearer {
		opts.Subprotocols = []string{"bearer"}
	}
	ws, err := websocket.Accept(w, r, opts)
	if err != nil {
		obs.Default().Warn("websocket_accept_failed", "err", err, "remote", r.RemoteAddr)
		return
	}
	defer ws.CloseNow()

	ws.SetReadLimit(10 * 1024 * 1024)

	c := &sessionConn{
		id:  newID(),
		ws:  ws,
		out: make(chan []byte, outboundQueue),
	}

	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()

	connCtx, cancel := context.WithCancel(r.Context())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.runWriter(connCtx, c) }()
	go func() { defer wg.Done(); s.runHeartbeat(connCtx, c) }()

	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		wg.Wait()
	}()

	s.sendTo(c, map[string]any{
		"type":       "status",
		"content":    "connected",
		"session_id": c.id,
	})

	for {
		_, data, err := ws.Read(connCtx)
		if err != nil {
			return
		}

		var msg wsInbound
		if err := json.Unmarshal(data, &msg); err != nil {
			s.sendTo(c, map[string]any{"type": "error", "content": "invalid message format"})
			continue
		}

		switch msg.Type {
		case "text":
			go s.handleText(connCtx, c, msg.Content)
		case "audio":
			go s.handleAudio(connCtx, c, msg.Content)
		case "reset":
			go func() {
				s.agent.Reset()
				s.sendTo(c, map[string]any{"type": "status", "content": "conversation reset"})
			}()
		case "confirm_response":
			s.deliverConfirm(msg.ConfirmID, agent.ConfirmResponse{
				Decision: decodeDecision(msg.Decision),
				Revision: msg.Revision,
			})
		case "cancel":
			s.cancelTurn(c, msg.TurnID)
		case "ui_context":
			s.setUIContextFromWS(msg.View, msg.FSPath)
		}
	}
}

func (s *Server) runWriter(ctx context.Context, c *sessionConn) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.out:
			wctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
			err := c.ws.Write(wctx, websocket.MessageText, data)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// runHeartbeat issues a WebSocket protocol-level Ping every heartbeatInterval
// and waits up to heartbeatTimeout for the matching Pong. Protocol frames are
// answered by the browser below the JS event loop, so backgrounded/throttled
// tabs stay alive where the old JSON ping/pong scheme would have timed out.
//
// A failed Ping closes the connection with PolicyViolation unless the parent
// context is already done (normal teardown path — no need to race the closer).
func (s *Server) runHeartbeat(ctx context.Context, c *sessionConn) {
	ticker := time.NewTicker(s.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, s.heartbeatTimeout)
			err := c.ws.Ping(pingCtx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					_ = c.ws.Close(websocket.StatusPolicyViolation, "heartbeat timeout")
				}
				return
			}
		}
	}
}

func (s *Server) deliverConfirm(id string, resp agent.ConfirmResponse) {
	s.mu.Lock()
	ch, ok := s.confirms[id]
	s.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- resp:
	default:
	}
}

func (s *Server) cancelTurn(c *sessionConn, turnID string) {
	s.mu.Lock()
	ts := s.currentTurn
	s.mu.Unlock()
	if ts == nil {
		return
	}
	if ts.owner != c {
		return
	}
	if turnID != "" && ts.id != turnID {
		return
	}
	ts.cancel()
}

func (s *Server) handleText(ctx context.Context, c *sessionConn, text string) {
	select {
	case s.requestQueue <- struct{}{}:
		defer func() { <-s.requestQueue }()
	case <-ctx.Done():
		return
	}

	s.driverMu.Lock()
	defer s.driverMu.Unlock()

	turnCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ts := &turnState{id: newID(), owner: c, cancel: cancel}
	s.setTurn(ts)
	defer s.clearTurn(ts)

	s.emitPhaseIfChanged(ts, "Thinking")
	defer s.emitPhaseIfChanged(ts, "Idle")

	// Mirror the REPL: blue LED on for the whole turn, off afterwards.
	// Gives operators the same "device is working" cue in the web UI
	// as they get on the CLI. Errors are ignored — the LED is cosmetic
	// and a failed write shouldn't block a real turn.
	if s.flipper != nil {
		_ = s.flipper.SetLED("b", 0xff)
		defer func() { _ = s.flipper.SetLED("b", 0) }()
	}

	resp, err := s.agent.Run(turnCtx, text)
	if err != nil {
		s.broadcast(map[string]any{
			"type":    "error",
			"content": err.Error(),
			"turn_id": ts.id,
		})
		return
	}
	s.broadcast(map[string]any{
		"type":    "response",
		"content": resp,
		"turn_id": ts.id,
	})
}

func (s *Server) handleAudio(ctx context.Context, c *sessionConn, audioBase64 string) {
	select {
	case s.requestQueue <- struct{}{}:
		defer func() { <-s.requestQueue }()
	case <-ctx.Done():
		return
	}

	if s.voice == nil {
		s.sendTo(c, map[string]any{"type": "error", "content": "voice not configured — set OPENAI_API_KEY"})
		return
	}

	s.sendTo(c, map[string]any{"type": "status", "content": "transcribing"})

	raw := audioBase64
	if idx := strings.Index(raw, ","); idx >= 0 {
		raw = raw[idx+1:]
	}

	audioBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		s.sendTo(c, map[string]any{"type": "error", "content": "invalid audio data"})
		return
	}

	text, err := s.voice.TranscribeReader(bytes.NewReader(audioBytes), "recording.webm")
	if err != nil {
		s.sendTo(c, map[string]any{"type": "error", "content": fmt.Sprintf("transcription failed: %v", err)})
		return
	}

	s.sendTo(c, map[string]any{"type": "transcription", "content": text})
	s.handleText(ctx, c, text)
}

func decodeDecision(s string) agent.Decision {
	switch s {
	case "approve":
		return agent.DecisionApprove
	case "approve_all":
		return agent.DecisionApproveAll
	case "revise":
		return agent.DecisionRevise
	default:
		return agent.DecisionDeny
	}
}

// rawOrEmpty returns the JSON body of a tool input as a string, or "" when
// the raw message is empty. Clients render this verbatim in the risk card
// and tool timeline so valid JSON is preserved byte-for-byte.
func rawOrEmpty(r json.RawMessage) string {
	if len(r) == 0 {
		return ""
	}
	return string(r)
}

// newID returns a 16-byte random hex identifier used for session / turn /
// confirm correlation. crypto/rand is seeded by the OS so there is no
// collision risk for the lifetime of a homelab process.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ts%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// CSRF posture: no CSRF middleware is needed on this server.
// Authentication is performed via the Authorization: Bearer header — not
// cookies. Browsers enforce the CORS preflight before allowing cross-origin
// requests to attach custom headers, so a malicious page cannot forge a
// credentialed request without the token. For unauthenticated operation
// (loopback-only or explicit web.allow_unauthed_public) the trust model is
// already 'anyone who can reach the port controls the agent', so CSRF
// protection would add no meaningful barrier.

// requireAuth wraps an http.HandlerFunc with the bearer-token check. When
// s.token is empty the wrapper is a passthrough — dev-mode parity with the
// legacy no-auth behaviour. A non-empty token must arrive in
// `Authorization: Bearer <token>`; anything else is 401.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.checkAuth(r, bearerFromHeader(r.Header.Get("Authorization"))) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// checkAuth is the single policy decision. Empty s.token → allow (the
// per-Start warning covers non-loopback exposure). Non-empty token → the
// supplied value must match in constant time.
func (s *Server) checkAuth(_ *http.Request, supplied string) bool {
	if s.token == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(s.token)) == 1
}

// bearerFromHeader returns the token portion of an "Authorization: Bearer X"
// header, or "" when the header is absent or not a Bearer scheme.
func bearerFromHeader(h string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// bearerFromWSProtocol extracts a bearer token from the Sec-WebSocket-Protocol
// negotiation. Clients send `Sec-WebSocket-Protocol: bearer, <token>` (the
// header may arrive as either one comma-separated value or multiple header
// values). Returns the supplied token and whether the "bearer" scheme was
// present; the caller uses the second result to decide whether to echo the
// subprotocol back on the upgrade response.
func bearerFromWSProtocol(headers []string) (token string, hasBearer bool) {
	var parts []string
	for _, h := range headers {
		for _, p := range strings.Split(h, ",") {
			if t := strings.TrimSpace(p); t != "" {
				parts = append(parts, t)
			}
		}
	}
	for i, p := range parts {
		if p == "bearer" {
			hasBearer = true
			if i+1 < len(parts) {
				token = parts[i+1]
			}
			return token, hasBearer
		}
	}
	return "", false
}

// effectiveOriginPatterns translates the configured allow-list into the
// pattern slice coder/websocket expects. Empty slice means "same-origin
// only" — coder/websocket compares Origin host to Host header itself.
//
// The config loader (see validateOriginConfig) has already refused a literal
// "*" entry, so this function never emits the wildcard as a matcher for an
// individual host; wildcard semantics come exclusively from allowAnyOrigin.
func (s *Server) effectiveOriginPatterns() []string {
	if s.allowAnyOrigin {
		return []string{"*"}
	}
	if len(s.corsOrigins) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.corsOrigins))
	for _, o := range s.corsOrigins {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		out = append(out, o)
	}
	return out
}

// validateOriginConfig refuses a CORS config that contains a literal "*"
// entry. The user-facing requirement is explicit: to enable wildcard Origin
// matching the operator must (a) remove "*" from web.cors_origins and
// (b) set web.allow_any_origin: true. Catching the footgun at Start keeps a
// stray "*" in config from silently exposing the agent bridge to any tab.
func (s *Server) validateOriginConfig() error {
	for _, o := range s.corsOrigins {
		if strings.TrimSpace(o) == "*" {
			return fmt.Errorf(`web.cors_origins contains "*": remove it and set web.allow_any_origin: true if you truly want wildcard Origin matching (this indirection keeps the footgun out of an origin allow-list)`)
		}
	}
	return nil
}

// hostOf returns the host portion of "host:port", or "" when parsing fails.
// Used by Start to decide whether to print the no-token-and-public warning.
func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return h
}
