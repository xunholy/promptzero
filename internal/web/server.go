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
// Outbound taxonomy: status, response, transcription, error (legacy),
// text_delta, tool_status, confirm_request, phase, ping.
// Inbound taxonomy: text, audio, reset (legacy), confirm_response, cancel,
// pong.
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
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
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
	confirms    map[string]chan agent.Decision

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

	// token, when non-empty, is the shared bearer the server requires on
	// every /api and /ws request. Empty means auth disabled (dev mode);
	// the server prints a loud warning when the bind is also non-loopback.
	// Compared with subtle.ConstantTimeCompare to avoid timing side channels.
	token string
	// corsOrigins is the allow-list for the WebSocket Origin header. Empty
	// means same-origin only (the coder/websocket default). Use "*" only
	// for local dev; we pass it through to the AcceptOptions verbatim.
	corsOrigins []string
}

type sessionConn struct {
	id       string
	ws       *websocket.Conn
	out      chan []byte
	lastPong atomic.Int64 // unix nanos; updated by reader on each pong
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
	T         string `json:"t,omitempty"`
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
		confirms:          make(map[string]chan agent.Decision),
		heartbeatInterval: 15 * time.Second,
		heartbeatTimeout:  30 * time.Second,
		writeTimeout:      5 * time.Second,
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

// SetMarauderConnected records the current Marauder serial state for the
// /api/debug snapshot. Call on connect/disconnect transitions.
func (s *Server) SetMarauderConnected(v bool) { s.marauderOn.Store(v) }

// SetAuthToken installs the shared bearer token for /api and /ws. Empty
// disables the check (dev-mode default). Must be called before Start —
// changing the token at runtime would leave open connections with stale
// credentials.
func (s *Server) SetAuthToken(t string) { s.token = t }

// SetCORSOrigins sets the WebSocket Origin allow-list. Empty = same-origin
// only. Must be called before Start.
func (s *Server) SetCORSOrigins(origins []string) { s.corsOrigins = origins }

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
		fmt.Fprintf(os.Stderr, "\x1b[31m●\x1b[0m Web UI bound non-loopback with NO TOKEN set — every /api + /ws is open. Set web.token or PROMPTZERO_WEB_TOKEN.\n")
	}

	srv := &http.Server{Addr: s.addr, Handler: mux}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("PromptZero web UI: http://%s", s.addr)
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

	s.agent.SetConfirmCallback(func(ctx context.Context, req agent.ConfirmRequest) agent.Decision {
		ts := s.turn()
		if ts == nil || ts.owner == nil {
			return agent.DecisionDeny
		}
		id := newID()
		ch := make(chan agent.Decision, 1)
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
		case d := <-ch:
			return d
		case <-ctx.Done():
			return agent.DecisionDeny
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
	if !s.checkAuth(r, r.URL.Query().Get("token")) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: s.effectiveOriginPatterns(),
	})
	if err != nil {
		log.Printf("websocket accept: %v", err)
		return
	}
	defer ws.CloseNow()

	ws.SetReadLimit(10 * 1024 * 1024)

	c := &sessionConn{
		id:  newID(),
		ws:  ws,
		out: make(chan []byte, outboundQueue),
	}
	c.lastPong.Store(time.Now().UnixNano())

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
			s.deliverConfirm(msg.ConfirmID, decodeDecision(msg.Decision))
		case "cancel":
			s.cancelTurn(c, msg.TurnID)
		case "pong":
			c.lastPong.Store(time.Now().UnixNano())
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

func (s *Server) runHeartbeat(ctx context.Context, c *sessionConn) {
	ticker := time.NewTicker(s.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			last := time.Unix(0, c.lastPong.Load())
			if time.Since(last) > s.heartbeatTimeout {
				_ = c.ws.Close(websocket.StatusPolicyViolation, "heartbeat timeout")
				return
			}
			s.sendTo(c, map[string]any{
				"type": "ping",
				"t":    t.UTC().Format(time.RFC3339Nano),
			})
		}
	}
}

func (s *Server) deliverConfirm(id string, d agent.Decision) {
	s.mu.Lock()
	ch, ok := s.confirms[id]
	s.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- d:
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
	s.driverMu.Lock()
	defer s.driverMu.Unlock()

	turnCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ts := &turnState{id: newID(), owner: c, cancel: cancel}
	s.setTurn(ts)
	defer s.clearTurn(ts)

	s.emitPhaseIfChanged(ts, "Thinking")
	defer s.emitPhaseIfChanged(ts, "Idle")

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

// effectiveOriginPatterns translates the configured allow-list into the
// pattern slice coder/websocket expects. Empty slice means "same-origin
// only" — coder/websocket compares Origin host to Host header itself.
func (s *Server) effectiveOriginPatterns() []string {
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

// hostOf returns the host portion of "host:port", or "" when parsing fails.
// Used by Start to decide whether to print the no-token-and-public warning.
func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return h
}
