package obs

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Recorder owns a Prometheus registry and the full PromptZero metric
// surface. It is constructed once per process and handed to every
// subsystem that emits events (audit observer, webhook dispatcher, MQTT
// bridge, agent, workflows). Each Record* method is concurrency-safe
// and cheap — callers should never conditionally branch on "metrics
// enabled"; instead, pass a nil Recorder to disable (every method is a
// nil-receiver no-op).
//
// The Recorder uses its own *prometheus.Registry (not the default
// global) so tests and the Go runtime's process metrics don't bleed
// into PromptZero's scrape surface. Handler() returns an
// http.Handler that exposes the registry in the standard Prom text
// format at whatever route the web server mounts.
type Recorder struct {
	registry *prometheus.Registry

	toolCalls          *prometheus.CounterVec
	toolDuration       *prometheus.HistogramVec
	workflowRuns       *prometheus.CounterVec
	workflowDuration   *prometheus.HistogramVec
	auditEntries       *prometheus.CounterVec
	riskPrompts        *prometheus.CounterVec
	sessionMessages    *prometheus.CounterVec
	tokenUsage         *prometheus.CounterVec
	flipperConnected   prometheus.Gauge
	marauderConnected  prometheus.Gauge
	webhookDeliveries  *prometheus.CounterVec
	mqttPublishes      *prometheus.CounterVec
	anthropicReachable prometheus.Gauge
	uptimeStart        time.Time

	// lastToolMu guards the rolling ring of recent tool completions used
	// by /debug. The ring itself is fixed-size so a noisy session doesn't
	// leak memory.
	lastToolMu sync.Mutex
	lastTool   [lastToolRing]ToolSample
	lastHead   int
	lastCount  int
}

// ToolSample is a compact record of a completed tool invocation used by
// the /debug snapshot. Sample width is intentionally shallow — the full
// output lives in the audit DB.
type ToolSample struct {
	At       time.Time
	Tool     string
	Risk     string
	Err      bool
	Duration time.Duration
}

// lastToolRing is the depth of the in-memory "recent tool calls" buffer
// surfaced by /debug. Three is enough context for a human glance; more
// than that is better served by /history or /audit find.
const lastToolRing = 3

// NewRecorder builds a Recorder backed by a fresh Prometheus registry.
// The native histogram buckets below target PromptZero's observed
// latencies (sub-second reads up through multi-minute brute-forces).
func NewRecorder() *Recorder {
	r := &Recorder{
		registry:    prometheus.NewRegistry(),
		uptimeStart: time.Now(),
	}
	buckets := []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}

	r.toolCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "promptzero_tool_calls_total", Help: "Tool invocation count."},
		[]string{"tool", "risk", "status"},
	)
	r.toolDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "promptzero_tool_duration_seconds", Help: "Tool invocation duration.", Buckets: buckets},
		[]string{"tool"},
	)
	r.workflowRuns = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "promptzero_workflow_runs_total", Help: "Composite workflow runs."},
		[]string{"name", "status"},
	)
	r.workflowDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "promptzero_workflow_duration_seconds", Help: "Workflow total duration.", Buckets: buckets},
		[]string{"name"},
	)
	r.auditEntries = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "promptzero_audit_entries_total", Help: "Audit rows written."},
		[]string{"risk", "level"},
	)
	r.riskPrompts = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "promptzero_risk_prompts_total", Help: "Risk confirmation prompt decisions."},
		[]string{"tool", "decision"},
	)
	r.sessionMessages = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "promptzero_session_messages_total", Help: "Messages added to history."},
		[]string{"role"},
	)
	r.tokenUsage = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "promptzero_token_usage", Help: "Anthropic token usage."},
		[]string{"kind"},
	)
	r.flipperConnected = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "promptzero_flipper_connected", Help: "1 when Flipper serial CLI is connected."},
	)
	r.marauderConnected = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "promptzero_marauder_connected", Help: "1 when Marauder serial CLI is connected."},
	)
	r.webhookDeliveries = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "promptzero_webhook_deliveries_total", Help: "Outbound webhook deliveries."},
		[]string{"name", "status"},
	)
	r.mqttPublishes = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "promptzero_mqtt_publishes_total", Help: "Outbound MQTT publishes."},
		[]string{"status"},
	)
	r.anthropicReachable = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "promptzero_anthropic_reachable", Help: "1 when the Anthropic API was reachable on the last stream attempt."},
	)
	r.anthropicReachable.Set(1)

	r.registry.MustRegister(
		r.toolCalls, r.toolDuration,
		r.workflowRuns, r.workflowDuration,
		r.auditEntries, r.riskPrompts,
		r.sessionMessages, r.tokenUsage,
		r.flipperConnected, r.marauderConnected,
		r.webhookDeliveries, r.mqttPublishes,
		r.anthropicReachable,
	)
	return r
}

// Handler returns the standard Prometheus text-format HTTP handler. Mount
// it at whatever path config.Observability.MetricsPath resolves to.
func (r *Recorder) Handler() http.Handler {
	if r == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics disabled", http.StatusNotFound)
		})
	}
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// Registry returns the underlying registry so tests can scrape it
// directly without standing up an HTTP server.
func (r *Recorder) Registry() *prometheus.Registry {
	if r == nil {
		return nil
	}
	return r.registry
}

// UptimeStart reports when NewRecorder was called. /debug reads this to
// render an uptime string.
func (r *Recorder) UptimeStart() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.uptimeStart
}

// RecordToolCall bumps the tool invocation counter and timing histogram.
// Status is one of "ok", "error", "denied" so Grafana dashboards can
// split the three outcomes without parsing labels. A nil recorder is a
// no-op — pass nil freely when metrics are disabled.
func (r *Recorder) RecordToolCall(tool, riskLevel, status string, d time.Duration) {
	if r == nil {
		return
	}
	r.toolCalls.WithLabelValues(tool, riskLevel, status).Inc()
	r.toolDuration.WithLabelValues(tool).Observe(d.Seconds())

	r.lastToolMu.Lock()
	r.lastTool[r.lastHead] = ToolSample{
		At: time.Now().UTC(), Tool: tool, Risk: riskLevel, Err: status == "error", Duration: d,
	}
	r.lastHead = (r.lastHead + 1) % lastToolRing
	if r.lastCount < lastToolRing {
		r.lastCount++
	}
	r.lastToolMu.Unlock()
}

// RecordWorkflowRun increments the workflow counter and records the
// wall-clock duration. Name matches the advertised tool name (e.g.
// "workflow_nfc_badge_pipeline"), status is "ok" or "error".
func (r *Recorder) RecordWorkflowRun(name, status string, d time.Duration) {
	if r == nil {
		return
	}
	r.workflowRuns.WithLabelValues(name, status).Inc()
	r.workflowDuration.WithLabelValues(name).Observe(d.Seconds())
}

// RecordAudit bumps the audit counter. Call once per audit.Record from
// the audit observer hook.
func (r *Recorder) RecordAudit(risk, level string) {
	if r == nil {
		return
	}
	r.auditEntries.WithLabelValues(risk, level).Inc()
}

// RecordRiskPrompt records an operator decision at the risk gate.
// Decision is "approve", "deny", or "approve_all".
func (r *Recorder) RecordRiskPrompt(tool, decision string) {
	if r == nil {
		return
	}
	r.riskPrompts.WithLabelValues(tool, decision).Inc()
}

// RecordMessage tracks message-history churn so dashboards can see how
// chatty a session is. Role is "user", "assistant", or "tool".
func (r *Recorder) RecordMessage(role string) {
	if r == nil {
		return
	}
	r.sessionMessages.WithLabelValues(role).Inc()
}

// RecordTokens pushes token consumption into the Prom counter. Kind is
// "input" or "output".
func (r *Recorder) RecordTokens(kind string, n int64) {
	if r == nil || n <= 0 {
		return
	}
	r.tokenUsage.WithLabelValues(kind).Add(float64(n))
}

// SetFlipperConnected flips the connected gauge for the Flipper serial
// transport. Called by the flipper connect/reconnect hooks.
func (r *Recorder) SetFlipperConnected(v bool) {
	if r == nil {
		return
	}
	if v {
		r.flipperConnected.Set(1)
	} else {
		r.flipperConnected.Set(0)
	}
}

// SetMarauderConnected flips the Marauder gauge. Only toggled when the
// operator is actively using --wifi; otherwise stays at the default 0.
func (r *Recorder) SetMarauderConnected(v bool) {
	if r == nil {
		return
	}
	if v {
		r.marauderConnected.Set(1)
	} else {
		r.marauderConnected.Set(0)
	}
}

// RecordWebhookDelivery counts an outbound webhook attempt. Status is
// "ok", "error", or a numeric 4xx/5xx class the dispatcher cares to
// split on.
func (r *Recorder) RecordWebhookDelivery(name, status string) {
	if r == nil {
		return
	}
	r.webhookDeliveries.WithLabelValues(name, status).Inc()
}

// RecordMQTTPublish counts an outbound MQTT publish. Status is "ok" or
// "error".
func (r *Recorder) RecordMQTTPublish(status string) {
	if r == nil {
		return
	}
	r.mqttPublishes.WithLabelValues(status).Inc()
}

// SetAnthropicReachable toggles the offline-mode gauge. See
// internal/cost for the detection logic that drives this.
func (r *Recorder) SetAnthropicReachable(v bool) {
	if r == nil {
		return
	}
	if v {
		r.anthropicReachable.Set(1)
	} else {
		r.anthropicReachable.Set(0)
	}
}

// LastTools returns a chronological copy of the recent tool calls,
// oldest first. Used by the /debug snapshot.
func (r *Recorder) LastTools() []ToolSample {
	if r == nil {
		return nil
	}
	r.lastToolMu.Lock()
	defer r.lastToolMu.Unlock()
	out := make([]ToolSample, 0, r.lastCount)
	// Walk the ring oldest → newest.
	start := (r.lastHead - r.lastCount + lastToolRing) % lastToolRing
	for i := 0; i < r.lastCount; i++ {
		idx := (start + i) % lastToolRing
		out = append(out, r.lastTool[idx])
	}
	return out
}
