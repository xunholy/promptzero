package flipper

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// CheckLevel classifies a single ConnectionReport step's outcome.
//
// LevelPass: the step completed cleanly.
// LevelWarn: the step succeeded after a recovery, or completed with a
// non-fatal degradation that the operator should know about.
// LevelFail: the step failed terminally; downstream steps were skipped.
// LevelSkipped: the step did not run on this transport / firmware
// (e.g. CLI handshake on a BLE link).
type CheckLevel string

const (
	LevelPass    CheckLevel = "pass"
	LevelWarn    CheckLevel = "warn"
	LevelFail    CheckLevel = "fail"
	LevelSkipped CheckLevel = "skipped"
)

// Check is one step's outcome inside a ConnectionReport.
//
// Name is a stable, machine-readable identifier (snake_case with dotted
// namespacing — e.g. "transport.dial", "handshake", "detect_capabilities").
// Detail is operator-facing free text — kept short, no ANSI.
// Elapsed is the wall-clock time the step took.
type Check struct {
	Name    string        `json:"name"`
	Level   CheckLevel    `json:"level"`
	Detail  string        `json:"detail,omitempty"`
	Elapsed time.Duration `json:"elapsed_ns"`
}

// ConnectionReport is the structured trail of every step ConnectURL took
// to bring a Flipper online. It is appended to in-order and never
// re-shuffled; the JSON shape is the operator-facing contract surfaced
// in /api/device.
type ConnectionReport struct {
	StartedAt   time.Time
	CompletedAt time.Time

	mu     sync.Mutex
	checks []Check
}

// NewConnectionReport stamps StartedAt and returns an empty report ready
// for Add. The zero-value ConnectionReport is also usable; this helper
// just records the start time consistently.
func NewConnectionReport() *ConnectionReport {
	return &ConnectionReport{StartedAt: time.Now()}
}

// Add appends a check to the report. Safe for concurrent use — although
// ConnectURL drives steps sequentially today, /api/device may read the
// report from a different goroutine.
func (r *ConnectionReport) Add(c Check) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.checks = append(r.checks, c)
	r.mu.Unlock()
}

// Complete stamps CompletedAt. Idempotent on the assumption ConnectURL
// calls it once, but a second call simply overwrites with a fresher
// timestamp.
func (r *ConnectionReport) Complete() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.CompletedAt = time.Now()
	r.mu.Unlock()
}

// Checks returns a copy of the recorded checks. The slice is detached so
// callers can range over it without holding the report lock.
func (r *ConnectionReport) Checks() []Check {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Check, len(r.checks))
	copy(out, r.checks)
	return out
}

// Duration returns CompletedAt - StartedAt when both are set, otherwise
// the time since StartedAt. Zero when the report has not started.
func (r *ConnectionReport) Duration() time.Duration {
	if r == nil || r.StartedAt.IsZero() {
		return 0
	}
	r.mu.Lock()
	end := r.CompletedAt
	r.mu.Unlock()
	if end.IsZero() {
		return time.Since(r.StartedAt)
	}
	return end.Sub(r.StartedAt)
}

// PassedCount returns the number of checks at LevelPass.
func (r *ConnectionReport) PassedCount() int { return r.countAt(LevelPass) }

// WarningCount returns the number of checks at LevelWarn.
func (r *ConnectionReport) WarningCount() int { return r.countAt(LevelWarn) }

// FailedCount returns the number of checks at LevelFail.
func (r *ConnectionReport) FailedCount() int { return r.countAt(LevelFail) }

// SkippedCount returns the number of checks at LevelSkipped.
func (r *ConnectionReport) SkippedCount() int { return r.countAt(LevelSkipped) }

func (r *ConnectionReport) countAt(level CheckLevel) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.checks {
		if c.Level == level {
			n++
		}
	}
	return n
}

// Summary renders a one-line operator summary of the report's terminal
// state, e.g. "3 passed, 1 warning". Used by --verbose mode and any
// caller that wants a banner-friendly digest without iterating Checks.
func (r *ConnectionReport) Summary() string {
	if r == nil {
		return "no checks recorded"
	}
	pass := r.PassedCount()
	warn := r.WarningCount()
	fail := r.FailedCount()
	skip := r.SkippedCount()
	total := pass + warn + fail + skip
	if total == 0 {
		return "no checks recorded"
	}
	parts := []string{fmt.Sprintf("%d passed", pass)}
	if warn > 0 {
		parts = append(parts, fmt.Sprintf("%d warning%s", warn, plural(warn)))
	}
	if fail > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", fail))
	}
	if skip > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", skip))
	}
	return joinComma(parts)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func joinComma(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}

// reportJSON is the on-the-wire shape of a ConnectionReport. Field names
// are stable: operator tooling (jq pipelines, /api/device consumers)
// reads them by name, so renames are breaking changes.
type reportJSON struct {
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at,omitempty"`
	DurationNS   int64     `json:"duration_ns"`
	Summary      string    `json:"summary"`
	PassedCount  int       `json:"passed_count"`
	WarningCount int       `json:"warning_count"`
	FailedCount  int       `json:"failed_count"`
	SkippedCount int       `json:"skipped_count"`
	Checks       []Check   `json:"checks"`
}

// MarshalJSON produces operator-readable JSON. The rendered shape is the
// stable contract surfaced via /api/device.connection_report.
func (r *ConnectionReport) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	r.mu.Lock()
	checks := make([]Check, len(r.checks))
	copy(checks, r.checks)
	completed := r.CompletedAt
	r.mu.Unlock()
	out := reportJSON{
		StartedAt:    r.StartedAt,
		CompletedAt:  completed,
		DurationNS:   r.Duration().Nanoseconds(),
		Summary:      r.Summary(),
		PassedCount:  r.PassedCount(),
		WarningCount: r.WarningCount(),
		FailedCount:  r.FailedCount(),
		SkippedCount: r.SkippedCount(),
		Checks:       checks,
	}
	return json.Marshal(out)
}

// ToJSON returns the report rendered as an interface{} suitable for
// embedding in another JSON response. Convenience wrapper around
// MarshalJSON for /api/device, which assembles a single map[string]any
// payload.
func (r *ConnectionReport) ToJSON() any {
	if r == nil {
		return nil
	}
	b, err := r.MarshalJSON()
	if err != nil {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil
	}
	return v
}

// SetConnectionReport stashes a ConnectionReport on the Flipper handle so
// /api/device and --verbose can read it after ConnectURL returns.
//
// Stored via atomic.Pointer because /api/device may read concurrently
// with a future Reconnect path that wants to refresh the report.
func (f *Flipper) SetConnectionReport(r *ConnectionReport) {
	if f == nil {
		return
	}
	f.connReport.Store(r)
}

// ConnectionReport returns the most recently attached ConnectionReport,
// or nil when none has been set. Callers must treat the returned value
// as read-only.
func (f *Flipper) ConnectionReport() *ConnectionReport {
	if f == nil {
		return nil
	}
	return f.connReport.Load()
}
