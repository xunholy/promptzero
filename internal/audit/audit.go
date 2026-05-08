package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/risk"
)

type Level string

const (
	LevelInfo     Level = "info"
	LevelAction   Level = "action"
	LevelWarning  Level = "warning"
	LevelCritical Level = "critical"
)

type Entry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Tool      string    `json:"tool"`
	Input     string    `json:"input"`
	Output    string    `json:"output"`
	Risk      string    `json:"risk"`
	Level     Level     `json:"level"`
	SessionID string    `json:"session_id"`
	Duration  int64     `json:"duration_ms"`
	Success   bool      `json:"success"`

	// TraceID correlates this entry with one REPL turn. Not persisted to
	// the DB (schema predates the field); carried in-memory so observers
	// (rules engine, webhooks, slog) can surface the turn that produced
	// it. Empty when the caller did not route through obs.WithTrace.
	TraceID string `json:"trace_id,omitempty"`

	// TechniqueIDs records the MITRE ATT&CK technique IDs the tool
	// contributes to at recording time (P1-07). Populated by the
	// agent from the attack.Index; derived, not persisted to the
	// DB schema. Enables the /report ATT&CK coverage heatmap to
	// trust entry-time mappings even if the index changes later.
	TechniqueIDs []string `json:"technique_ids,omitempty"`
}

// TechniqueResolver is an optional hook that maps a tool name to the
// ATT&CK technique IDs it contributes to. Installed via SetTechniqueResolver;
// wired at agent startup to internal/attack's Index (P1-07). Empty
// slice / nil resolver means entries carry no TechniqueIDs.
type TechniqueResolver func(toolName string) []string

type Log struct {
	db          *sql.DB
	sessionID   string
	path        string
	lockFile    *os.File
	techResolve TechniqueResolver

	obsMu     sync.RWMutex
	observers []func(Entry)
}

// Open prepares the audit log at dbPath. It takes a non-blocking advisory
// flock on the db file so only one PromptZero process writes to a given
// path at a time; if that lock is already held, Open falls back to a
// PID-suffixed sibling path (<dbPath>.<pid>) and logs a warning. The
// fallback keeps the REPL responsive instead of hard-erroring when a
// stale or sibling process still holds the primary log — each process
// gets its own WAL-backed sqlite file and concurrent writers no longer
// corrupt each other.
//
// The lock is released on Log.Close.
func Open(dbPath string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, err
	}

	actualPath := dbPath
	lockFile, locked, err := tryFlock(dbPath)
	if err != nil {
		return nil, fmt.Errorf("locking audit db: %w", err)
	}
	if !locked {
		fallback := fmt.Sprintf("%s.%d", dbPath, os.Getpid())
		obs.Default().Warn("audit_lock_contended",
			"primary", dbPath,
			"fallback", fallback,
			"reason", "another process holds the primary db flock",
		)
		lockFile, locked, err = tryFlock(fallback)
		if err != nil {
			return nil, fmt.Errorf("locking audit db fallback %s: %w", fallback, err)
		}
		if !locked {
			// Extremely unlikely: two processes with the same PID raced.
			// Disambiguate with a timestamp and retry once.
			fallback = fmt.Sprintf("%s.%d-%d", dbPath, os.Getpid(), time.Now().UnixNano())
			lockFile, locked, err = tryFlock(fallback)
			if err != nil || !locked {
				return nil, fmt.Errorf("locking audit db fallback %s: %w", fallback, err)
			}
		}
		actualPath = fallback
	}

	db, err := sql.Open("sqlite", actualPath)
	if err != nil {
		_ = releaseFlock(lockFile)
		return nil, fmt.Errorf("opening audit db: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			tool TEXT NOT NULL,
			input TEXT,
			output TEXT,
			risk TEXT,
			level TEXT NOT NULL,
			session_id TEXT,
			duration_ms INTEGER,
			success INTEGER DEFAULT 1
		);
		CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool);
		CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
		CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_log(risk);
	`)
	if err != nil {
		db.Close()
		_ = releaseFlock(lockFile)
		return nil, fmt.Errorf("creating audit tables: %w", err)
	}

	// Audit log can contain secrets embedded in tool inputs/outputs. Tighten
	// the mode now that the file is guaranteed to exist.
	if err := os.Chmod(actualPath, 0o600); err != nil {
		obs.Default().Warn("audit_chmod_failed", "path", actualPath, "err", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		obs.Default().Warn("audit_wal_enable_failed", "err", err)
	}

	return &Log{
		db:        db,
		sessionID: fmt.Sprintf("session-%d", time.Now().Unix()),
		path:      actualPath,
		lockFile:  lockFile,
	}, nil
}

func (l *Log) Close() error {
	err := l.db.Close()
	if relErr := releaseFlock(l.lockFile); relErr != nil && err == nil {
		err = relErr
	}
	l.lockFile = nil
	return err
}

// Path returns the on-disk path of the sqlite db backing this log. When
// the primary path was contended at Open time this will be the
// PID-suffixed fallback; tests and /audit tail use it to distinguish the
// two cases.
func (l *Log) Path() string { return l.path }

func (l *Log) SessionID() string {
	return l.sessionID
}

func (l *Log) Record(tool string, input interface{}, output string, risk string, level Level, duration time.Duration, success bool) {
	l.RecordCtx(context.Background(), tool, input, output, risk, level, duration, success)
}

// RecordCtx is the ctx-aware Record path. When ctx carries a trace (via
// obs.WithTrace) the trace ID is attached to the emitted Entry and the
// structured log line so observers can correlate the audit row with the
// REPL turn that produced it.
func (l *Log) RecordCtx(ctx context.Context, tool string, input interface{}, output string, risk string, level Level, duration time.Duration, success bool) {
	inputJSON, err := json.Marshal(input)
	if err != nil {
		obs.Default().Warn("audit_input_marshal_failed", "tool", tool, "err", err)
		inputJSON = []byte(fmt.Sprintf(`{"_marshal_error":%q}`, err.Error()))
	}

	// Truncate long outputs for storage
	if len(output) > 65535 {
		output = output[:65535] + "... [truncated]"
	}

	ts := time.Now().UTC()
	_, err = l.db.Exec(`
		INSERT INTO audit_log (timestamp, tool, input, output, risk, level, session_id, duration_ms, success)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts.Format(time.RFC3339),
		tool,
		string(inputJSON),
		output,
		risk,
		string(level),
		l.sessionID,
		duration.Milliseconds(),
		success,
	)
	if err != nil {
		obs.Default().Warn("audit_record_failed", "tool", tool, "err", err)
		return
	}
	traceID := obs.TraceID(ctx)
	obs.FromCtx(ctx).Info("audit_record",
		"tool", tool,
		"risk", risk,
		"level", string(level),
		"success", success,
		"duration_ms", duration.Milliseconds(),
		"session_id", l.sessionID,
	)
	var techs []string
	if l.techResolve != nil {
		techs = l.techResolve(tool)
	}
	l.notify(Entry{
		Timestamp:    ts,
		Tool:         tool,
		Input:        string(inputJSON),
		Output:       output,
		Risk:         risk,
		Level:        level,
		SessionID:    l.sessionID,
		Duration:     duration.Milliseconds(),
		Success:      success,
		TraceID:      traceID,
		TechniqueIDs: techs,
	})
}

// SetTechniqueResolver installs the ATT&CK tool-to-technique mapping
// used to populate Entry.TechniqueIDs. Pass nil to disable. Safe to
// call from setup code before Record begins; callers during Record
// accept the race (the next entry picks up the new resolver).
func (l *Log) SetTechniqueResolver(fn TechniqueResolver) {
	l.techResolve = fn
}

// AddObserver registers a callback fired after every successful Record
// insert. Observers run synchronously on the caller goroutine, so keep
// them fast — for anything network-bound (webhooks) the observer
// should enqueue and return immediately. Adding during iteration is safe;
// observers added mid-notify are picked up on the next event.
func (l *Log) AddObserver(fn func(Entry)) {
	if fn == nil {
		return
	}
	l.obsMu.Lock()
	defer l.obsMu.Unlock()
	l.observers = append(l.observers, fn)
}

// notify fans out an Entry to every registered observer. RLock so
// AddObserver does not block the Record path; observers panicking would
// crash audit recording, so they are run in a deferred-recover block.
//
// The zero-observer fast path skips the slice copy entirely. notify is
// called from RecordCtx on every tool dispatch, and most sessions wire
// only an internal logger or none at all — saving the make/copy keeps
// the dispatch hot path free of one heap allocation per audit row.
func (l *Log) notify(e Entry) {
	l.obsMu.RLock()
	if len(l.observers) == 0 {
		l.obsMu.RUnlock()
		return
	}
	observers := make([]func(Entry), len(l.observers))
	copy(observers, l.observers)
	l.obsMu.RUnlock()
	for _, fn := range observers {
		func() {
			defer func() {
				if r := recover(); r != nil {
					obs.Default().Error("audit_observer_panicked", "recovered", fmt.Sprintf("%v", r))
				}
			}()
			fn(e)
		}()
	}
}

func (l *Log) Query(limit int) ([]Entry, error) {
	rows, err := l.db.Query(`
		SELECT id, timestamp, tool, COALESCE(input,''), COALESCE(output,''), COALESCE(risk,''), level, COALESCE(session_id,''), COALESCE(duration_ms,0), success
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Tool, &e.Input, &e.Output, &e.Risk, &e.Level, &e.SessionID, &e.Duration, &e.Success); err != nil {
			obs.Default().Warn("audit_row_scan_failed", "where", "Query", "err", err)
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (l *Log) QueryBySession(sessionID string) ([]Entry, error) {
	rows, err := l.db.Query(`
		SELECT id, timestamp, tool, COALESCE(input,''), COALESCE(output,''), COALESCE(risk,''), level, session_id, COALESCE(duration_ms,0), success
		FROM audit_log WHERE session_id = ? ORDER BY id ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Tool, &e.Input, &e.Output, &e.Risk, &e.Level, &e.SessionID, &e.Duration, &e.Success); err != nil {
			obs.Default().Warn("audit_row_scan_failed", "where", "QueryBySession", "session_id", sessionID, "err", err)
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// Filter is the declarative query shape accepted by QueryFiltered. Zero
// fields are ignored; non-zero fields are ANDed together. All string
// matches against indexed columns are exact (Risk, Session) or substring
// (Tool, Contains); none use user-supplied SQL fragments.
type Filter struct {
	Tool     string    // substring match on tool name (LIKE '%<v>%')
	Risk     string    // exact: low|medium|high|critical
	Session  string    // exact session id
	Since    time.Time // timestamp >= Since when non-zero
	Until    time.Time // timestamp <= Until when non-zero
	Success  *bool     // nil = any; &true / &false to filter
	Contains string    // substring match on input OR output
	Limit    int       // default 100 when <= 0
	Offset   int       // rows to skip for pagination
}

// ToolCount is one row of a top-tools aggregation.
type ToolCount struct {
	Tool  string
	Count int
}

// RiskCount is one row of a top-risks aggregation.
type RiskCount struct {
	Risk  string
	Count int
}

// QueryFiltered returns audit entries matching f. All user-supplied values
// are bound as SQL parameters — no string interpolation, so operator input
// cannot inject SQL. An empty Filter returns the most recent 100 entries.
func (l *Log) QueryFiltered(f Filter) ([]Entry, error) {
	var (
		clauses []string
		args    []interface{}
	)
	if f.Tool != "" {
		clauses = append(clauses, "tool LIKE ?")
		args = append(args, "%"+f.Tool+"%")
	}
	if f.Risk != "" {
		clauses = append(clauses, "risk = ?")
		args = append(args, f.Risk)
	}
	if f.Session != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, f.Session)
	}
	if !f.Since.IsZero() {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}
	if !f.Until.IsZero() {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, f.Until.UTC().Format(time.RFC3339))
	}
	if f.Success != nil {
		clauses = append(clauses, "success = ?")
		if *f.Success {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}
	if f.Contains != "" {
		clauses = append(clauses, "(input LIKE ? OR output LIKE ?)")
		args = append(args, "%"+f.Contains+"%", "%"+f.Contains+"%")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, limit, f.Offset)

	rows, err := l.db.Query(`
		SELECT id, timestamp, tool, COALESCE(input,''), COALESCE(output,''), COALESCE(risk,''), level, COALESCE(session_id,''), COALESCE(duration_ms,0), success
		FROM audit_log`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Tool, &e.Input, &e.Output, &e.Risk, &e.Level, &e.SessionID, &e.Duration, &e.Success); err != nil {
			obs.Default().Warn("audit_row_scan_failed", "where", "QueryFiltered", "err", err)
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// TopTools groups audit entries by tool and returns the count-desc
// top-n, optionally restricted to entries since the given time. A zero
// since means "all time".
func (l *Log) TopTools(since time.Time, n int) ([]ToolCount, error) {
	if n <= 0 {
		n = 10
	}
	var (
		rows *sql.Rows
		err  error
	)
	if since.IsZero() {
		rows, err = l.db.Query(`SELECT tool, COUNT(*) FROM audit_log GROUP BY tool ORDER BY COUNT(*) DESC LIMIT ?`, n)
	} else {
		rows, err = l.db.Query(`SELECT tool, COUNT(*) FROM audit_log WHERE timestamp >= ? GROUP BY tool ORDER BY COUNT(*) DESC LIMIT ?`,
			since.UTC().Format(time.RFC3339), n)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ToolCount
	for rows.Next() {
		var tc ToolCount
		if err := rows.Scan(&tc.Tool, &tc.Count); err != nil {
			obs.Default().Warn("audit_row_scan_failed", "where", "TopTools", "err", err)
			continue
		}
		out = append(out, tc)
	}
	return out, rows.Err()
}

// TopRisks groups audit entries by risk level and returns the count-desc
// ordering. Used by /audit top risks to spotlight whether a session leans
// heavy on destructive calls.
func (l *Log) TopRisks(since time.Time) ([]RiskCount, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if since.IsZero() {
		rows, err = l.db.Query(`SELECT COALESCE(risk,''), COUNT(*) FROM audit_log GROUP BY risk ORDER BY COUNT(*) DESC`)
	} else {
		rows, err = l.db.Query(`SELECT COALESCE(risk,''), COUNT(*) FROM audit_log WHERE timestamp >= ? GROUP BY risk ORDER BY COUNT(*) DESC`,
			since.UTC().Format(time.RFC3339))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RiskCount
	for rows.Next() {
		var rc RiskCount
		if err := rows.Scan(&rc.Risk, &rc.Count); err != nil {
			obs.Default().Warn("audit_row_scan_failed", "where", "TopRisks", "err", err)
			continue
		}
		out = append(out, rc)
	}
	return out, rows.Err()
}

// MaxID returns the current highest row id, used by the /audit tail
// implementation to watch for new inserts.
func (l *Log) MaxID() (int64, error) {
	var id sql.NullInt64
	if err := l.db.QueryRow("SELECT MAX(id) FROM audit_log").Scan(&id); err != nil {
		return 0, err
	}
	if !id.Valid {
		return 0, nil
	}
	return id.Int64, nil
}

// QuerySince returns entries whose id is strictly greater than afterID,
// ordered oldest-first. Pair with MaxID() to tail new audit rows.
func (l *Log) QuerySince(afterID int64) ([]Entry, error) {
	rows, err := l.db.Query(`
		SELECT id, timestamp, tool, COALESCE(input,''), COALESCE(output,''), COALESCE(risk,''), level, COALESCE(session_id,''), COALESCE(duration_ms,0), success
		FROM audit_log WHERE id > ? ORDER BY id ASC`, afterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Tool, &e.Input, &e.Output, &e.Risk, &e.Level, &e.SessionID, &e.Duration, &e.Success); err != nil {
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (l *Log) Export() (string, error) {
	entries, err := l.QueryBySession(l.sessionID)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (l *Log) Stats() (string, error) {
	// One conditional-aggregate query instead of three round-trips.
	// SQLite turns SUM(boolean-expr) into a count-where for free, and
	// COUNT(DISTINCT tool) coexists with the conditional sums in a
	// single scan over the session's rows.
	var total, success, tools int
	err := l.db.QueryRow(`
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT tool)
		FROM audit_log WHERE session_id = ?`, l.sessionID).Scan(&total, &success, &tools)
	if err != nil {
		return "", fmt.Errorf("querying stats: %w", err)
	}
	failed := total - success

	return fmt.Sprintf("Session: %s\nTotal actions: %d\nSuccessful: %d\nFailed: %d\nUnique tools: %d",
		l.sessionID, total, success, failed, tools), nil
}

// RequireOpen returns an error when l is nil and level is High or above.
// This enforces fail-closed behaviour: when the audit log is not initialised,
// destructive (High/Critical) actions are refused rather than proceeding silently.
// Low/Medium actions are permitted without an audit log for back-compat.
func RequireOpen(l *Log, level risk.Level) error {
	if l != nil {
		return nil
	}
	if level >= risk.High {
		return fmt.Errorf("audit log not initialized — refusing %s-risk action", level)
	}
	return nil
}
