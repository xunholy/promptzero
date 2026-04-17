package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
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
}

type Log struct {
	db        *sql.DB
	sessionID string
}

func Open(dbPath string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
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
		return nil, fmt.Errorf("creating audit tables: %w", err)
	}

	// Audit log can contain secrets embedded in tool inputs/outputs. Tighten
	// the mode now that the file is guaranteed to exist.
	if err := os.Chmod(dbPath, 0o600); err != nil {
		log.Printf("audit: chmod %s: %v", dbPath, err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		log.Printf("audit: enabling WAL journal mode failed: %v", err)
	}

	return &Log{
		db:        db,
		sessionID: fmt.Sprintf("session-%d", time.Now().Unix()),
	}, nil
}

func (l *Log) Close() error {
	return l.db.Close()
}

func (l *Log) SessionID() string {
	return l.sessionID
}

func (l *Log) Record(tool string, input interface{}, output string, risk string, level Level, duration time.Duration, success bool) {
	inputJSON, _ := json.Marshal(input)

	// Truncate long outputs for storage
	if len(output) > 10000 {
		output = output[:10000] + "... [truncated]"
	}

	_, err := l.db.Exec(`
		INSERT INTO audit_log (timestamp, tool, input, output, risk, level, session_id, duration_ms, success)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339),
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
		log.Printf("audit: failed to record %s: %v", tool, err)
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
	var total, success, failed int
	if err := l.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE session_id = ?", l.sessionID).Scan(&total); err != nil {
		return "", fmt.Errorf("querying stats: %w", err)
	}
	if err := l.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE session_id = ? AND success = 1", l.sessionID).Scan(&success); err != nil {
		return "", fmt.Errorf("querying stats: %w", err)
	}
	failed = total - success

	var tools int
	if err := l.db.QueryRow("SELECT COUNT(DISTINCT tool) FROM audit_log WHERE session_id = ?", l.sessionID).Scan(&tools); err != nil {
		return "", fmt.Errorf("querying stats: %w", err)
	}

	return fmt.Sprintf("Session: %s\nTotal actions: %d\nSuccessful: %d\nFailed: %d\nUnique tools: %d",
		l.sessionID, total, success, failed, tools), nil
}
