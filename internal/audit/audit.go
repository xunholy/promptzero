package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
