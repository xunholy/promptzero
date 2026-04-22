// Package targetmem stores per-target facts across PromptZero
// sessions. When a scan, detect, or RX tool produces a target
// identifier (BSSID, card UID, RF frequency+protocol), the agent
// can record what it learned about that target and recall those
// facts on future sessions.
//
// Backing store: SQLite. Same database file as the audit log would
// be conceptually clean but keeps migration simpler to separate for
// now; targets live in ~/.promptzero/targetmem.db. Schema is
// key/value per target identifier so operators can attach arbitrary
// JSON without schema migrations.
package targetmem

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Target is one remembered target row. Identifier is the stable
// key (BSSID, card UID hex, freq+protocol tuple); Kind describes
// what kind of identifier it is so the model knows how to read it.
type Target struct {
	Identifier string    `json:"identifier"`
	Kind       string    `json:"kind"` // "bssid" / "nfc_uid" / "rfid_data" / "subghz" / other
	Facts      any       `json:"facts,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Known target kinds. Operators / tools are free to introduce new
// kinds — the store accepts any string — but these constants cover
// the common cases.
const (
	KindBSSID    = "bssid"
	KindNFCUID   = "nfc_uid"
	KindRFIDData = "rfid_data"
	KindSubGHz   = "subghz"
	KindIButton  = "ibutton"
)

// Store is the persistent target memory. Safe for concurrent use;
// a single SQLite connection is serialised internally.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

// DefaultPath returns ~/.promptzero/targetmem.db.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".promptzero", "targetmem.db"), nil
}

// Open creates or opens the target-memory store at path. The parent
// directory is created if missing. Schema migrations run idempotently
// on every open so a fresh install and an existing db reach the same
// state.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("targetmem: mkdir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("targetmem: open: %w", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS targets (
			identifier TEXT NOT NULL,
			kind TEXT NOT NULL,
			facts TEXT,
			first_seen TIMESTAMP NOT NULL,
			last_seen TIMESTAMP NOT NULL,
			PRIMARY KEY (identifier, kind)
		);
		CREATE INDEX IF NOT EXISTS idx_targets_kind ON targets(kind);
		CREATE INDEX IF NOT EXISTS idx_targets_last_seen ON targets(last_seen);
	`); err != nil {
		return nil, fmt.Errorf("targetmem: schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Remember upserts a target. When the identifier+kind already exists,
// Facts is overwritten and LastSeen bumps; FirstSeen is preserved so
// the original discovery timestamp survives across re-observations.
// Passing an empty identifier is rejected to keep the primary key
// clean.
func (s *Store) Remember(t Target) error {
	if t.Identifier == "" {
		return fmt.Errorf("targetmem: empty identifier")
	}
	if t.Kind == "" {
		t.Kind = KindBSSID // conservative default — most common case
	}
	factsJSON, err := json.Marshal(t.Facts)
	if err != nil {
		return fmt.Errorf("targetmem: marshal facts: %w", err)
	}
	now := time.Now().UTC()
	if t.FirstSeen.IsZero() {
		t.FirstSeen = now
	}
	if t.LastSeen.IsZero() {
		t.LastSeen = now
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`
		INSERT INTO targets (identifier, kind, facts, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(identifier, kind) DO UPDATE SET
			facts = excluded.facts,
			last_seen = excluded.last_seen
	`, t.Identifier, t.Kind, string(factsJSON), t.FirstSeen.Format(time.RFC3339), t.LastSeen.Format(time.RFC3339))
	return err
}

// Lookup returns a target by identifier+kind or (zero, false) when
// absent. Case-sensitive — BSSIDs are normalised lowercase by
// convention at the call site, not the store.
func (s *Store) Lookup(identifier, kind string) (Target, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var t Target
	var factsJSON string
	var firstSeenStr, lastSeenStr string
	err := s.db.QueryRow(`
		SELECT identifier, kind, facts, first_seen, last_seen
		FROM targets
		WHERE identifier = ? AND kind = ?
	`, identifier, kind).Scan(&t.Identifier, &t.Kind, &factsJSON, &firstSeenStr, &lastSeenStr)
	if err == sql.ErrNoRows {
		return Target{}, false, nil
	}
	if err != nil {
		return Target{}, false, err
	}
	if factsJSON != "" {
		_ = json.Unmarshal([]byte(factsJSON), &t.Facts)
	}
	t.FirstSeen, _ = time.Parse(time.RFC3339, firstSeenStr)
	t.LastSeen, _ = time.Parse(time.RFC3339, lastSeenStr)
	return t, true, nil
}

// Recent returns the N most recently observed targets, newest first.
// Useful for the /targets REPL command and for the agent's session-
// start known-targets context block.
func (s *Store) Recent(n int) ([]Target, error) {
	if n <= 0 {
		n = 20
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT identifier, kind, facts, first_seen, last_seen
		FROM targets
		ORDER BY last_seen DESC
		LIMIT ?
	`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		var factsJSON, firstSeenStr, lastSeenStr string
		if err := rows.Scan(&t.Identifier, &t.Kind, &factsJSON, &firstSeenStr, &lastSeenStr); err != nil {
			return nil, err
		}
		if factsJSON != "" {
			_ = json.Unmarshal([]byte(factsJSON), &t.Facts)
		}
		t.FirstSeen, _ = time.Parse(time.RFC3339, firstSeenStr)
		t.LastSeen, _ = time.Parse(time.RFC3339, lastSeenStr)
		out = append(out, t)
	}
	return out, rows.Err()
}

// Forget deletes a target. Safe to call on a non-existent target —
// returns nil. Intended for /targets forget <id> in the REPL.
func (s *Store) Forget(identifier, kind string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM targets WHERE identifier = ? AND kind = ?`, identifier, kind)
	return err
}
