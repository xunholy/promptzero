package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/risk"
)

// MaxQueryLimit caps the per-call row count returned by Query and
// QueryFiltered. The audit DB grows without bound across sessions;
// a caller asking for limit=1000000 (operator typo, malicious LLM
// tool call, stress test) would tie up SQLite for seconds and
// flood downstream consumers. 10k is generous for any reasonable
// triage flow — callers wanting more should paginate via Offset.
//
// Both the REPL slash commands (/audit query, /history) and the
// audit_query tool consult this cap so the cap can't be bypassed
// by routing through a different surface.
const MaxQueryLimit = 10000

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

	// PersonaVersion is the operator-supplied version string from the
	// active persona's `version:` YAML field at recording time
	// (P3-31). Populated via the per-session PersonaContextResolver.
	// Carried in-memory only; not persisted to the DB schema. Empty
	// when the operator hasn't versioned the persona, when no
	// persona is active, or when the resolver is unset.
	PersonaVersion string `json:"persona_version,omitempty"`

	// PromptHash is the SHA-256 (hex) of the system prompt the agent
	// would have presented for this turn (P3-31). Same provenance
	// rules as PersonaVersion. Lets a regression analyser group
	// sessions by exact prompt content even if the persona version
	// string didn't change (e.g. a prompt typo fixed without bumping
	// the version).
	PromptHash string `json:"prompt_hash,omitempty"`
}

// TechniqueResolver is an optional hook that maps a tool name to the
// ATT&CK technique IDs it contributes to. Installed via SetTechniqueResolver;
// wired at agent startup to internal/attack's Index (P1-07). Empty
// slice / nil resolver means entries carry no TechniqueIDs.
type TechniqueResolver func(toolName string) []string

// PersonaContext is the per-session prompt + persona snapshot recorded
// on every audit row (P3-31). Populated by the agent at session start
// and on persona-switch; the audit log reads it on each Record so
// regression analysis can group rows by the exact prompt content the
// operator was running.
type PersonaContext struct {
	PersonaVersion string
	PromptHash     string
}

// PersonaContextResolver is the hook the agent installs so the audit log
// can pick up the active PersonaContext at record time. The resolver
// is invoked once per audit row; nil resolver leaves the fields empty.
type PersonaContextResolver func() PersonaContext

type Log struct {
	db             *sql.DB
	sessionID      string
	path           string
	lockFile       *os.File
	techResolve    TechniqueResolver
	personaResolve PersonaContextResolver

	// writeMu serialises the read-head/compute-hash/insert sequence in
	// RecordCtx so two concurrent writers in this process can't fork the
	// hash chain. The cross-process flock guarantees a single writer
	// process; writeMu covers intra-process concurrency.
	writeMu sync.Mutex
	// headHash is the hex entry_hash of the most recent row, the chain
	// link the next insert hashes onto. Empty means "no hashed row yet"
	// (fresh DB, or a legacy DB whose tail rows predate the hash chain).
	headHash string

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
			success INTEGER DEFAULT 1,
			entry_hash TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool);
		CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
		CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_log(risk);
	`)
	if err != nil {
		_ = db.Close()
		_ = releaseFlock(lockFile)
		return nil, fmt.Errorf("creating audit tables: %w", err)
	}

	// Migrate audit logs created before the tamper-evidence hash chain:
	// add entry_hash if it is missing. SQLite has no ADD COLUMN IF NOT
	// EXISTS, so a duplicate-column error on an already-migrated DB is
	// expected and ignored. Pre-existing rows keep a NULL hash and are
	// reported as "legacy / unverifiable" by VerifyChain.
	if _, aerr := db.Exec(`ALTER TABLE audit_log ADD COLUMN entry_hash TEXT`); aerr != nil &&
		!strings.Contains(strings.ToLower(aerr.Error()), "duplicate column") {
		obs.Default().Warn("audit_migrate_entry_hash_failed", "err", aerr)
	}

	// Audit log can contain secrets embedded in tool inputs/outputs.
	// Tighten the mode now that the file is guaranteed to exist.
	// SQLite (the modernc.org/sqlite pure-Go port included) clones
	// the main DB's mode onto the -wal and -shm sidecar files when
	// it creates them, so the chmod here transitively tightens the
	// WAL sidecars too — the WAL carries the same uncommitted
	// INSERT data as the main DB, and the sidecars would otherwise
	// land at the process umask (typically 0o644). The
	// TestOpen_WALSidecarsInheritMainDBPerms regression test pins
	// this end-to-end (chmod runs, first Record commits a WAL
	// transaction, the resulting -wal/-shm files come up at 0o600).
	if err := os.Chmod(actualPath, 0o600); err != nil {
		obs.Default().Warn("audit_chmod_failed", "path", actualPath, "err", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		obs.Default().Warn("audit_wal_enable_failed", "err", err)
	}

	l := &Log{
		db: db,
		// UnixNano avoids same-second collisions when an operator
		// reopens the audit log inside a tight loop (quick `Open` →
		// `Close` → `Open` could otherwise reuse the same sessionID
		// and braid two sessions' rows together).
		sessionID: fmt.Sprintf("session-%d", time.Now().UnixNano()),
		path:      actualPath,
		lockFile:  lockFile,
	}

	// Seed the in-memory chain head from the most recent HASHED row so a
	// reopened log continues the existing chain. We must skip trailing rows
	// that carry no hash (rows written by a pre-chain binary, i.e. a version
	// downgrade, or a directly-inserted legacy row): seeding from such a tail
	// would reset headHash to empty and chain the next insert from genesis
	// even though earlier hashed rows exist — which VerifyChain (it skips
	// hashless rows and keeps the running prevHash) would then report as a
	// false break on an untampered log. When there is no hashed row at all
	// (fresh or all-legacy log) the query returns nothing and headHash stays
	// empty, correctly starting a new chain.
	var head sql.NullString
	if qerr := db.QueryRow(`SELECT entry_hash FROM audit_log
		WHERE entry_hash IS NOT NULL AND entry_hash <> ''
		ORDER BY id DESC LIMIT 1`).Scan(&head); qerr == nil && head.Valid {
		l.headHash = head.String
	}

	return l, nil
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
		// Build the fallback row via json.Marshal so control bytes
		// in the error string survive as JSON-valid escapes
		// (\u00NN) rather than Go-string escapes (\a, \v, \xNN)
		// that downstream parsers reject. Pre-v0.150 the fallback
		// used `fmt.Sprintf("%q", err.Error())`, which is
		// strconv.Quote semantics — perfectly valid Go but invalid
		// JSON for any control byte outside the {\b \f \n \r \t}
		// whitelist. A BEL (\x07) in an err message landed as `\a`
		// and corrupted the audit row.
		fbBytes, mErr := json.Marshal(map[string]string{"_marshal_error": err.Error()})
		if mErr != nil {
			// Marshal of a map[string]string with a UTF-8 error
			// string can't actually fail under encoding/json, but
			// fall back to a hardcoded constant so the audit row
			// always carries some sentinel rather than empty.
			fbBytes = []byte(`{"_marshal_error":"unrenderable"}`)
		}
		inputJSON = fbBytes
	}

	// Truncate long outputs for storage. UTF-8-aware: when the cap
	// lands in the middle of a multi-byte rune we walk back to the
	// previous rune start so the audit row stays valid UTF-8 — the
	// web UI and /report renderer otherwise show U+FFFD or reject
	// the row outright. Mirrors the discipline in
	// session.clipTitle / generate.capSize / agent.truncatePreview.
	if len(output) > 65535 {
		cut := 65535
		for cut > 0 && output[cut]&0xC0 == 0x80 {
			cut--
		}
		output = output[:cut] + "... [truncated]"
	}

	ts := time.Now().UTC()
	tsStr := ts.Format(time.RFC3339)
	durMs := duration.Milliseconds()

	// Tamper-evidence: chain each row's hash onto the previous one's, so a
	// post-hoc edit, mid-deletion, reorder, or forged insert into the DB
	// breaks the chain at VerifyChain time. writeMu makes the
	// read-head/compute/insert/update-head sequence atomic within the
	// process; the flock keeps it single-writer across processes.
	l.writeMu.Lock()
	entryHash := chainHash(l.headHash, tsStr, tool, string(inputJSON), output, risk, string(level), l.sessionID, durMs, success)
	_, err = l.db.Exec(`
		INSERT INTO audit_log (timestamp, tool, input, output, risk, level, session_id, duration_ms, success, entry_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tsStr,
		tool,
		string(inputJSON),
		output,
		risk,
		string(level),
		l.sessionID,
		durMs,
		success,
		entryHash,
	)
	if err == nil {
		l.headHash = entryHash
	}
	l.writeMu.Unlock()
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
	var pctx PersonaContext
	if l.personaResolve != nil {
		pctx = l.personaResolve()
	}
	l.notify(Entry{
		Timestamp:      ts,
		Tool:           tool,
		Input:          string(inputJSON),
		Output:         output,
		Risk:           risk,
		Level:          level,
		SessionID:      l.sessionID,
		Duration:       duration.Milliseconds(),
		Success:        success,
		TraceID:        traceID,
		TechniqueIDs:   techs,
		PersonaVersion: pctx.PersonaVersion,
		PromptHash:     pctx.PromptHash,
	})
}

// SetTechniqueResolver installs the ATT&CK tool-to-technique mapping
// used to populate Entry.TechniqueIDs. Pass nil to disable. Safe to
// call from setup code before Record begins; callers during Record
// accept the race (the next entry picks up the new resolver).
func (l *Log) SetTechniqueResolver(fn TechniqueResolver) {
	l.techResolve = fn
}

// SetPersonaContextResolver installs the per-session hook used to
// populate Entry.PersonaVersion + Entry.PromptHash on each audit row
// (P3-31). Pass nil to disable. The same race-tolerance contract as
// SetTechniqueResolver — call once at agent startup; mid-session
// persona switches simply update the closure the agent installs.
func (l *Log) SetPersonaContextResolver(fn PersonaContextResolver) {
	l.personaResolve = fn
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
					obs.Default().Error("audit_observer_panicked",
						"recovered", fmt.Sprintf("%v", r),
						"stack", string(debug.Stack()))
				}
			}()
			fn(e)
		}()
	}
}

func (l *Log) Query(limit int) ([]Entry, error) {
	// Clamp at the package boundary instead of trusting callers.
	// SQLite treats `LIMIT -1` (or any negative) as "no upper bound",
	// so a caller passing limit=-1 — e.g. an LLM tool call with
	// `{"limit": -1}` reaching the audit_query handler in
	// internal/tools/audit.go, which only guards `> MaxQueryLimit` —
	// would otherwise dump the entire audit DB and bypass the cap
	// the const's docstring promises. Defaulting <=0 to 100 mirrors
	// QueryFiltered; the upper cap is the documented limit.
	if limit <= 0 {
		limit = 100
	}
	if limit > MaxQueryLimit {
		limit = MaxQueryLimit
	}
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

// likeEscape escapes the SQL LIKE metacharacters so a filter value matches
// literally. Without this, a "%" or "_" in operator input acts as a wildcard:
// a forensic search for tool "nfc_detect" would also match "nfcXdetect",
// silently over-including rows in evidence retrieval. The backslash is the
// escape character (declared via ESCAPE '\' on each LIKE clause) and so must
// be escaped first. Values are still bound as parameters — this is about match
// semantics, not injection.
func likeEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
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
		clauses = append(clauses, `tool LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(f.Tool)+"%")
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
		clauses = append(clauses, `(input LIKE ? ESCAPE '\' OR output LIKE ? ESCAPE '\')`)
		esc := "%" + likeEscape(f.Contains) + "%"
		args = append(args, esc, esc)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	// Same upper-bound enforcement as Query — the HTTP handler 400s on
	// limit > MaxQueryLimit today, but a future in-process caller that
	// constructs Filter directly shouldn't be able to bypass the cap.
	if limit > MaxQueryLimit {
		limit = MaxQueryLimit
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
			obs.Default().Warn("audit_row_scan_failed", "where", "QuerySince", "after_id", afterID, "err", err)
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
	// Ensure the marshalled body is always a JSON array, even for an
	// empty session. json.MarshalIndent on a nil slice returns the
	// literal "null", which forces every downstream consumer
	// (cockpit, report generator, CLI `/audit export`) to special-case
	// the empty-session path. Substituting an empty []Entry preserves
	// the array shape so callers can iterate unconditionally.
	if entries == nil {
		entries = []Entry{}
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ExportCSV returns the current session's audit entries as CSV text
// suitable for spreadsheet import or SIEM ingestion. Columns match
// the JSON Export field names. Values containing commas, quotes, or
// newlines are quoted per RFC 4180.
func (l *Log) ExportCSV() (string, error) {
	entries, err := l.QueryBySession(l.sessionID)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString("id,timestamp,tool,input,output,risk,level,session_id,duration_ms,success\n")
	for _, e := range entries {
		fmt.Fprintf(&sb, "%d,%s,%s,%s,%s,%s,%s,%s,%d,%t\n",
			e.ID,
			csvQuote(e.Timestamp.UTC().Format(time.RFC3339)),
			csvQuote(e.Tool),
			csvQuote(e.Input),
			csvQuote(e.Output),
			csvQuote(e.Risk),
			csvQuote(string(e.Level)),
			csvQuote(e.SessionID),
			e.Duration,
			e.Success,
		)
	}
	return sb.String(), nil
}

func csvQuote(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func (l *Log) Stats() (string, error) {
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

	var sb strings.Builder
	fmt.Fprintf(&sb, "Session: %s\nTotal actions: %d\nSuccessful: %d\nFailed: %d\nUnique tools: %d",
		l.sessionID, total, success, failed, tools)

	rows, err := l.db.Query(`
		SELECT COALESCE(risk,''), COUNT(*)
		FROM audit_log WHERE session_id = ?
		GROUP BY risk ORDER BY COUNT(*) DESC`, l.sessionID)
	if err == nil {
		defer rows.Close()
		first := true
		for rows.Next() {
			var r string
			var c int
			if rows.Scan(&r, &c) != nil {
				continue
			}
			if first {
				sb.WriteString("\nRisk breakdown:")
				first = false
			}
			if r == "" {
				r = "unset"
			}
			fmt.Fprintf(&sb, " %s=%d", r, c)
		}
	}

	return sb.String(), nil
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
