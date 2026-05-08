// Package snapshot captures pre-write copies of Flipper SD files so
// /rewind can restore them on demand. Snapshots are small (SD files
// rarely exceed a few hundred KB) and are grouped per-session so the
// retention story is trivial: the next session doesn't see the
// previous session's undo history.
//
// Layout under $SNAPSHOT_DIR/<session>/:
//
//	20260422T091530-abcdef.bak      — the raw pre-write contents
//	20260422T091530-abcdef.json     — metadata (original path, sha256)
//
// The snapshot dir defaults to ~/.promptzero/snapshots but can be
// overridden at construction time for tests.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/obs"
)

// snapshotTimeLayout is a filesystem-safe timestamp format. RFC3339's
// colons break Windows paths, so we use a compact local form.
const snapshotTimeLayout = "20060102T150405"

// validSessionIDRE constrains session IDs to filesystem-safe identifiers.
// Required because Store / List / Restore / Purge / Rotate map id ->
// "<root>/<id>/...": a value containing "../" or "/" would let the
// caller escape the snapshot root. The agent's auto-generated session
// IDs and the session.Store's allow-list both match this pattern.
var validSessionIDRE = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`)

func validateSessionID(id string) error {
	if id == "" {
		return errors.New("snapshot: sessionID required")
	}
	if !validSessionIDRE.MatchString(id) {
		return fmt.Errorf("snapshot: invalid sessionID %q (allowed: letters, digits, _, -, .; max 128 chars; no path separators)", id)
	}
	return nil
}

// validateSnapshotID guards the second filepath.Join target — the
// snapshot id passed to Restore. Internally Store generates ids as
// "<timestamp>-<sha256>" (letters/digits/hyphen), so the same
// allow-list applies. Without this a caller could pass id="../foo"
// to escape the per-session dir even when the sessionID itself is
// sanitised.
func validateSnapshotID(id string) error {
	if id == "" {
		return errors.New("snapshot: id required")
	}
	if !validSessionIDRE.MatchString(id) {
		return fmt.Errorf("snapshot: invalid id %q (allowed: letters, digits, _, -, .; max 128 chars; no path separators)", id)
	}
	return nil
}

// Entry is the public metadata record for a saved snapshot. Exposed so
// /rewind list can render a table without re-parsing filenames.
type Entry struct {
	ID           string    `json:"id"`            // base filename without extension
	OriginalPath string    `json:"original_path"` // the Flipper path that was about to be overwritten
	TakenAt      time.Time `json:"taken_at"`      // wall-clock at snapshot time
	SizeBytes    int       `json:"size_bytes"`    // byte length of the captured content
	SHA256       string    `json:"sha256"`        // hex digest of the content
	DataFile     string    `json:"-"`             // absolute path to the .bak file (populated by List / Get)
}

// Manager owns the on-disk snapshot tree and provides Store / List /
// Restore primitives keyed by session ID. Safe for concurrent use —
// each method takes no cross-request state and the filesystem handles
// atomicity via rename.
type Manager struct {
	root string
}

// NewManager constructs a Manager rooted at the given directory. The
// root is created lazily on the first Store call so passing a
// non-existent dir is not an error (important for tests using
// t.TempDir paths that may not survive between runs).
func NewManager(root string) *Manager {
	return &Manager{root: root}
}

// DefaultRoot returns ~/.promptzero/snapshots.
func DefaultRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".promptzero", "snapshots"), nil
}

// Store records a snapshot of the given path + content under the
// specified session. Returns the Entry so callers can log the ID for
// later reference. content is copied into the snapshot tree
// verbatim — no compression (SD files are tiny) and no encryption
// (if the SD card held secrets the operator already authorised the
// agent's reading it).
func (m *Manager) Store(sessionID, originalPath string, content []byte) (Entry, error) {
	if err := validateSessionID(sessionID); err != nil {
		return Entry{}, err
	}
	if originalPath == "" {
		return Entry{}, errors.New("snapshot: originalPath required")
	}
	dir := filepath.Join(m.root, sessionID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Entry{}, fmt.Errorf("snapshot mkdir: %w", err)
	}

	sum := sha256.Sum256(content)
	id := fmt.Sprintf("%s-%s", time.Now().UTC().Format(snapshotTimeLayout), hex.EncodeToString(sum[:4]))

	dataPath := filepath.Join(dir, id+".bak")
	if err := writeAtomic(dataPath, content); err != nil {
		return Entry{}, err
	}

	entry := Entry{
		ID:           id,
		OriginalPath: originalPath,
		TakenAt:      time.Now(),
		SizeBytes:    len(content),
		SHA256:       hex.EncodeToString(sum[:]),
		DataFile:     dataPath,
	}
	metaPath := filepath.Join(dir, id+".json")
	metaBytes, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return Entry{}, fmt.Errorf("snapshot meta marshal: %w", err)
	}
	if err := writeAtomic(metaPath, metaBytes); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// List returns every snapshot recorded under the given session, newest
// first. Session directories that don't exist yet return an empty
// slice (not an error) so UI can render "no snapshots" cleanly.
func (m *Manager) List(sessionID string) ([]Entry, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
	dir := filepath.Join(m.root, sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		metaPath := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(metaPath)
		if err != nil {
			// Skip individual unreadable entries rather than failing the whole
			// list; surface the failure so a corrupt meta file is visible.
			obs.Default().Warn("snapshot_meta_read_failed", "session_id", sessionID, "file", e.Name(), "err", err)
			continue
		}
		var entry Entry
		if err := json.Unmarshal(raw, &entry); err != nil {
			obs.Default().Warn("snapshot_meta_parse_failed", "session_id", sessionID, "file", e.Name(), "err", err)
			continue
		}
		entry.DataFile = filepath.Join(dir, entry.ID+".bak")
		out = append(out, entry)
	}
	// Sort newest-first. The ID prefix is a timestamp so string-sort
	// is chronological.
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Restore reads the raw pre-write content for a given snapshot ID.
// Returns an error if the ID doesn't exist — callers are expected to
// pair this with a Flipper write to the entry's OriginalPath.
func (m *Manager) Restore(sessionID, id string) (Entry, []byte, error) {
	if err := validateSessionID(sessionID); err != nil {
		return Entry{}, nil, err
	}
	if err := validateSnapshotID(id); err != nil {
		return Entry{}, nil, err
	}
	dir := filepath.Join(m.root, sessionID)
	metaPath := filepath.Join(dir, id+".json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return Entry{}, nil, fmt.Errorf("snapshot meta %s: %w", id, err)
	}
	var entry Entry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return Entry{}, nil, fmt.Errorf("snapshot meta parse: %w", err)
	}
	dataPath := filepath.Join(dir, id+".bak")
	content, err := os.ReadFile(dataPath)
	if err != nil {
		return Entry{}, nil, fmt.Errorf("snapshot data %s: %w", id, err)
	}
	entry.DataFile = dataPath
	return entry, content, nil
}

// Purge removes every snapshot for a session. Intended for cleanup
// when a session is explicitly dropped; the per-session dir stays
// around on normal exit so /rewind still works across restarts.
func (m *Manager) Purge(sessionID string) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	dir := filepath.Join(m.root, sessionID)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DefaultRetention is the number of most-recent snapshots a session
// keeps when Rotate is called without an explicit value. Tuned for
// the typical pentest session (a few dozen write operations) with
// headroom — 100 entries at a mean of ~30 KB each is ~3 MB per
// session, trivial even on cramped SD cards. Longer sessions should
// Purge between phases or raise the keep value explicitly.
const DefaultRetention = 100

// Rotate trims the per-session snapshot tree down to the most recent
// 'keep' entries, deleting older .bak/.json pairs. Intended to run
// periodically (e.g. on session save, between workflow phases) so
// long-running sessions don't accumulate unbounded undo history.
//
// A keep value of 0 or negative defaults to DefaultRetention. The
// newest entries (highest timestamp-prefixed IDs) are preserved.
// Nothing is deleted when the current count is at or below keep.
//
// Returns the number of snapshots deleted. Missing session dirs are
// a no-op (returns 0, nil) — rotate is safe to call before any
// snapshots have landed.
func (m *Manager) Rotate(sessionID string, keep int) (int, error) {
	if keep <= 0 {
		keep = DefaultRetention
	}
	entries, err := m.List(sessionID)
	if err != nil {
		return 0, err
	}
	if len(entries) <= keep {
		return 0, nil
	}
	// List returns newest-first; drop everything past the keep index.
	toDelete := entries[keep:]
	dir := filepath.Join(m.root, sessionID)
	var deleted int
	for _, e := range toDelete {
		metaPath := filepath.Join(dir, e.ID+".json")
		dataPath := filepath.Join(dir, e.ID+".bak")
		// Order matters: remove data first, then meta. If data removal
		// fails we leave both files and the snapshot stays restorable.
		// If we removed meta first and then data failed, List() would
		// still hide it (no .json) but the data would orphan on disk
		// invisible to any cleanup. If meta removal then fails after
		// data succeeded the meta becomes a dangling pointer — List()
		// reads it and Restore fails — which is the worst-case UX
		// (snapshot visible but un-restorable). We mitigate by removing
		// meta after data and checking that error too.
		if err := os.Remove(dataPath); err != nil && !os.IsNotExist(err) {
			return deleted, fmt.Errorf("snapshot rotate %s: %w", e.ID, err)
		}
		if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
			return deleted, fmt.Errorf("snapshot rotate %s meta: %w", e.ID, err)
		}
		deleted++
	}
	return deleted, nil
}

// writeAtomic writes data to path via a sibling .tmp file + rename so
// a crash never leaves a truncated snapshot. The rename is atomic on
// POSIX; on Windows it's best-effort but still safer than direct
// writes.
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("snapshot tmp write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("snapshot rename: %w", err)
	}
	return nil
}
