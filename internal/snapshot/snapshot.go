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
	"sort"
	"strings"
	"time"
)

// snapshotTimeLayout is a filesystem-safe timestamp format. RFC3339's
// colons break Windows paths, so we use a compact local form.
const snapshotTimeLayout = "20060102T150405"

// Entry is the public metadata record for a saved snapshot. Exposed so
// /rewind list can render a table without re-parsing filenames.
type Entry struct {
	ID           string    `json:"id"`             // base filename without extension
	OriginalPath string    `json:"original_path"`  // the Flipper path that was about to be overwritten
	TakenAt      time.Time `json:"taken_at"`       // wall-clock at snapshot time
	SizeBytes    int       `json:"size_bytes"`     // byte length of the captured content
	SHA256       string    `json:"sha256"`         // hex digest of the content
	DataFile     string    `json:"-"`              // absolute path to the .bak file (populated by List / Get)
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
	if sessionID == "" {
		return Entry{}, errors.New("snapshot: sessionID required")
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
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // skip individual unreadable entries rather than failing the whole list
		}
		var entry Entry
		if err := json.Unmarshal(raw, &entry); err != nil {
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
	if id == "" {
		return Entry{}, nil, errors.New("snapshot: id required")
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
	dir := filepath.Join(m.root, sessionID)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
