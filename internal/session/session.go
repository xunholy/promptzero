package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Message captures one entry of conversation history. Content is a
// human-readable preview; Raw carries the full JSON of the underlying
// anthropic.MessageParam (including tool_use and tool_result blocks) so
// that resuming a session leaves the model-visible history byte-identical
// to what was sent originally.
type Message struct {
	Role    string          `json:"role"`
	Content string          `json:"content,omitempty"`
	Raw     json.RawMessage `json:"raw,omitempty"`
}

type State struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Messages  []Message `json:"messages"`
	Model     string    `json:"model"`
	Notes     string    `json:"notes,omitempty"`
}

type Store struct {
	dir string
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating session dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Save(state *State) error {
	state.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}

	// Atomic write: stage into a sibling .tmp file, then rename. This avoids
	// leaving a truncated/partially-written session on disk if we crash or
	// the process is killed mid-write.
	path := filepath.Join(s.dir, state.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing session tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming session: %w", err)
	}
	return nil
}

func (s *Store) Load(id string) (*State, error) {
	path := filepath.Join(s.dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading session %s: %w", id, err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing session: %w", err)
	}
	return &state, nil
}

func (s *Store) List() ([]State, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	var sessions []State
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		id := e.Name()[:len(e.Name())-5]
		state, err := s.Load(id)
		if err != nil {
			continue
		}
		sessions = append(sessions, *state)
	}
	return sessions, nil
}

func (s *Store) Delete(id string) error {
	path := filepath.Join(s.dir, id+".json")
	return os.Remove(path)
}

func (s *Store) Latest() (*State, error) {
	sessions, err := s.List()
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("no saved sessions")
	}

	latest := sessions[0]
	for _, sess := range sessions[1:] {
		if sess.UpdatedAt.After(latest.UpdatedAt) {
			latest = sess
		}
	}
	return &latest, nil
}
