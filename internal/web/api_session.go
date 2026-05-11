// Persisted-session HTTP surface. Adapts agent.Agent's session store onto
// JSON endpoints the cockpit sidebar consumes — list, get-transcript,
// resume, rename, delete, plus a "new session" action. Every handler
// returns 503 when SetSessionDriver hasn't been called so the frontend
// can hide the sidebar uniformly.
//
// Resume / new / rename / delete also broadcast `session_list_changed`
// (and `session_switched` on resume) so peer tabs follow the active
// conversation without polling.

package web

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/session"
)

// sessionListEntry is the sidebar payload shape — id, display title (with
// a derived fallback), timestamps, and a coarse turn count so the row can
// show "12 turns · 5m ago".
type sessionListEntry struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Model     string    `json:"model"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Messages  int       `json:"messages"`
	Active    bool      `json:"active"`
}

// sessionDetail is the GET-by-id payload. The frontend reuses its live-stream
// rendering helpers on the Events array — see static/app.js renderTranscript.
type sessionDetail struct {
	sessionListEntry
	Events []agent.TranscriptEvent `json:"events"`
}

func (s *Server) handleSessionList(w http.ResponseWriter, _ *http.Request) {
	if s.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "session store not configured")
		return
	}
	states, err := s.sessions.ListSessions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	active := s.sessions.SessionID()
	out := make([]sessionListEntry, 0, len(states))
	for i := range states {
		out = append(out, listEntryFromState(&states[i], active))
	}
	// Newest first — matches Claude Desktop / ChatGPT sidebar ordering.
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	respondJSON(w, http.StatusOK, map[string]any{
		"active":   active,
		"sessions": out,
	})
}

func (s *Server) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "session store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}
	states, err := s.sessions.ListSessions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range states {
		if states[i].ID != id {
			continue
		}
		entry := listEntryFromState(&states[i], s.sessions.SessionID())
		respondJSON(w, http.StatusOK, sessionDetail{
			sessionListEntry: entry,
			Events:           agent.SessionTranscript(&states[i]),
		})
		return
	}
	writeError(w, http.StatusNotFound, fmt.Sprintf("session %q not found", id))
}

// handleSessionNew clears in-memory history and starts a fresh session id
// so the next user turn writes to a brand-new file. Broadcasts so peer
// tabs reset their transcript view.
func (s *Server) handleSessionNew(w http.ResponseWriter, _ *http.Request) {
	if s.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "session store not configured")
		return
	}
	id := s.sessions.NewSession()
	s.broadcast(map[string]any{
		"type":       "session_switched",
		"session_id": id,
		"fresh":      true,
	})
	s.broadcast(map[string]any{"type": "session_list_changed"})
	respondJSON(w, http.StatusOK, map[string]any{"id": id})
}

// handleSessionResume swaps the agent's in-memory history with the
// persisted state for id. Broadcasts session_switched so every connected
// tab reloads its transcript pane from /api/sessions/:id.
func (s *Server) handleSessionResume(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "session store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}
	if err := s.sessions.ResumeSession(id); err != nil {
		// Same classification rule as PATCH/DELETE (v0.108–v0.109):
		// NotExist → 404 (the operator typed an id that isn't on
		// disk); anything else → 500 (parse error in the saved
		// state, I/O failure mid-load, etc.). Pre-v0.110 every
		// ResumeSession error became a 404, so a corrupt session
		// file looked indistinguishable from a typo.
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.broadcast(map[string]any{
		"type":       "session_switched",
		"session_id": id,
		"fresh":      false,
	})
	s.broadcast(map[string]any{"type": "session_list_changed"})
	respondJSON(w, http.StatusOK, map[string]any{"id": id})
}

// handleSessionPatch updates mutable session metadata. Only `title` is
// supported today; future fields can join the same body shape without
// breaking older clients.
func (s *Server) handleSessionPatch(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "session store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}
	var body struct {
		Title *string `json:"title,omitempty"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Title == nil {
		writeError(w, http.StatusBadRequest, "no fields to update")
		return
	}
	title := strings.TrimSpace(*body.Title)
	if err := s.sessions.RenameSession(id, title); err != nil {
		// "not found" stays 404 (typical case: typo'd id); real
		// I/O errors map to 500 so the cockpit can show a
		// different message. Pre-v0.109 every RenameSession error
		// became a 404 — operators couldn't tell disk-full from
		// "the id you typed doesn't exist".
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.broadcast(map[string]any{"type": "session_list_changed"})
	respondJSON(w, http.StatusOK, map[string]any{"id": id, "title": title})
}

func (s *Server) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "session store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}
	if err := s.sessions.DeleteSession(id); err != nil {
		// Map "file does not exist" to 404 (typo'd id) instead of
		// 500 (real I/O failure). Pre-v0.109 every DeleteSession
		// error became a 500, so the cockpit couldn't distinguish
		// "you spelled the id wrong" from "disk is failing".
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Deleting the active session implicitly transitions to a fresh one
	// so subsequent turns don't keep writing into the just-deleted file.
	if id == s.sessions.SessionID() {
		newID := s.sessions.NewSession()
		s.broadcast(map[string]any{
			"type":       "session_switched",
			"session_id": newID,
			"fresh":      true,
		})
	}
	s.broadcast(map[string]any{"type": "session_list_changed"})
	respondJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// listEntryFromState converts an on-disk session.State into the wire-shape
// the cockpit consumes. When the persisted title is blank — pre-existing
// files predate the Title field, brand-new sessions haven't autosaved
// yet — fall back to a derivation over the saved messages so the
// sidebar shows a meaningful preview without rewriting disk.
func listEntryFromState(state *session.State, activeID string) sessionListEntry {
	title := strings.TrimSpace(state.Title)
	if title == "" {
		title = agent.DeriveTitleFromMessages(state.Messages)
	}
	return sessionListEntry{
		ID:        state.ID,
		Title:     title,
		Model:     state.Model,
		CreatedAt: state.CreatedAt,
		UpdatedAt: state.UpdatedAt,
		Messages:  len(state.Messages),
		Active:    state.ID == activeID,
	}
}
