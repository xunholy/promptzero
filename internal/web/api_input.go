//go:build linux

// Flipper Zero input-send REST handler — /api/input/send.

package web

import (
	"encoding/json"
	"net/http"
)

var validInputButtons = map[string]struct{}{
	"up": {}, "down": {}, "left": {}, "right": {}, "ok": {}, "back": {},
}

var validInputEventTypes = map[string]struct{}{
	"press": {}, "release": {}, "short": {}, "long": {},
}

// handleInputSend drives a synthetic button event on the connected Flipper.
// Body: {"button": "ok", "event_type": "short"}
func (s *Server) handleInputSend(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "flipper not connected")
		return
	}
	if s.refuseIfMirrorActive(w) {
		return
	}
	var body struct {
		Button    string `json:"button"`
		EventType string `json:"event_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if _, ok := validInputButtons[body.Button]; !ok {
		writeError(w, http.StatusBadRequest, "invalid button: must be one of up, down, left, right, ok, back")
		return
	}
	if _, ok := validInputEventTypes[body.EventType]; !ok {
		writeError(w, http.StatusBadRequest, "invalid event_type: must be one of press, release, short, long")
		return
	}
	if _, err := s.flipper.InputSend(body.Button, body.EventType); err != nil {
		if isFAPBusy(err) {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.fsAudit("web.input.send", body.Button+"/"+body.EventType)
	respondJSON(w, http.StatusOK, map[string]any{
		"button":     body.Button,
		"event_type": body.EventType,
	})
}
