package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/voice"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	agent *agent.Agent
	voice *voice.Engine
	addr  string
	conns map[*websocket.Conn]bool
	mu    sync.Mutex
}

type wsMessage struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

// NewServer creates a web server bound to addr. If the host portion of addr
// is empty (":PORT") or the legacy hardcoded "0.0.0.0", the server defaults
// the bind to "127.0.0.1" and prints a one-line note to stderr explaining
// how to override via config.Web.Host. If the effective host is non-loopback,
// NewServer additionally prints a yellow warning on stderr: the web UI has
// no authentication, so a public bind must be explicit and visible.
func NewServer(addr string, ag *agent.Agent, v *voice.Engine) *Server {
	addr = applyLoopbackDefault(addr)
	return &Server{
		agent: ag,
		voice: v,
		addr:  addr,
		conns: make(map[*websocket.Conn]bool),
	}
}

// applyLoopbackDefault enforces the local-first bind default: empty or
// "0.0.0.0" hosts are rewritten to "127.0.0.1"; non-loopback hosts print a
// warning. Exposed at package scope (lowercase) so tests can exercise it.
func applyLoopbackDefault(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Unparseable — leave untouched, net/http will surface the error.
		return addr
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		effective := net.JoinHostPort("127.0.0.1", port)
		fmt.Fprintf(os.Stderr, "\x1b[33m●\x1b[0m Web UI defaulting to loopback (%s); set web.host in config to bind publicly\n", effective)
		return effective
	}
	if !isLoopback(host) {
		fmt.Fprintf(os.Stderr, "\x1b[33m●\x1b[0m Web UI bound to %s — accessible from the network without authentication (intended for local pentesting only)\n", net.JoinHostPort(host, port))
	}
	return addr
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("static files: %w", err)
	}

	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/ws", s.handleWebSocket)

	srv := &http.Server{Addr: s.addr, Handler: mux}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("PromptZero web UI: http://%s", s.addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		log.Printf("websocket accept: %v", err)
		return
	}
	defer conn.CloseNow()

	conn.SetReadLimit(10 * 1024 * 1024) // 10MB max message

	s.mu.Lock()
	s.conns[conn] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()

	if err := s.sendJSON(conn, wsMessage{Type: "status", Content: "connected"}); err != nil {
		return
	}

	ctx := r.Context()

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}

		var msg wsMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			if err := s.sendJSON(conn, wsMessage{Type: "error", Content: "invalid message format"}); err != nil {
				return
			}
			continue
		}

		switch msg.Type {
		case "text":
			s.handleText(ctx, conn, msg.Content)
		case "audio":
			s.handleAudio(ctx, conn, msg.Content)
		case "reset":
			s.agent.Reset()
			if err := s.sendJSON(conn, wsMessage{Type: "status", Content: "conversation reset"}); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleText(ctx context.Context, conn *websocket.Conn, text string) {
	if err := s.sendJSON(conn, wsMessage{Type: "status", Content: "thinking"}); err != nil {
		return
	}

	response, err := s.agent.Run(ctx, text)
	if err != nil {
		if err := s.sendJSON(conn, wsMessage{Type: "error", Content: err.Error()}); err != nil {
			return
		}
		return
	}

	if err := s.sendJSON(conn, wsMessage{Type: "response", Content: response}); err != nil {
		return
	}
}

func (s *Server) handleAudio(ctx context.Context, conn *websocket.Conn, audioBase64 string) {
	if s.voice == nil {
		if err := s.sendJSON(conn, wsMessage{Type: "error", Content: "voice not configured — set OPENAI_API_KEY"}); err != nil {
			return
		}
		return
	}

	if err := s.sendJSON(conn, wsMessage{Type: "status", Content: "transcribing"}); err != nil {
		return
	}

	// Strip data URL prefix if present (e.g. "data:audio/webm;base64,...")
	raw := audioBase64
	if idx := strings.Index(raw, ","); idx >= 0 {
		raw = raw[idx+1:]
	}

	audioBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if err := s.sendJSON(conn, wsMessage{Type: "error", Content: "invalid audio data"}); err != nil {
			return
		}
		return
	}

	text, err := s.voice.TranscribeReader(bytes.NewReader(audioBytes), "recording.webm")
	if err != nil {
		if err := s.sendJSON(conn, wsMessage{Type: "error", Content: fmt.Sprintf("transcription failed: %v", err)}); err != nil {
			return
		}
		return
	}

	if err := s.sendJSON(conn, wsMessage{Type: "transcription", Content: text}); err != nil {
		return
	}
	s.handleText(ctx, conn, text)
}

func (s *Server) sendJSON(conn *websocket.Conn, msg wsMessage) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, data)
}
