// Screen-mirror WebSocket layer.
//
// Owns the screen_acquire / screen_release / screen_keepalive WS frames,
// the binary frame forwarder, the heartbeat, the single release funnel,
// and the refuseIfMirrorActive HTTP guard used by fs/input/device handlers.

package web

import (
	"context"
	"net/http"
	"time"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/flipper/rpc"
)

// screenClient is the narrow surface the web layer needs from an RPC client.
// *rpc.Client satisfies this interface naturally.
type screenClient interface {
	StartScreenStream(ctx context.Context) (<-chan rpc.ScreenFrame, error)
	StopScreenStream(ctx context.Context) error
	SendInput(ctx context.Context, button, event string) error
	Close() error
}

// flipperRPCProvider is the narrow surface Server needs from *flipper.Flipper
// for RPC mode. *flipper.Flipper does not satisfy it directly because its
// EnterRPC returns *rpc.Client (concrete) — wired via flipperRPCAdapter in
// SetFlipper.
type flipperRPCProvider interface {
	EnterRPC(ctx context.Context) (screenClient, func(), error)
}

// handleScreenAcquire processes a screen_acquire WS frame.
func (s *Server) handleScreenAcquire(c *sessionConn) {
	s.screenMu.Lock()
	if s.screenHolder != nil {
		s.screenMu.Unlock()
		s.sendTo(c, map[string]any{
			"type":              "screen_state",
			"active":            true,
			"holder_session_id": s.screenHolder.id,
			"reason":            "taken",
		})
		return
	}
	if s.flipperRPC == nil {
		s.screenMu.Unlock()
		s.sendTo(c, map[string]any{
			"type":    "screen_error",
			"code":    "no_device",
			"message": "no Flipper attached",
		})
		return
	}

	// Tentatively claim before EnterRPC so racing CLI calls fail fast.
	s.mirrorActive.Store(true)
	s.screenHolder = c
	s.screenMu.Unlock()

	streamCtx, cancel := context.WithCancel(context.Background())
	rpcClient, release, err := s.flipperRPC.EnterRPC(streamCtx)
	if err != nil {
		cancel()
		s.screenMu.Lock()
		s.screenHolder = nil
		s.screenMu.Unlock()
		s.mirrorActive.Store(false)
		s.sendTo(c, map[string]any{
			"type":    "screen_error",
			"code":    "rpc_open_failed",
			"message": err.Error(),
		})
		s.broadcast(map[string]any{
			"type":   "screen_state",
			"active": false,
			"reason": "open_failed",
		})
		return
	}

	s.screenMu.Lock()
	s.screenCancel = cancel
	s.screenRelease = release
	s.screenActiveRPC = rpcClient
	s.screenMu.Unlock()
	s.mirrorLastSeen.Store(time.Now().UnixNano())

	frames, err := rpcClient.StartScreenStream(streamCtx)
	if err != nil {
		s.releaseScreen("start_failed")
		return
	}

	s.broadcast(map[string]any{
		"type":              "screen_state",
		"active":            true,
		"holder_session_id": c.id,
		"reason":            "acquired",
	})
	s.screenAudit("web.screen.start", c.id, "", audit.LevelAction, "medium")

	go s.streamFrames(streamCtx, c, frames)
	go s.heartbeatScreen(streamCtx)
}

// handleScreenRelease processes a screen_release WS frame. Idempotent if not holder.
func (s *Server) handleScreenRelease(c *sessionConn) {
	s.screenMu.Lock()
	if s.screenHolder != c {
		s.screenMu.Unlock()
		return
	}
	s.screenMu.Unlock()
	s.releaseScreen("released")
}

// handleScreenKeepalive resets the heartbeat timer for the holder.
func (s *Server) handleScreenKeepalive(c *sessionConn) {
	s.screenMu.Lock()
	isHolder := s.screenHolder == c
	s.screenMu.Unlock()
	if isHolder {
		s.mirrorLastSeen.Store(time.Now().UnixNano())
	}
}

// handleScreenInput dispatches a button event to the firmware via the active
// RPC session. Only the screen holder may send input; non-holders are ignored
// silently. Validation happens server-side in *rpc.Client.SendInput.
func (s *Server) handleScreenInput(c *sessionConn, button, event string) {
	s.screenMu.Lock()
	cli := s.screenActiveRPC
	isHolder := s.screenHolder == c
	s.screenMu.Unlock()
	if !isHolder || cli == nil {
		return
	}
	if event == "" {
		event = "short"
	}
	if err := cli.SendInput(context.Background(), button, event); err != nil {
		s.sendTo(c, map[string]any{
			"type":    "screen_error",
			"code":    "input_failed",
			"message": err.Error(),
		})
	}
}

// releaseScreen is the single funnel for all release paths. It is idempotent:
// if the mirror is not active it returns immediately.
func (s *Server) releaseScreen(reason string) {
	s.screenMu.Lock()
	if s.screenHolder == nil {
		s.screenMu.Unlock()
		return
	}
	holderID := s.screenHolder.id
	cancel := s.screenCancel
	release := s.screenRelease
	s.screenHolder = nil
	s.screenCancel = nil
	s.screenRelease = nil
	s.screenActiveRPC = nil
	s.screenMu.Unlock()

	// Clear the fast-path guard before running the release closure so HTTP
	// handlers don't see a transient false-409 during the post-RPC handshake
	// recovery. CLI ops still block on f.mu until release() unlocks it.
	s.mirrorActive.Store(false)
	if cancel != nil {
		cancel()
	}
	if release != nil {
		release()
	}

	s.screenAudit("web.screen.stop", holderID, reason, audit.LevelInfo, "low")
	s.broadcast(map[string]any{
		"type":   "screen_state",
		"active": false,
		"reason": reason,
	})
}

// streamFrames drives the WS write. It keeps only the most recent frame
// when the writer is busy — the goal is lowest input-to-render latency,
// not delivering every frame.
func (s *Server) streamFrames(ctx context.Context, c *sessionConn, in <-chan rpc.ScreenFrame) {
	for {
		var pending rpc.ScreenFrame
		select {
		case <-ctx.Done():
			return
		case f, ok := <-in:
			if !ok {
				s.releaseScreen("transport_lost")
				return
			}
			pending = f
		}
		// Drain any further frames synchronously while we're already here,
		// keeping only the newest.
	drain:
		for {
			select {
			case f, ok := <-in:
				if !ok {
					s.releaseScreen("transport_lost")
					return
				}
				pending = f
			default:
				break drain
			}
		}
		buf := make([]byte, 1+len(pending.Pixels))
		buf[0] = 0x01
		copy(buf[1:], pending.Pixels)
		s.sendBinaryTo(c, buf)
	}
}

// heartbeatScreen auto-releases the mirror if the holder stops sending keepalives.
func (s *Server) heartbeatScreen(ctx context.Context) {
	const dead = 30 * time.Second
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			last := time.Unix(0, s.mirrorLastSeen.Load())
			if time.Since(last) > dead {
				s.releaseScreen("timeout")
				return
			}
		}
	}
}

// sendBinaryTo enqueues a binary WebSocket frame for delivery by runWriter.
// Drops the frame silently when the outBin queue is full (same policy as
// enqueue for text frames) — frames are disposable; the next one arrives.
func (s *Server) sendBinaryTo(c *sessionConn, data []byte) {
	select {
	case c.outBin <- data:
	default:
	}
}

// refuseIfMirrorActive writes a 409 Conflict response and returns true when
// the mirror is held. Callers should return immediately on true.
func (s *Server) refuseIfMirrorActive(w http.ResponseWriter) bool {
	if s.mirrorActive.Load() {
		respondJSON(w, http.StatusConflict, map[string]any{
			"error":               "flipper screen mirror is active",
			"code":                "mirror_active",
			"retry_after_release": true,
		})
		return true
	}
	return false
}

// screenAudit records a screen-mirror event. Skips silently when no log is configured.
func (s *Server) screenAudit(tool, holderID, reason string, level audit.Level, risk string) {
	if s.auditLog == nil {
		return
	}
	input := map[string]string{
		"session_id": s.auditLog.SessionID(),
		"holder_id":  holderID,
		"transport":  "rpc",
	}
	if reason != "" {
		input["reason"] = reason
	}
	s.auditLog.Record(tool, input, "", risk, level, 0, true)
}
