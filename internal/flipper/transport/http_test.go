package transport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBridge is a minimal in-memory FlipperHTTP-style bridge used by the
// unit tests below. It supports POST /uart/send (queues bytes for the
// next recv) and GET /uart/recv (drains the queue, optionally honouring
// the timeout_ms long-poll).
type fakeBridge struct {
	t           *testing.T
	send        chan []byte
	recvBuffer  []byte
	requireAuth string
	recvCount   atomic.Int64
	sendCount   atomic.Int64
}

func newFakeBridge(t *testing.T) *fakeBridge {
	return &fakeBridge{t: t, send: make(chan []byte, 16)}
}

func (b *fakeBridge) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/uart/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if b.requireAuth != "" && r.Header.Get("Authorization") != "Bearer "+b.requireAuth {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		b.send <- body
		b.sendCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/uart/recv", func(w http.ResponseWriter, r *http.Request) {
		if b.requireAuth != "" && r.Header.Get("Authorization") != "Bearer "+b.requireAuth {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		b.recvCount.Add(1)
		if len(b.recvBuffer) == 0 {
			// Honour client's timeout_ms long-poll window.
			ms := r.URL.Query().Get("timeout_ms")
			if ms != "" {
				select {
				case data := <-b.send:
					b.recvBuffer = append(b.recvBuffer, data...)
				case <-time.After(50 * time.Millisecond):
					// fall through with empty buffer
				}
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if len(b.recvBuffer) > 0 {
			_, _ = w.Write(b.recvBuffer)
			b.recvBuffer = nil
		}
	})
	return mux
}

func TestHTTPDialer(t *testing.T) {
	bridge := newFakeBridge(t)
	srv := httptest.NewServer(bridge.handler())
	defer srv.Close()

	tr, err := Open(srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()

	if got := tr.Kind(); got != "http" {
		t.Errorf("Kind = %q, want http", got)
	}
	if !strings.HasPrefix(tr.Identity(), "http://") {
		t.Errorf("Identity = %q, want http:// prefix", tr.Identity())
	}

	if err := tr.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
}

func TestHTTPRoundTrip(t *testing.T) {
	bridge := newFakeBridge(t)
	srv := httptest.NewServer(bridge.handler())
	defer srv.Close()

	tr, err := Open(srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	if err := tr.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Write some bytes — they'll show up in the next recv.
	want := []byte("device_info\n")
	n, err := tr.Write(want)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(want) {
		t.Errorf("Write n = %d, want %d", n, len(want))
	}

	// Read should see those same bytes.
	buf := make([]byte, 64)
	got, err := tr.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:got]) != string(want) {
		t.Errorf("Read got %q, want %q", string(buf[:got]), string(want))
	}
}

func TestHTTPReadDrainsPending(t *testing.T) {
	bridge := newFakeBridge(t)
	srv := httptest.NewServer(bridge.handler())
	defer srv.Close()

	tr, err := Open(srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	if err := tr.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if _, err := tr.Write([]byte("12345678901234567890")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read in 5-byte chunks; the first call hits the network, subsequent
	// calls drain pending without an extra request.
	preCount := bridge.recvCount.Load()
	chunk := make([]byte, 5)
	got := ""
	for i := 0; i < 4; i++ {
		n, err := tr.Read(chunk)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		got += string(chunk[:n])
	}
	postCount := bridge.recvCount.Load()
	if got != "12345678901234567890" {
		t.Errorf("recovered %q, want %q", got, "12345678901234567890")
	}
	// Probe (Dial) + first Read = 2 network hits at most.
	if postCount-preCount > 1 {
		t.Errorf("too many recv hits: %d (want at most 1 for pending-drain)", postCount-preCount)
	}
}

func TestHTTPAuthToken(t *testing.T) {
	bridge := newFakeBridge(t)
	bridge.requireAuth = "secret-token"
	srv := httptest.NewServer(bridge.handler())
	defer srv.Close()

	// Without token — should fail.
	tr, err := Open(srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	if err := tr.Dial(context.Background()); err == nil {
		t.Errorf("expected dial to fail without token")
	}

	// With token — should succeed.
	tr2, err := Open(srv.URL + "?token=secret-token")
	if err != nil {
		t.Fatalf("Open w/ token: %v", err)
	}
	defer tr2.Close()
	if err := tr2.Dial(context.Background()); err != nil {
		t.Errorf("Dial w/ token: %v", err)
	}
}

func TestHTTPCustomPaths(t *testing.T) {
	bridge := newFakeBridge(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/cli/send", func(w http.ResponseWriter, _ *http.Request) {
		bridge.sendCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/cli/recv", func(w http.ResponseWriter, _ *http.Request) {
		bridge.recvCount.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tr, err := Open(srv.URL + "?send_path=/api/cli/send&recv_path=/api/cli/recv")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	if err := tr.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := tr.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if bridge.sendCount.Load() != 1 {
		t.Errorf("send count = %d, want 1 (custom path not hit)", bridge.sendCount.Load())
	}
}

func TestHTTPCloseIdempotent(t *testing.T) {
	srv := httptest.NewServer(newFakeBridge(t).handler())
	defer srv.Close()

	tr, err := Open(srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := tr.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if err := tr.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	// Read after close → ErrClosedPipe.
	if _, err := tr.Read(make([]byte, 4)); err != io.ErrClosedPipe {
		t.Errorf("Read after Close = %v, want ErrClosedPipe", err)
	}
}

func TestHTTPSetReadTimeout(t *testing.T) {
	srv := httptest.NewServer(newFakeBridge(t).handler())
	defer srv.Close()

	tr, err := Open(srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	if err := tr.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := tr.SetReadTimeout(123 * time.Millisecond); err != nil {
		t.Errorf("SetReadTimeout: %v", err)
	}
	if err := tr.SetReadTimeout(-1); err == nil {
		t.Errorf("SetReadTimeout(-1) should error")
	}
}

func TestHTTPInvalidURL(t *testing.T) {
	if _, err := Open("http://"); err == nil {
		t.Errorf("expected error for empty host")
	}
	if _, err := Open("http://x?timeout_ms=abc"); err == nil {
		t.Errorf("expected error for invalid timeout_ms")
	}
	if _, err := Open("http://x?batch=-1"); err == nil {
		t.Errorf("expected error for invalid batch")
	}
}

// TestHTTPRecvResponseSizeCap exercises the load-bearing safety
// check: a misbehaving / compromised proxy that ignores the
// `?max=batch` hint and returns a giant body must not buffer
// without bound into t.pending. The cap fires at
// maxHTTPRecvResponseBytes and the caller sees a clear refusal.
func TestHTTPRecvResponseSizeCap(t *testing.T) {
	mux := http.NewServeMux()
	// Probe must succeed so Dial doesn't reject the transport before
	// our oversized recv ever fires.
	probed := false
	mux.HandleFunc("/uart/recv", func(w http.ResponseWriter, r *http.Request) {
		if !probed {
			probed = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Stream maxHTTPRecvResponseBytes+1024 bytes so the cap fires.
		buf := make([]byte, 4096)
		for i := range buf {
			buf[i] = 'A'
		}
		written := 0
		for written < maxHTTPRecvResponseBytes+1024 {
			n, err := w.Write(buf)
			if err != nil {
				return
			}
			written += n
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tr, err := Open(srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	if err := tr.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	buf := make([]byte, 4096)
	_, err = tr.Read(buf)
	if err == nil {
		t.Fatal("expected error on oversized recv body")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error %q should mention size cap", err.Error())
	}
}

func TestHTTPRejectsUnknownStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/uart/recv", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal", http.StatusInternalServerError)
	})
	mux.HandleFunc("/uart/send", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tr, err := Open(srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	if err := tr.Dial(context.Background()); err == nil {
		t.Errorf("expected error for 500 probe")
	}
}

// TestHTTPDialer_RejectsOverCapBatch pins the ceiling enforcement
// the maxHTTPRecvResponseBytes constant has always promised:
// "configurable via ?batch=N up to this ceiling". Pre-this-fix the
// dialer accepted any positive int, and the resulting transport
// then failed every Read with "response exceeded cap" — the dial
// succeeded but the transport was unusable.
//
// 16 MiB is the ceiling today. Configuring batch=20MiB now fails
// at dial time with a clear ceiling-exceeded error instead.
func TestHTTPDialer_RejectsOverCapBatch(t *testing.T) {
	overCap := maxHTTPRecvResponseBytes + 1
	url := fmt.Sprintf("http://127.0.0.1:1?batch=%d", overCap)
	_, err := Open(url)
	if err == nil {
		t.Fatalf("Open with batch=%d (over %d-byte ceiling) should have failed", overCap, maxHTTPRecvResponseBytes)
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Errorf("error message missing ceiling diagnostic: %v", err)
	}
}

// TestHTTPDialer_AcceptsAtCapBatch confirms the boundary is
// inclusive — batch=ceiling exactly is allowed. The fix uses a
// strict `>` check, not `>=`, so this exercises the off-by-one.
func TestHTTPDialer_AcceptsAtCapBatch(t *testing.T) {
	url := fmt.Sprintf("http://127.0.0.1:1?batch=%d", maxHTTPRecvResponseBytes)
	tr, err := Open(url)
	if err != nil {
		t.Fatalf("Open with batch=%d (at ceiling) should succeed: %v", maxHTTPRecvResponseBytes, err)
	}
	defer tr.Close()
}
