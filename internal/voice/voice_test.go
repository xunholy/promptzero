package voice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAvailableFalseWithoutRec asserts that Available() returns false when
// the 'rec' binary is absent from PATH.  t.Setenv restores the original
// PATH value after the test so other tests are unaffected.
func TestAvailableFalseWithoutRec(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir — no executables present
	if Available() {
		t.Error("Available() should return false when rec is absent from PATH")
	}
}

// TestWhisperTimeoutRespected verifies that TranscribeReader uses the
// scoped HTTP client (not http.DefaultClient) and therefore respects the
// configured timeout rather than blocking forever.
func TestWhisperTimeoutRespected(t *testing.T) {
	// Delay longer than the client timeout — simulates an unresponsive API.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	defer ts.Close()

	e := &Engine{
		apiKey:     "test-key",
		model:      "whisper-1",
		whisperURL: ts.URL,
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
	}

	_, err := e.TranscribeReader(strings.NewReader("audio"), "test.wav")
	if err == nil {
		t.Fatal("expected timeout error from hanging Whisper server, got nil")
	}
}

// TestTranscribeReaderCtx_CancellationAbortsRequest verifies that
// cancelling the caller's ctx interrupts a slow Whisper request — what
// the REPL relies on so Ctrl+C during a stuck transcription returns
// immediately rather than waiting for the HTTP client's 60s timeout.
//
// Server delays its response by 2 seconds; client cancels after 50ms.
// If TranscribeReaderCtx honours ctx the client returns < 1s; if not
// the test's deadline catches the regression at the 1s threshold.
func TestTranscribeReaderCtx_CancellationAbortsRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
			_ = json.NewEncoder(w).Encode(map[string]string{"text": "too late"})
		}
	}))
	defer ts.Close()

	e := &Engine{
		apiKey:     "test-key",
		model:      "whisper-1",
		whisperURL: ts.URL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.TranscribeReaderCtx(ctx, strings.NewReader("audio"), "test.wav")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected cancellation error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "context") {
		t.Errorf("error should reflect ctx cancellation, got: %v", err)
	}
	if elapsed > 1*time.Second {
		t.Errorf("cancellation took %s, want < 1s — ctx likely not honoured", elapsed)
	}
}

// TestTranscribeReaderParsesResponse verifies the happy path: a mock
// Whisper server returns valid JSON and TranscribeReader returns the text.
func TestTranscribeReaderParsesResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"text": "hello world"}); err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer ts.Close()

	e := &Engine{
		apiKey:     "test-key",
		model:      "whisper-1",
		whisperURL: ts.URL,
	}

	text, err := e.TranscribeReader(strings.NewReader("audio data"), "test.wav")
	if err != nil {
		t.Fatalf("TranscribeReader: %v", err)
	}
	if text != "hello world" {
		t.Errorf("text = %q, want %q", text, "hello world")
	}
}
