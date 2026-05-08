package voice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Engine struct {
	apiKey     string
	model      string
	whisperURL string
	// httpClient is the Whisper API client. Constructed once in New()
	// with a 60-second timeout; tests can override the field directly
	// when they construct Engine via the literal (matches existing
	// test pattern at internal/voice/voice_test.go).
	httpClient *http.Client
}

// client returns the configured HTTP client. Kept as a method so a
// future variant (e.g. per-request middleware) has a single edit
// point. The lazy fallback for nil httpClient remains as a safety net
// for code that bypasses New() and forgets to set the field.
func (e *Engine) client() *http.Client {
	if e.httpClient != nil {
		return e.httpClient
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func New(openAIKey string) *Engine {
	return &Engine{
		apiKey:     openAIKey,
		model:      "whisper-1",
		whisperURL: "https://api.openai.com/v1/audio/transcriptions",
		// Cache the production client so each Transcribe call doesn't
		// build a fresh http.Client. Tests construct &Engine{...}
		// directly with a custom httpClient and skip this default.
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// recordTimeout caps how long a silence-stop recording can run before
// we kill the `rec` process. Without it, a stuck mic / driver issue
// could wedge the REPL indefinitely waiting on rec to detect silence
// that will never arrive. Two minutes is generous for a voice prompt
// (operator-empath finding: most prompts are 5–15 seconds) and tight
// enough that a hang surfaces before the operator gives up.
const recordTimeout = 2 * time.Minute

// Record captures audio from the microphone using sox. Equivalent to
// RecordCtx with context.Background(); kept for back-compat.
//
// Deprecated: prefer RecordCtx so the REPL's turn ctx can abort a stuck
// recording (Ctrl+C cancels mid-flight instead of waiting for silence).
func (e *Engine) Record(outPath string) error {
	return e.RecordCtx(context.Background(), outPath)
}

// RecordCtx captures audio from the microphone using sox until the
// silence detector fires or the recordTimeout fallback expires. The
// caller's ctx is honoured: cancelling it kills the rec process.
// Records 16kHz mono WAV, stops after 1s of silence.
func (e *Engine) RecordCtx(ctx context.Context, outPath string) error {
	args := []string{
		"-r", "16000",
		"-c", "1",
		"-b", "16",
		outPath,
		"silence", "1", "0.1", "1%",
		"1", "1.0", "1%",
	}

	// Overlay a per-call timeout on the caller's ctx so a hung mic
	// driver still terminates without the operator hitting Ctrl+C.
	cctx, cancel := context.WithTimeout(ctx, recordTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "rec", args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RecordFixed captures audio for a fixed duration in seconds.
func (e *Engine) RecordFixed(outPath string, seconds int) error {
	args := []string{
		"-r", "16000",
		"-c", "1",
		"-b", "16",
		outPath,
		"trim", "0", fmt.Sprintf("%d", seconds),
	}

	// Per-call timeout = requested duration + 10s margin so a stuck
	// rec process doesn't wedge the REPL past the natural window.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+10)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "rec", args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Transcribe sends audio to OpenAI Whisper API and returns the text.
// Equivalent to TranscribeCtx with context.Background().
//
// Deprecated: prefer TranscribeCtx so a network hang can be cancelled.
func (e *Engine) Transcribe(audioPath string) (string, error) {
	return e.TranscribeCtx(context.Background(), audioPath)
}

// TranscribeCtx is the ctx-aware variant of Transcribe.
func (e *Engine) TranscribeCtx(ctx context.Context, audioPath string) (string, error) {
	file, err := os.Open(audioPath)
	if err != nil {
		return "", fmt.Errorf("opening audio file: %w", err)
	}
	defer file.Close()
	return e.TranscribeReaderCtx(ctx, file, filepath.Base(audioPath))
}

// TranscribeReader sends audio from a reader to OpenAI Whisper API.
// Equivalent to TranscribeReaderCtx with context.Background().
//
// Deprecated: prefer TranscribeReaderCtx — without a cancellable ctx
// the only timeout is the HTTP client's Timeout field.
func (e *Engine) TranscribeReader(audio io.Reader, filename string) (string, error) {
	return e.TranscribeReaderCtx(context.Background(), audio, filename)
}

// TranscribeReaderCtx sends audio from a reader to OpenAI Whisper API.
// Honours ctx — cancelling it aborts the in-flight HTTP request so the
// REPL can return immediately on Ctrl+C even if the API hangs.
func (e *Engine) TranscribeReaderCtx(ctx context.Context, audio io.Reader, filename string) (string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return "", fmt.Errorf("creating form file: %w", err)
	}
	if _, err := io.Copy(part, audio); err != nil {
		return "", fmt.Errorf("copying audio data: %w", err)
	}

	if err := writer.WriteField("model", e.model); err != nil {
		return "", err
	}
	if err := writer.WriteField("response_format", "json"); err != nil {
		return "", err
	}
	writer.Close()

	req, err := http.NewRequestWithContext(ctx, "POST", e.whisperURL, &buf)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := e.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("whisper API request: %w", err)
	}
	defer resp.Body.Close()

	// Cap the response. Whisper transcriptions of a few minutes of
	// audio are well under 100 KB; 4 MiB is generous headroom while
	// protecting against a misconfigured whisperURL pointing at
	// something that returns multi-GB bodies. The +1 trick lets us
	// distinguish "exactly cap bytes" from "exceeded".
	const maxWhisperResponseBytes = 4 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWhisperResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	if int64(len(body)) > maxWhisperResponseBytes {
		return "", fmt.Errorf("whisper response exceeded %d-byte cap; refusing to buffer", maxWhisperResponseBytes)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("whisper API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}

	return strings.TrimSpace(result.Text), nil
}

// Available checks if sox/rec is installed.
func Available() bool {
	_, err := exec.LookPath("rec")
	return err == nil
}
