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

// Record captures audio from the microphone using sox.
// Press Ctrl+C or wait for silence to stop.
func (e *Engine) Record(outPath string) error {
	// sox's `rec` command — widely available on Linux/macOS
	// Records 16kHz mono WAV, stops after 1s of silence
	args := []string{
		"-r", "16000",
		"-c", "1",
		"-b", "16",
		outPath,
		"silence", "1", "0.1", "1%",
		"1", "1.0", "1%",
	}

	cmd := exec.CommandContext(context.Background(), "rec", args...)
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

	cmd := exec.CommandContext(context.Background(), "rec", args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Transcribe sends audio to OpenAI Whisper API and returns the text.
func (e *Engine) Transcribe(audioPath string) (string, error) {
	file, err := os.Open(audioPath)
	if err != nil {
		return "", fmt.Errorf("opening audio file: %w", err)
	}
	defer file.Close()

	return e.TranscribeReader(file, filepath.Base(audioPath))
}

// TranscribeReader sends audio from a reader to OpenAI Whisper API.
func (e *Engine) TranscribeReader(audio io.Reader, filename string) (string, error) {
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

	req, err := http.NewRequest("POST", e.whisperURL, &buf)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
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
