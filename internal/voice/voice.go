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
	// httpClient overrides the default 60-second Whisper client; set in
	// tests to inject a short-timeout or mock-server client.
	httpClient *http.Client
}

// client returns the HTTP client to use for Whisper API calls.
// When httpClient is nil (production), a fresh client with a 60-second
// timeout is returned so we never reuse http.DefaultClient's shared
// transport state and cannot be blocked by a hung upstream forever.
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
