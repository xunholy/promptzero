package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestOllama_HappyPath round-trips a known message through a stub
// Ollama-compatible server and verifies the request shape and the
// content extracted from the response.
func TestOllama_HappyPath(t *testing.T) {
	var seenBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("path = %q, want /api/chat", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		_, _ = io.WriteString(w, `{"message":{"content":"pong"}}`)
	}))
	defer srv.Close()

	o := NewOllama(srv.URL, "test-model")
	resp, err := o.Complete(context.Background(), "you are helpful",
		[]Message{{Role: "user", Content: "ping"}})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "pong" {
		t.Errorf("Content = %q, want pong", resp.Content)
	}
	if seenBody["model"] != "test-model" {
		t.Errorf("body.model = %v, want test-model", seenBody["model"])
	}
	msgs, _ := seenBody["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages (system + user), got %d", len(msgs))
	}
}

// TestOllama_NonOK propagates a non-200 status as a structured error
// including the body text — operators see the upstream error message,
// not just "request failed".
func TestOllama_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "model unloaded")
	}))
	defer srv.Close()

	o := NewOllama(srv.URL, "test")
	_, err := o.Complete(context.Background(), "", []Message{{Role: "user", Content: "x"}})
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "model unloaded") {
		t.Errorf("error %q should include status + body", err.Error())
	}
}

// TestProvider_ResponseTooLarge is the load-bearing safety check: a
// misconfigured baseURL pointing at a multi-GB endpoint must not
// exhaust memory. The cap fires when the response exceeds
// maxResponseBytes and the caller sees a clear refusal message.
func TestProvider_ResponseTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stream maxResponseBytes+1024 bytes so the cap definitely fires.
		w.Header().Set("Content-Type", "application/json")
		buf := make([]byte, 4096)
		for i := range buf {
			buf[i] = 'A'
		}
		written := 0
		for written < maxResponseBytes+1024 {
			n, err := w.Write(buf)
			if err != nil {
				return
			}
			written += n
		}
	}))
	defer srv.Close()

	o := NewOllama(srv.URL, "test")
	_, err := o.Complete(context.Background(), "", []Message{{Role: "user", Content: "x"}})
	if err == nil {
		t.Fatal("expected error when response exceeds cap")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error %q should mention size cap", err.Error())
	}
}

// TestOllama_DefaultsBaseURLAndModel locks the convenience defaults so
// a persona declaring `provider: { generate: ollama }` without a
// model/url still picks up sensible values rather than silently
// connecting to "" + "".
func TestOllama_DefaultsBaseURLAndModel(t *testing.T) {
	o := NewOllama("", "")
	if o.baseURL != "http://localhost:11434" {
		t.Errorf("default baseURL = %q", o.baseURL)
	}
	if o.model != "llama3.1" {
		t.Errorf("default model = %q", o.model)
	}
	// Name is provider-prefixed so /cost shows which client billed.
	if got := o.Name(); got != "ollama/llama3.1" {
		t.Errorf("Name = %q, want ollama/llama3.1", got)
	}
}

// TestOpenAICompat_HappyPath verifies the request shape matches the
// Chat Completions API and the response is unwrapped from
// .choices[0].message.content. Authorization header is asserted so a
// future refactor that drops the bearer token gets caught here.
func TestOpenAICompat_HappyPath(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %q, want /chat/completions", r.URL.Path)
		}
		seenAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w,
			`{"choices":[{"message":{"content":"openai-pong"}}]}`)
	}))
	defer srv.Close()

	o := NewOpenAICompat(srv.URL, "secret-key", "gpt-test", "openai-test")
	resp, err := o.Complete(context.Background(), "sys",
		[]Message{{Role: "user", Content: "ping"}})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "openai-pong" {
		t.Errorf("Content = %q", resp.Content)
	}
	if seenAuth != "Bearer secret-key" {
		t.Errorf("Authorization = %q, want Bearer secret-key", seenAuth)
	}
	if got := o.Name(); got != "openai-test/gpt-test" {
		t.Errorf("Name = %q", got)
	}
}

// TestOpenAICompat_EmptyChoicesIsHandled confirms a server-side error
// shape (no choices) is reported as a structured error rather than a
// nil-index panic. Pins the contract that downstream callers can
// distinguish "got nothing back" from "couldn't reach upstream".
func TestOpenAICompat_EmptyChoicesIsHandled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[]}`)
	}))
	defer srv.Close()

	o := NewOpenAICompat(srv.URL, "k", "m", "test")
	_, err := o.Complete(context.Background(), "", []Message{{Role: "user", Content: "x"}})
	if err == nil {
		t.Fatal("expected error on empty choices, got nil")
	}
	if !strings.Contains(err.Error(), "empty response") {
		t.Errorf("error %q should mention 'empty response'", err.Error())
	}
}

// TestNewOpenRouter_DefaultsModel locks the OpenRouter convenience
// constructor so a missing model arg still picks up the documented
// default rather than sending an empty model string upstream.
func TestNewOpenRouter_DefaultsModel(t *testing.T) {
	o := NewOpenRouter("k", "")
	if o.model != "anthropic/claude-sonnet-4" {
		t.Errorf("default model = %q", o.model)
	}
	if o.name != "openrouter" {
		t.Errorf("name = %q", o.name)
	}
}

// Sanity check that maxResponseBytes is large enough for a normal LLM
// completion. 1MB is well above any reasonable single response.
func TestMaxResponseBytes_AllowsTypicalCompletion(t *testing.T) {
	if maxResponseBytes < 1<<20 {
		t.Fatalf("maxResponseBytes = %d; want at least 1 MiB to cover normal completions", maxResponseBytes)
	}
}
