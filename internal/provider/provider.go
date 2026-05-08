package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

// Message is a provider-agnostic chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Response from an LLM provider.
type Response struct {
	Content string
}

// Provider abstracts LLM completion.
type Provider interface {
	Complete(ctx context.Context, system string, messages []Message) (*Response, error)
	Name() string
}

var httpClient = &http.Client{Timeout: 5 * time.Minute}

// maxResponseBytes caps how much an HTTP-based provider response we'll
// buffer in memory before giving up. Real LLM completions are well
// under 1 MB; the cap is generous to avoid clipping legitimate large
// outputs while protecting against a misconfigured baseURL pointing
// at a file server or a multi-GB error page from a CDN.
const maxResponseBytes = 16 << 20 // 16 MiB

// readCappedBody reads at most maxResponseBytes from body. Returns an
// explicit error when the cap is hit so the caller can surface a clear
// "response too large" message rather than silently truncating into a
// JSON parse error downstream.
func readCappedBody(body io.Reader, name string) ([]byte, error) {
	r := io.LimitReader(body, maxResponseBytes+1)
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading %s response: %w", name, err)
	}
	if int64(len(data)) > maxResponseBytes {
		return nil, fmt.Errorf("%s response exceeded %d-byte cap; refusing to buffer in memory", name, maxResponseBytes)
	}
	return data, nil
}

// --- Claude ---

type Claude struct {
	client *anthropic.Client
	model  string
}

func NewClaude(client *anthropic.Client, model string) *Claude {
	return &Claude{client: client, model: model}
}

func (c *Claude) Name() string { return "claude/" + c.model }

func (c *Claude) Complete(ctx context.Context, system string, messages []Message) (*Response, error) {
	var msgs []anthropic.MessageParam
	for _, m := range messages {
		switch m.Role {
		case "user":
			msgs = append(msgs, anthropic.NewUserMessage(anthropic.NewTextBlock(m.Content)))
		case "assistant":
			msgs = append(msgs, anthropic.NewAssistantMessage(anthropic.NewTextBlock(m.Content)))
		}
	}

	resp, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     c.model,
		MaxTokens: 8192,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages:  msgs,
	})
	if err != nil {
		return nil, fmt.Errorf("claude API: %w", err)
	}

	for _, block := range resp.Content {
		if block.Type == "text" {
			return &Response{Content: block.Text}, nil
		}
	}
	return &Response{Content: ""}, nil
}

// --- Ollama ---

type Ollama struct {
	baseURL string
	model   string
}

func NewOllama(baseURL, model string) *Ollama {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.1"
	}
	return &Ollama{baseURL: baseURL, model: model}
}

func (o *Ollama) Name() string { return "ollama/" + o.model }

func (o *Ollama) Complete(ctx context.Context, system string, messages []Message) (*Response, error) {
	msgs := make([]map[string]string, 0, len(messages)+1)
	if system != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": system})
	}
	for _, m := range messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}

	body, err := json.Marshal(map[string]interface{}{
		"model":    o.model,
		"messages": msgs,
		"stream":   false,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", o.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	data, err := readCappedBody(resp.Body, "ollama")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ollama error %d: %s", resp.StatusCode, string(data))
	}

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing ollama response: %w", err)
	}
	return &Response{Content: result.Message.Content}, nil
}

// --- OpenRouter / OpenAI-compatible ---

type OpenAICompat struct {
	baseURL string
	apiKey  string
	model   string
	name    string
}

func NewOpenRouter(apiKey, model string) *OpenAICompat {
	if model == "" {
		model = "anthropic/claude-sonnet-4"
	}
	return &OpenAICompat{
		baseURL: "https://openrouter.ai/api/v1",
		apiKey:  apiKey,
		model:   model,
		name:    "openrouter",
	}
}

func NewOpenAICompat(baseURL, apiKey, model, name string) *OpenAICompat {
	return &OpenAICompat{baseURL: baseURL, apiKey: apiKey, model: model, name: name}
}

func (o *OpenAICompat) Name() string { return o.name + "/" + o.model }

func (o *OpenAICompat) Complete(ctx context.Context, system string, messages []Message) (*Response, error) {
	msgs := make([]map[string]string, 0, len(messages)+1)
	if system != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": system})
	}
	for _, m := range messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}

	body, err := json.Marshal(map[string]interface{}{
		"model":    o.model,
		"messages": msgs,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", o.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request: %w", o.name, err)
	}
	defer resp.Body.Close()

	data, err := readCappedBody(resp.Body, o.name)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s error %d: %s", o.name, resp.StatusCode, string(data))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing %s response: %w", o.name, err)
	}
	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("%s: empty response", o.name)
	}
	return &Response{Content: result.Choices[0].Message.Content}, nil
}
