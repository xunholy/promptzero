package vision

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
)

type Analyzer struct {
	client *anthropic.Client
	model  string
}

func New(client *anthropic.Client, model string) *Analyzer {
	if model == "" {
		model = "claude-opus-4-7"
	}
	return &Analyzer{client: client, model: model}
}

func (a *Analyzer) AnalyzeFile(ctx context.Context, path string, question string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading image: %w", err)
	}

	mediaType := detectMediaType(path)
	b64 := base64.StdEncoding.EncodeToString(data)

	return a.analyze(ctx, mediaType, b64, question)
}

func (a *Analyzer) AnalyzeBase64(ctx context.Context, b64data string, question string) (string, error) {
	mediaType := anthropic.Base64ImageSourceMediaTypeImageJPEG
	if idx := strings.Index(b64data, ";base64,"); idx >= 0 {
		mt := b64data[5:idx]
		mediaType = anthropic.Base64ImageSourceMediaType(mt)
		b64data = b64data[idx+8:]
	}

	return a.analyze(ctx, string(mediaType), b64data, question)
}

func (a *Analyzer) analyze(ctx context.Context, mediaType, b64data, question string) (string, error) {
	if question == "" {
		question = "Identify this device, remote, tag, or label. What is it? What Flipper Zero capabilities could interact with it? List the specific protocol, frequency, or technology involved and suggest the exact promptzero command to use."
	}

	imageBlock := anthropic.ContentBlockParamUnion{
		OfImage: &anthropic.ImageBlockParam{
			Source: anthropic.ImageBlockParamSourceUnion{
				OfBase64: &anthropic.Base64ImageSourceParam{
					MediaType: anthropic.Base64ImageSourceMediaType(mediaType),
					Data:      b64data,
				},
			},
		},
	}

	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: 2048,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(
				imageBlock,
				anthropic.NewTextBlock(question),
			),
		},
	})
	if err != nil {
		return "", fmt.Errorf("vision API: %w", err)
	}

	for _, block := range resp.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("no text in vision response")
}

func detectMediaType(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".png"):
		return "image/png"
	case strings.HasSuffix(lower, ".gif"):
		return "image/gif"
	case strings.HasSuffix(lower, ".webp"):
		return "image/webp"
	default:
		return "image/jpeg"
	}
}
