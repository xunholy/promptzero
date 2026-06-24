package vision

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/confidence"
)

type Analyzer struct {
	client *anthropic.Client
	model  string
}

// Result is the typed envelope returned by AnalyzeWithConfidence
// (roadmap P3-29). Text is the model's natural-language identification
// of the device / remote / tag / label in the image. Confidence is the
// model's self-graded certainty in [0, 1]; HasConfidence reports
// whether the model actually emitted a confidence value (a `false`
// here means "no signal — treat Confidence as the default 1.0 only
// for the purpose of comparing against thresholds, not as a true
// claim of certainty"). LowConfidence is precomputed against the
// caller-supplied threshold so the operator-facing renderer can flip
// to a clarifying-question UX.
type Result struct {
	Text          string
	Confidence    confidence.Score
	HasConfidence bool
	LowConfidence bool
}

func New(client *anthropic.Client, model string) *Analyzer {
	if model == "" {
		model = "claude-opus-4-8"
	}
	return &Analyzer{client: client, model: model}
}

// AnalyzeFile remains the legacy string-only entry point for callers
// that don't care about confidence routing. New callers should prefer
// AnalyzeFileWithConfidence so they can route low-confidence results
// to a clarifying user-facing question.
func (a *Analyzer) AnalyzeFile(ctx context.Context, path string, question string) (string, error) {
	res, err := a.AnalyzeFileWithConfidence(ctx, path, question, 0)
	if err != nil {
		return "", err
	}
	return res.Text, nil
}

func (a *Analyzer) AnalyzeBase64(ctx context.Context, b64data string, question string) (string, error) {
	res, err := a.AnalyzeBase64WithConfidence(ctx, b64data, question, 0)
	if err != nil {
		return "", err
	}
	return res.Text, nil
}

// AnalyzeFileWithConfidence is the P3-29 entrypoint. threshold is the
// per-call abstention threshold; pass 0 to use
// confidence.DefaultClassifierThreshold. Behaviour matches AnalyzeFile
// when the model doesn't emit a confidence signal — Result.Text is
// populated with the original prose and LowConfidence is false.
func (a *Analyzer) AnalyzeFileWithConfidence(ctx context.Context, path, question string, threshold confidence.Score) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, fmt.Errorf("reading image: %w", err)
	}
	mediaType := detectMediaType(path)
	b64 := base64.StdEncoding.EncodeToString(data)
	return a.analyzeWithConfidence(ctx, mediaType, b64, question, threshold)
}

// AnalyzeBase64WithConfidence mirrors AnalyzeFileWithConfidence for
// data-URL / raw-base64 inputs.
func (a *Analyzer) AnalyzeBase64WithConfidence(ctx context.Context, b64data, question string, threshold confidence.Score) (Result, error) {
	mediaType := anthropic.Base64ImageSourceMediaTypeImageJPEG
	if mt, payload, ok := parseDataURL(b64data); ok {
		mediaType = anthropic.Base64ImageSourceMediaType(mt)
		b64data = payload
	}
	return a.analyzeWithConfidence(ctx, string(mediaType), b64data, question, threshold)
}

// parseDataURL extracts the media type and base64 payload from a data
// URL of shape "data:<media-type>;base64,<payload>". Returns ok=false
// for malformed inputs (missing "data:" prefix, missing ";base64,"
// delimiter, etc.) so the caller can fall back to treating the input
// as raw base64. Previously the prefix-strip was an unchecked
// b64data[5:idx] slice that panicked on inputs like "X;base64,..."
// where idx<5.
func parseDataURL(s string) (mediaType, payload string, ok bool) {
	const prefix = "data:"
	const delim = ";base64,"
	if !strings.HasPrefix(s, prefix) {
		return "", "", false
	}
	rest := s[len(prefix):]
	idx := strings.Index(rest, delim)
	if idx < 0 {
		return "", "", false
	}
	return rest[:idx], rest[idx+len(delim):], true
}

func (a *Analyzer) analyzeWithConfidence(ctx context.Context, mediaType, b64data, question string, threshold confidence.Score) (Result, error) {
	if question == "" {
		question = "Identify this device, remote, tag, or label. What is it? What Flipper Zero capabilities could interact with it? List the specific protocol, frequency, or technology involved and suggest the exact promptzero command to use."
	}
	// P3-29: ask the model to wrap its answer in a JSON envelope
	// with a confidence score. Pre-existing prose-only responses
	// still parse — extractVisionAnswer falls back to the raw text.
	question += "\n\nRespond as a JSON object: {\"answer\": \"<your identification>\", \"confidence\": <0.0-1.0>}. " +
		"Set confidence near 1.0 when you can identify the object unambiguously, near 0.5 when uncertain, " +
		"≤0.3 when the image is ambiguous or you are guessing. Output ONLY JSON. No prose, no markdown fences."

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
		return Result{}, fmt.Errorf("vision API: %w", err)
	}

	var raw string
	for _, block := range resp.Content {
		if block.Type == "text" {
			raw = block.Text
			break
		}
	}
	if raw == "" {
		return Result{}, fmt.Errorf("no text in vision response")
	}

	answer, score, hasSig := extractVisionAnswer(raw)
	low := false
	if hasSig {
		low = confidence.ShouldAbstainAt(score, threshold)
	}
	return Result{
		Text:          answer,
		Confidence:    score,
		HasConfidence: hasSig,
		LowConfidence: low,
	}, nil
}

// extractVisionAnswer pulls (text, confidence, hasSignal) from a raw
// vision response. Tolerant: if the model returned plain prose
// instead of the requested JSON envelope, returns the raw text with
// hasSignal=false (no confidence claim, treat as full signal).
func extractVisionAnswer(raw string) (string, confidence.Score, bool) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") {
		var obj struct {
			Answer     string `json:"answer"`
			Confidence any    `json:"confidence"`
		}
		if err := json.Unmarshal([]byte(trimmed), &obj); err == nil && obj.Answer != "" {
			score, has := confidence.ParseClassifierResponse(trimmed)
			return obj.Answer, score, has
		}
	}
	return raw, confidence.Score(1.0), false
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
