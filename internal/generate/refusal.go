package generate

import (
	"context"
	"strings"

	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/provider"
)

// refusalPrefixes are the canonical opening phrases of model refusals
// across recent Claude generations. Detection is intentionally simple:
// trim whitespace, lowercase, check if the response starts with any of
// these. A short response (~< 200 chars) that begins with one of these
// is treated as a refusal; longer responses are not, since a thorough
// answer can begin with "I cannot guarantee…" without actually refusing.
//
// Patterns curated from observed Anthropic refusal shapes. False
// positives are recoverable (we just retry through the fallback),
// false negatives mean the operator gets the original refusal text
// — exactly the same UX as today.
var refusalPrefixes = []string{
	"i can't help",
	"i can't assist",
	"i cannot help",
	"i cannot assist",
	"i won't help",
	"i won't assist",
	"i'm not able to",
	"i am not able to",
	"i'm unable to",
	"i am unable to",
	"i cannot provide",
	"i can't provide",
	"i won't provide",
	"i cannot create",
	"i can't create",
	"i won't create",
	"i cannot generate",
	"i can't generate",
	"i won't generate",
	"i cannot write",
	"i can't write",
	"i won't write",
	"i don't think i should",
	"i shouldn't",
	"i'd recommend reaching out",
}

// refusalMaxLen caps the length at which a refusal-prefix match is
// treated as a refusal. Longer responses that happen to open with a
// hedged phrase are usually not actual refusals — they're answers
// with a caveat. Empirically ~300 characters covers the typical
// "I cannot help with X. <three-sentence explanation>" shape.
const refusalMaxLen = 300

// looksLikeRefusal returns true when the response text starts with a
// canonical refusal phrase AND is short enough to be a pure refusal
// rather than a caveated answer.
func looksLikeRefusal(text string) bool {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) == 0 {
		return false
	}
	if len(trimmed) > refusalMaxLen {
		return false
	}
	lower := strings.ToLower(trimmed)
	for _, p := range refusalPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// completeWithFallback issues a Complete call against g.llm and, when
// the response looks like a model refusal AND a fallback provider is
// configured, retries the same call against the fallback. Returns the
// response that succeeded plus a non-empty providerName when the
// fallback was used (so callers can surface "generated via Ollama"
// to the operator).
//
// Network / API errors propagate as-is — those aren't refusals and
// retrying them through the fallback would mask the real problem.
//
// When no fallback is configured, behaviour is identical to a direct
// g.llm.Complete call: refusal text passes through unchanged, just
// like pre-v0.20.0.
func (g *Generator) completeWithFallback(ctx context.Context, system string, msgs []provider.Message, taskLabel string) (*provider.Response, string, error) {
	resp, err := g.llm.Complete(ctx, system, msgs)
	if err != nil {
		return nil, "", err
	}
	if !looksLikeRefusal(resp.Content) {
		return resp, "", nil
	}
	// Refusal detected. Log structured so operators see it in audit
	// and observability tools regardless of fallback availability.
	obs.Default().Warn("generate_refusal_detected",
		"task", taskLabel,
		"primary_provider", g.llm.Name(),
		"refusal_excerpt", excerpt(resp.Content, 120))

	if g.fallback == nil {
		// No fallback wired — return the refusal as the response.
		// The caller surfaces it; the operator gets the same UX as
		// today plus a structured log row to consult.
		return resp, "", nil
	}

	fbResp, fbErr := g.fallback.Complete(ctx, system, msgs)
	if fbErr != nil {
		// Fallback failed — return the original refusal so the
		// operator at least sees something. The fallback error is
		// logged but doesn't propagate (we don't want to make the
		// refusal worse by also surfacing a fallback failure).
		obs.Default().Warn("generate_fallback_failed",
			"task", taskLabel,
			"fallback_provider", g.fallback.Name(),
			"err", fbErr.Error())
		return resp, "", nil
	}
	obs.Default().Info("generate_fallback_used",
		"task", taskLabel,
		"primary_provider", g.llm.Name(),
		"fallback_provider", g.fallback.Name())
	return fbResp, g.fallback.Name(), nil
}

// excerpt returns the first n runes of s, single-line, suffixed with
// "…" when truncated. Used in structured logs so a multi-paragraph
// refusal doesn't blow up a single log row.
func excerpt(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
