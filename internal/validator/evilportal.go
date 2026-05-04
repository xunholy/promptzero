package validator

import (
	"regexp"
	"strings"
)

// Evil Portal static validator. Mirrors the BadUSB rule-based approach
// so generate_evil_portal output gets a deterministic, machine-readable
// gate in addition to the Haiku chain-of-verification. The Marauder
// expects a very specific captive-portal shape:
//
//   - single <form>
//   - action="/get" (the FAP endpoint that logs credentials)
//   - method="GET" (Marauder only reads query-string params)
//   - field names exactly "email" and "password"
//   - everything inline (no external CSS/JS/img; the Flipper serves
//     the page offline)
//
// Deviations are usually silent failures — the portal renders but
// submits nothing the Marauder can capture. The existing verifier
// catches them via Haiku, but a static pass runs in microseconds,
// always reaches the same verdict, and doesn't cost an API call.

// epBadRules fire on positive matches that indicate a broken portal.
// Different from the required-present checks inside ValidateEvilPortal
// (where the missing pattern = bad), these rules hit on substrings
// that should NOT appear in a Marauder-compatible portal.
var epBadRules = []rule{
	{
		id:       "ep_external_resource",
		pattern:  regexp.MustCompile(`(?is)<(?:img|script|link|iframe)\b[^>]*\bsrc\s*=\s*["']\s*https?://`),
		severity: SeverityCritical,
		message:  "external resource URL — breaks when served offline from the Marauder",
	},
	{
		id:       "ep_external_stylesheet",
		pattern:  regexp.MustCompile(`(?is)<link\b[^>]*\brel\s*=\s*["']stylesheet["'][^>]*\bhref\s*=\s*["']\s*https?://`),
		severity: SeverityCritical,
		message:  "external stylesheet URL — breaks when served offline",
	},
	{
		id:       "ep_cdn_reference",
		pattern:  regexp.MustCompile(`(?is)(?:cdnjs\.cloudflare|ajax\.googleapis|unpkg\.com|jsdelivr\.net|bootstrapcdn|fontawesome|fonts\.googleapis)`),
		severity: SeverityCritical,
		message:  "CDN reference in HTML — the Flipper cannot reach external hosts when serving the portal",
	},
	{
		id:       "ep_markdown_fence",
		pattern:  regexp.MustCompile("```(?:html|HTML)?\\s*\\n?<!DOCTYPE"),
		severity: SeverityCritical,
		message:  "markdown code fence leaked into HTML output",
	},
	{
		id:       "ep_trailing_markdown",
		pattern:  regexp.MustCompile("\n```\\s*$"),
		severity: SeverityWarn,
		message:  "trailing markdown fence; trim before deploy",
	},
	{
		id:       "ep_wrong_field_username",
		pattern:  regexp.MustCompile(`(?is)<input\b[^>]*\bname\s*=\s*["']username["']`),
		severity: SeverityCritical,
		message:  `input named "username" — Marauder expects "email" verbatim`,
	},
	{
		id:       "ep_wrong_field_user",
		pattern:  regexp.MustCompile(`(?is)<input\b[^>]*\bname\s*=\s*["']user["']`),
		severity: SeverityCritical,
		message:  `input named "user" — Marauder expects "email" verbatim`,
	},
	{
		id:       "ep_wrong_field_pass",
		pattern:  regexp.MustCompile(`(?is)<input\b[^>]*\bname\s*=\s*["']pass["']`),
		severity: SeverityCritical,
		message:  `input named "pass" — Marauder expects "password" verbatim`,
	},
}

// epRequiredRules are compiled once at package init. Previously these
// regexps were declared (and re-compiled) inside ValidateEvilPortal on
// every call, which is the same anti-pattern epBadRules above explicitly
// avoids. Hoisting matches the existing convention and removes ~5
// regexp.MustCompile calls per validation.
var epRequiredRules = []struct {
	id      string
	pattern *regexp.Regexp
	missing string
}{
	{"ep_missing_form", regexp.MustCompile(`(?is)<form\b`),
		"no <form> element; Marauder has no credential submission path"},
	{"ep_missing_action_get", regexp.MustCompile(`(?is)<form\b[^>]*\baction\s*=\s*["']\s*/get\b`),
		`form action must be "/get" — Marauder only logs credentials on that endpoint`},
	{"ep_missing_method_get", regexp.MustCompile(`(?is)<form\b[^>]*\bmethod\s*=\s*["']\s*GET\s*["']`),
		`form method must be "GET" — Marauder only reads query-string params`},
	{"ep_missing_email_field", regexp.MustCompile(`(?is)<input\b[^>]*\bname\s*=\s*["']email["']`),
		`missing <input name="email"> — credential capture won't include username`},
	{"ep_missing_password_field", regexp.MustCompile(`(?is)<input\b[^>]*\bname\s*=\s*["']password["']`),
		`missing <input name="password"> — credential capture won't include password`},
}

// ValidateEvilPortal scans an Evil Portal HTML payload and returns a
// Report. Findings mirror the BadUSB shape so upstream risk-gating code
// can treat them uniformly. The report's top-level Severity is the
// highest individual finding.
//
// The function is deliberately lenient about whitespace and attribute
// ordering — real operator-authored pages don't always match the
// canonical shape letter-for-letter, but they must at least carry the
// four load-bearing pieces (form present, action=/get, method=GET,
// email+password fields).
func ValidateEvilPortal(name, html string) Report {
	rep := Report{Name: name}

	// Required-present checks — these flip severity only when the
	// pattern does NOT match, so a compliant payload produces no
	// findings for them.
	for _, r := range epRequiredRules {
		if !r.pattern.MatchString(html) {
			rep.Findings = append(rep.Findings, Finding{
				Severity: SeverityCritical,
				Rule:     r.id,
				Message:  r.missing,
				Line:     0,
				Excerpt:  "",
			})
		}
	}

	// Presence-bad checks — fire on a positive match.
	lines := strings.Split(html, "\n")
	for _, br := range epBadRules {
		idx := br.pattern.FindStringIndex(html)
		if idx == nil {
			continue
		}
		lineNo := 1 + strings.Count(html[:idx[0]], "\n")
		excerpt := ""
		if lineNo-1 < len(lines) {
			excerpt = strings.TrimSpace(lines[lineNo-1])
			if len(excerpt) > 120 {
				excerpt = excerpt[:120] + "…"
			}
		}
		rep.Findings = append(rep.Findings, Finding{
			Severity: br.severity,
			Rule:     br.id,
			Message:  br.message,
			Line:     lineNo,
			Excerpt:  excerpt,
		})
	}

	// Roll up top-level severity.
	for _, f := range rep.Findings {
		if f.Severity > rep.Severity {
			rep.Severity = f.Severity
		}
	}
	return rep
}
