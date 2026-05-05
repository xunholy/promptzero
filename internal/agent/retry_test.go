package agent

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

// TestIsRetryableStatusCode locks the canonical transient HTTP codes.
// Adding a new retryable code should add a case here; removing one
// should fail this test.
func TestIsRetryableStatusCode(t *testing.T) {
	retryable := []int{429, 500, 502, 503, 504, 529}
	for _, code := range retryable {
		if !isRetryableStatusCode(code) {
			t.Errorf("status %d should be retryable", code)
		}
	}
	notRetryable := []int{200, 301, 400, 401, 403, 404, 422, 451}
	for _, code := range notRetryable {
		if isRetryableStatusCode(code) {
			t.Errorf("status %d should NOT be retryable", code)
		}
	}
}

// TestIsRetryableAPIError_AnthropicSDKError uses the SDK's own error
// type so the StatusCode-based path is exercised.
func TestIsRetryableAPIError_AnthropicSDKError(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"429 too many requests":    {&anthropic.Error{StatusCode: http.StatusTooManyRequests}, true},
		"500 internal server":      {&anthropic.Error{StatusCode: http.StatusInternalServerError}, true},
		"503 service unavailable":  {&anthropic.Error{StatusCode: http.StatusServiceUnavailable}, true},
		"529 anthropic-overloaded": {&anthropic.Error{StatusCode: 529}, true},
		"400 bad request":          {&anthropic.Error{StatusCode: http.StatusBadRequest}, false},
		"401 unauthorised":         {&anthropic.Error{StatusCode: http.StatusUnauthorized}, false},
		"404 not found":            {&anthropic.Error{StatusCode: http.StatusNotFound}, false},
	}
	for name, c := range cases {
		if got := isRetryableAPIError(c.err); got != c.want {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
}

// TestIsRetryableAPIError_ContextErrorsNeverRetry verifies that ctx
// errors propagate as failures rather than triggering a retry — the
// caller cancelled, retrying would be wrong.
func TestIsRetryableAPIError_ContextErrorsNeverRetry(t *testing.T) {
	if isRetryableAPIError(context.Canceled) {
		t.Error("context.Canceled must not be retryable")
	}
	if isRetryableAPIError(context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded must not be retryable")
	}
}

// TestIsRetryableAPIError_StringMatchFallback exercises the fallback
// path for errors that aren't *anthropic.Error — wrapped, custom, or
// transport-level errors.
func TestIsRetryableAPIError_StringMatchFallback(t *testing.T) {
	cases := map[string]bool{
		"connection reset by peer":              true,
		"connection refused":                    true,
		"i/o timeout":                           true,
		"unexpected EOF mid-stream":             true,
		"overloaded_error: please try again":    true,
		"rate_limit_error: too many requests":   true,
		"503 service unavailable from upstream": true,
		"random transport failure":              false,
		"invalid api key":                       false,
		"the request was malformed":             false,
	}
	for msg, want := range cases {
		if got := isRetryableAPIError(errors.New(msg)); got != want {
			t.Errorf("%q: got %v, want %v", msg, got, want)
		}
	}
}

// TestIsRetryableAPIError_NilSafe is a smoke test against accidental
// nil-deref panics.
func TestIsRetryableAPIError_NilSafe(t *testing.T) {
	if isRetryableAPIError(nil) {
		t.Error("nil error should never be retryable")
	}
}

// TestRetryableErrorMarkers_AllSubstringsMatch verifies the marker
// list itself — every entry must be detectable as substring of an
// error message containing it. Catches the trivial bug where someone
// adds a marker with stray whitespace or a typo.
func TestRetryableErrorMarkers_AllSubstringsMatch(t *testing.T) {
	for _, m := range retryableErrorMarkers {
		err := errors.New("upstream said: " + m + ", retrying")
		if !isRetryableAPIError(err) {
			t.Errorf("marker %q is in retryableErrorMarkers but isRetryableAPIError didn't match it", m)
		}
		// Marker must not be empty.
		if strings.TrimSpace(m) == "" {
			t.Errorf("marker is empty/whitespace-only: %q", m)
		}
	}
}
