package agent

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/obs"
)

// Retry policy constants. Tuned for Anthropic's published behaviour:
// 429 / 529 (overloaded) / 5xx are transient; 4xx other than 429 are
// permanent. Initial 1s backoff doubles up to a 30s ceiling so a long
// outage doesn't burn the whole turn on retries; 4 attempts total
// (1 initial + 3 retries) gives ~1+2+4 = 7s of total backoff in the
// happy-recovery case.
const (
	retryMaxAttempts    = 4
	retryInitialBackoff = 1 * time.Second
	retryMaxBackoff     = 30 * time.Second
)

// streamOnceWithRetry wraps streamOnce with exponential-backoff
// retries for transient API failures. Callers see one of:
//
//   - the successful Message (whatever attempt produced it)
//   - a permanent error (auth, malformed request, etc.)
//   - the last transient error after retryMaxAttempts attempts
//   - ctx.Err() when the parent context cancels mid-retry
//
// Per-attempt failures are surfaced through the existing streamErrCb
// so the cost-tracker's offline-banner logic still fires; the
// recordable-streamErrCb handles each transient hit, and the operator
// sees a "[retrying after Anthropic transient error: …]" line via
// retryNotifyCb when one is installed. retryNotifyCb is opt-in;
// production wiring lives in cmd/promptzero/setup.go.
func (a *Agent) streamOnceWithRetry(ctx context.Context, sysPrompt string, tools []anthropic.ToolUnionParam) (*anthropic.Message, error) {
	var lastErr error
	backoff := retryInitialBackoff

	for attempt := 1; attempt <= retryMaxAttempts; attempt++ {
		// Honour ctx cancellation between attempts so a SIGINT mid-
		// retry doesn't burn the whole backoff window.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		msg, err := a.streamOnce(ctx, sysPrompt, tools)
		if err == nil {
			return msg, nil
		}
		lastErr = err

		if !isRetryableAPIError(err) {
			// Permanent error — surface immediately without retrying.
			return nil, err
		}

		if attempt == retryMaxAttempts {
			// Exhausted. Return the last transient error to the caller.
			break
		}

		// Backoff with cap. Sleep is interruptible by ctx cancellation.
		obs.Default().Warn("agent_stream_retry",
			"attempt", attempt,
			"backoff_ms", backoff.Milliseconds(),
			"err", err.Error())
		if a.retryNotifyCb != nil {
			a.retryNotifyCb(RetryNotice{Attempt: attempt, MaxAttempts: retryMaxAttempts, Backoff: backoff, Err: err})
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > retryMaxBackoff {
			backoff = retryMaxBackoff
		}
	}
	return nil, lastErr
}

// isRetryableAPIError reports whether err is a transient API failure
// worth retrying. The Anthropic Go SDK exposes status codes via
// *anthropic.Error so we can match precisely; for anything else we
// fall back to a string match against the canonical retryable codes
// in the error text. False positives (retrying a permanent error)
// just delay the caller's failure; false negatives (giving up too
// early) collapse to today's behaviour.
func isRetryableAPIError(err error) bool {
	if err == nil {
		return false
	}
	// Context errors are not API errors — never retry these.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// SDK-typed errors expose StatusCode directly.
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		return isRetryableStatusCode(apiErr.StatusCode)
	}

	// Fallback: string-match for the canonical transient codes.
	// Network errors that aren't wrapped as anthropic.Error
	// (e.g. dial timeout, connection reset) live here too.
	msg := err.Error()
	for _, marker := range retryableErrorMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// isRetryableStatusCode picks the well-known transient HTTP status
// codes Anthropic emits.
func isRetryableStatusCode(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429 rate-limited
		http.StatusInternalServerError, // 500 server error
		http.StatusBadGateway,          // 502 upstream bad
		http.StatusServiceUnavailable,  // 503 maintenance / overloaded
		http.StatusGatewayTimeout,      // 504 upstream timeout
		529:                            // Anthropic-specific "overloaded"
		return true
	}
	return false
}

// retryableErrorMarkers are substrings we'll treat as transient when
// the SDK error is wrapped past *anthropic.Error recognition. Kept
// small + specific so we don't over-retry permanent failures.
var retryableErrorMarkers = []string{
	"429 ", "503 ", "502 ", "504 ", "529 ",
	"connection reset",
	"connection refused",
	"i/o timeout",
	"context deadline exceeded", // surfaced from underlying transport
	"unexpected EOF",            // mid-stream disconnect
	"overloaded_error",          // Anthropic-specific
	"rate_limit_error",          // Anthropic-specific
}

// RetryNotice carries the per-attempt retry telemetry surfaced
// through Agent.retryNotifyCb. The REPL shows this as a one-line
// status update so the operator knows the turn is being recovered
// rather than wedged.
type RetryNotice struct {
	Attempt     int
	MaxAttempts int
	Backoff     time.Duration
	Err         error
}

// SetRetryNotifyCallback installs a per-attempt retry observer.
// Called once per backoff window with the attempt number, the
// configured max, and the error that triggered the retry. Pass nil
// to clear.
//
// Lock-free: stored under a.mu like the other agent callbacks.
func (a *Agent) SetRetryNotifyCallback(cb func(RetryNotice)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retryNotifyCb = cb
}

// SetBudgetCheckCallback installs a pre-flight gate consulted at the
// start of every Run() turn. The callback returns nil to allow the
// turn or a non-nil error to refuse it before any tokens burn.
// Production wiring (cmd/promptzero/setup.go) tests
// cost.Tracker.BudgetExceeded() and returns ErrBudgetExceeded when
// the session USD cap has been crossed.
//
// Pass nil to clear. Lock-free: stored under a.mu like the other
// agent callbacks. The callback is invoked while a.mu is held, so
// it MUST NOT reach back into the agent — keep it a thin predicate.
func (a *Agent) SetBudgetCheckCallback(cb func() error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.budgetCheckCb = cb
}
