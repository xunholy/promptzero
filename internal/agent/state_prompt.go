package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/obs"
)

// deviceStateTimeout caps how long the state-oracle probe can block the
// agent turn. Two seconds matches the stateCacheTTL: a cached snapshot
// returns instantly, and a miss that takes longer than this is more
// useful to skip than to stall the REPL on.
const deviceStateTimeout = 2 * time.Second

// buildDeviceStateBlock returns a <device-state>...</device-state> prefix
// for the next user turn, or the empty string when state isn't available
// (flipper not connected, probe errored, context already cancelled). The
// model is instructed via the system prompt's trust clause to treat the
// block as read-only grounding.
//
// The block is *not* cached by the prompt-cache breakpoint — device state
// changes every few seconds, which would constantly bust the cache. It
// sits outside the cached system+tools prefix and adds ~50 tokens per
// turn in exchange for killing repeated "what's connected?" round-trips.
func buildDeviceStateBlock(parent context.Context, f *flipper.Flipper) string {
	if f == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(parent, deviceStateTimeout)
	defer cancel()

	st, err := f.State(ctx)
	if err != nil && !st.Connected {
		return ""
	}
	if !st.Connected {
		return ""
	}

	body, err := json.Marshal(st)
	if err != nil {
		// Returning "" preserves the documented graceful behaviour
		// (turn proceeds without device-state annotation), but log
		// at warn so a future programmer attaching a non-encodable
		// type to the state struct sees the breadcrumb instead of
		// silently losing the agent's situational-awareness prefix.
		obs.Default().Warn("device_state_marshal_failed", "err", err)
		return ""
	}
	var b strings.Builder
	b.WriteString("<device-state>\n")
	b.Write(body)
	b.WriteString("\n</device-state>\n\n")
	return b.String()
}

// buildUIContextBlock returns a one-line XML annotation for the current web
// UI navigation state, or the empty string when both view and path are empty.
// Control characters are stripped from path; XML-special characters are not
// escaped — filesystem paths never contain them and path validation upstream
// rejects anything that would require escaping.
func buildUIContextBlock(view, path string) string {
	if view == "" && path == "" {
		return ""
	}
	// Strip control characters; keep printable UTF-8 only.
	var b strings.Builder
	for _, r := range path {
		if r >= 32 {
			b.WriteRune(r)
		}
	}
	cleanPath := b.String()
	return fmt.Sprintf("<ui-context view=%q path=%q/>\n", view, cleanPath)
}
