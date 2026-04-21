package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
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
		return ""
	}
	var b strings.Builder
	b.WriteString("<device-state>\n")
	b.Write(body)
	b.WriteString("\n</device-state>\n\n")
	return b.String()
}
