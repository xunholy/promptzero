// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"testing"
)

// TestBuild_VerifierBlockPreventsWrite guards the generated-payload-review
// contract: when the build verifier returns a block message, a *_build
// tool MUST surface it and MUST NOT persist the file. The handler is
// given a nil Flipper on purpose — if a refactor moved or dropped the
// `if blockMsg != "" { return ... }` gate so the SD-card write ran
// before the block check, the write would nil-panic here instead of
// returning the clean block message. This is the tool-layer half of the
// safety net (the BuildVerify function itself is tested in internal/agent).
func TestBuild_VerifierBlockPreventsWrite(t *testing.T) {
	const blocked = "BLOCKED: verifier flagged this payload (high severity)"
	blockVerify := func(_ context.Context, _ string, _ []byte, bypass bool) (string, string) {
		if bypass {
			return "verifier bypassed", ""
		}
		return "", blocked
	}

	cases := []struct {
		tool   string
		params map[string]any
	}{
		{"subghz_build", map[string]any{
			"path": "/ext/subghz/x.sub", "frequency": 433920000,
			"protocol": "Princeton", "key_hex": "00 11 22 33 44 55", "bit": 24,
		}},
		{"rfid_build", map[string]any{
			"path": "/ext/lfrfid/x.rfid", "key_type": "EM4100", "data": "1A 2B 3C 4D 5E",
		}},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			spec, ok := Get(c.tool)
			if !ok {
				t.Skipf("%s not registered in this build", c.tool)
			}
			// Flipper nil: the block path must return before any write.
			d := &Deps{BuildVerify: blockVerify}
			out, err := spec.Handler(context.Background(), d, c.params)
			if err != nil {
				t.Fatalf("%s handler errored on the block path (should return the block msg cleanly): %v", c.tool, err)
			}
			if out != blocked {
				t.Errorf("%s blocked build returned %q, want the block message %q — the SD-card write was NOT short-circuited",
					c.tool, out, blocked)
			}
		})
	}
}
