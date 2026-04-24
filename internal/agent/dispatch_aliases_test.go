package agent

import (
	"context"
	"strings"
	"testing"

	flippermock "github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/testmocks"
)

// TestDispatch_DeviceInfoAlias confirms the agent dispatch resolves both
// "system_info" (the long-standing agent-side name) and "device_info" (the
// MCP-side name and the firmware's CLI verb) to the same primitive. Without
// the alias, an LLM that learned the MCP catalogue or a persona migrated
// from MCP would hit "unknown tool" on device_info.
func TestDispatch_DeviceInfoAlias(t *testing.T) {
	flip := testmocks.NewMockFlipper(t,
		testmocks.WithFlipperHandler("device_info", func([]string) string {
			return "hardware_model : Flipper Zero\nfirmware_origin_fork : Momentum"
		}),
	)
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.flipper = flip

	for _, name := range []string{"system_info", "device_info"} {
		out, err := a.dispatch(context.Background(), name, map[string]any{})
		if err != nil {
			t.Errorf("dispatch(%q) returned error: %v", name, err)
			continue
		}
		if !strings.Contains(out, "hardware_model") {
			t.Errorf("dispatch(%q) output missing expected content: %q", name, out)
		}
	}
}

// TestDispatch_StorageWrite confirms the agent now exposes the bare-bytes
// storage_write primitive that MCP has always had — closing the gap that
// forced the LLM to compose generate_*/_build paths even when the user
// just wanted to drop a literal file on the SD card.
func TestDispatch_StorageWrite(t *testing.T) {
	var receivedPath, receivedContent string
	flip := testmocks.NewMockFlipper(t,
		// storage_write is implemented as the write_chunk protocol — the
		// mock receives a series of "storage write_chunk <path> <n>"
		// commands. Capture the path from the first one and ack each
		// chunk request so the wrapper completes.
		testmocks.WithFlipperHandler("storage", func(args []string) string {
			if len(args) < 2 {
				return ""
			}
			switch args[0] {
			case "write_chunk":
				if receivedPath == "" {
					receivedPath = args[1]
				}
				return "Ready"
			case "remove":
				return ""
			}
			return ""
		}),
		testmocks.WithFlipperHandler("__bytes__", flippermock.Handler(func(args []string) string {
			// The mock's bytes-channel handler captures raw payloads
			// the wrapper writes after the chunk-size response. We
			// concatenate them so the test can assert the full content
			// arrived.
			receivedContent += strings.Join(args, " ")
			return ""
		})),
	)
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.flipper = flip

	out, err := a.dispatch(context.Background(), "storage_write", map[string]any{
		"path":    "/ext/agent_test_canary.txt",
		"content": "hello-from-agent-dispatch",
	})
	if err != nil {
		t.Fatalf("dispatch(storage_write): %v", err)
	}
	if out != "ok" {
		t.Errorf("dispatch(storage_write) output = %q, want \"ok\"", out)
	}
}
