//go:build linux

package testmocks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

// TestMockFlipperDeviceInfo walks a trivial round trip through the pty
// mock: DeviceInfo should return the default Xtreme-ish blob the mock
// ships with.
func TestMockFlipperDeviceInfo(t *testing.T) {
	flip := NewMockFlipper(t)
	out, err := flip.DeviceInfo()
	if err != nil {
		t.Fatalf("DeviceInfo: %v", err)
	}
	if !strings.Contains(out, "hardware_uid") {
		t.Fatalf("device_info body missing hardware_uid:\n%s", out)
	}
}

// TestMockMarauderInfo exercises the fake serial port end-to-end:
// Info() should round-trip the canned response we registered.
func TestMockMarauderInfo(t *testing.T) {
	m := NewMockMarauder(t, WithMarauderResponse("info", "version: 1.11.1"))
	out, err := m.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !strings.Contains(out, "1.11.1") {
		t.Fatalf("info body missing version: %q", out)
	}
}

// TestMockAnthropicDispatchesOneTool builds a one-entry script and
// streams a single message — the returned content should carry the
// tool_use block the script requested, so the caller can feed it back
// through their real dispatcher.
func TestMockAnthropicDispatchesOneTool(t *testing.T) {
	client := NewMockAnthropic(t, []AnthropicScript{
		{Tool: "device_info", ToolInput: map[string]any{}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := client.Messages.NewStreaming(ctx, anthropic.MessageNewParams{
		Model:     "claude-mock",
		MaxTokens: 128,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock("please call device_info")),
		},
	})
	defer stream.Close()

	var msg anthropic.Message
	for stream.Next() {
		if err := msg.Accumulate(stream.Current()); err != nil {
			t.Fatalf("accumulate: %v", err)
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream err: %v", err)
	}
	if len(msg.Content) != 1 {
		t.Fatalf("want 1 content block, got %d", len(msg.Content))
	}
	if msg.Content[0].Type != "tool_use" {
		t.Fatalf("want tool_use block, got %q", msg.Content[0].Type)
	}
	if msg.Content[0].Name != "device_info" {
		t.Fatalf("want tool name device_info, got %q", msg.Content[0].Name)
	}
	if msg.StopReason != "tool_use" {
		t.Fatalf("want stop_reason=tool_use, got %q", msg.StopReason)
	}
}

// TestMockAnthropicText covers the plain-text path — no tool_use, just a
// rendered assistant message.
func TestMockAnthropicText(t *testing.T) {
	client := NewMockAnthropic(t, []AnthropicScript{{Text: "hello operator"}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := client.Messages.NewStreaming(ctx, anthropic.MessageNewParams{
		Model:     "claude-mock",
		MaxTokens: 32,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock("hi")),
		},
	})
	defer stream.Close()

	var msg anthropic.Message
	for stream.Next() {
		if err := msg.Accumulate(stream.Current()); err != nil {
			t.Fatalf("accumulate: %v", err)
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream err: %v", err)
	}
	if len(msg.Content) != 1 || msg.Content[0].Type != "text" {
		t.Fatalf("want one text block, got %+v", msg.Content)
	}
	if msg.Content[0].Text != "hello operator" {
		t.Fatalf("want text body, got %q", msg.Content[0].Text)
	}
}
