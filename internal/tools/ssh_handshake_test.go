package tools

import (
	"context"
	"strings"
	"testing"
)

// TestSSHHandshakeDecodeHandler_VersionBanner pins an OpenSSH
// banner through the Spec handler.
func TestSSHHandshakeDecodeHandler_VersionBanner(t *testing.T) {
	out, err := sshHandshakeDecodeHandler(context.Background(), nil, map[string]any{
		"input": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"protocol_version": "2.0"`) {
		t.Errorf("expected protocol_version 2.0:\n%s", out)
	}
	if !strings.Contains(out, `"software_version": "OpenSSH_9.6p1"`) {
		t.Errorf("expected software_version OpenSSH_9.6p1:\n%s", out)
	}
}

func TestSSHHandshakeDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := sshHandshakeDecodeHandler(context.Background(), nil, map[string]any{"input": ""})
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestSSHHandshakeDecodeHandler_RejectsBadHex(t *testing.T) {
	_, err := sshHandshakeDecodeHandler(context.Background(), nil, map[string]any{"input": "ZZZZ"})
	if err == nil {
		t.Fatal("want error for invalid hex")
	}
}
