package tools

import (
	"context"
	"strings"
	"testing"
)

// TestJWTDecodeHandler_StandardHS256 pins the canonical jwt.io
// HS256 example through the Spec handler.
func TestJWTDecodeHandler_StandardHS256(t *testing.T) {
	out, err := jwtDecodeHandler(context.Background(), nil, map[string]any{
		"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
			"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"header_algorithm": "HS256"`) {
		t.Errorf("expected HS256:\n%s", out)
	}
	if !strings.Contains(out, `"subject": "1234567890"`) {
		t.Errorf("expected subject 1234567890:\n%s", out)
	}
	if !strings.Contains(out, `"alg_none": false`) {
		t.Errorf("expected alg_none false:\n%s", out)
	}
}

func TestJWTDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := jwtDecodeHandler(context.Background(), nil, map[string]any{"token": ""})
	if err == nil {
		t.Fatal("want error for empty token")
	}
}

func TestJWTDecodeHandler_RejectsBadFormat(t *testing.T) {
	// 4 segments — neither JWS (3) nor JWE (5).
	_, err := jwtDecodeHandler(context.Background(), nil, map[string]any{"token": "not.a.jwt.invalid"})
	if err == nil {
		t.Fatal("want error for malformed token (4 segments)")
	}
}
