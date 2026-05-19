package tools

import (
	"context"
	"strings"
	"testing"
)

// TestHTTPMessageDecodeHandler_GET pins a GET request through
// the Spec handler.
func TestHTTPMessageDecodeHandler_GET(t *testing.T) {
	req := "GET /api/users HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"User-Agent: curl/8.4.0\r\n" +
		"Authorization: Bearer abc.def.ghi\r\n" +
		"\r\n"
	out, err := httpMessageDecodeHandler(context.Background(), nil, map[string]any{
		"message": req,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"method": "GET"`) {
		t.Errorf("expected method GET:\n%s", out)
	}
	if !strings.Contains(out, `"host": "api.example.com"`) {
		t.Errorf("expected host:\n%s", out)
	}
	if !strings.Contains(out, `"scheme": "Bearer"`) {
		t.Errorf("expected Bearer auth:\n%s", out)
	}
}

// TestHTTPMessageDecodeHandler_404 pins a 404 response.
func TestHTTPMessageDecodeHandler_404(t *testing.T) {
	resp := "HTTP/1.1 404 Not Found\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	out, err := httpMessageDecodeHandler(context.Background(), nil, map[string]any{
		"message": resp,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"status_code": 404`) {
		t.Errorf("expected status_code 404:\n%s", out)
	}
	if !strings.Contains(out, `"status_name": "Not Found"`) {
		t.Errorf("expected status_name:\n%s", out)
	}
}

func TestHTTPMessageDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := httpMessageDecodeHandler(context.Background(), nil, map[string]any{"message": ""})
	if err == nil {
		t.Fatal("want error for empty message")
	}
}

func TestHTTPMessageDecodeHandler_RejectsMalformed(t *testing.T) {
	_, err := httpMessageDecodeHandler(context.Background(), nil, map[string]any{
		"message": "GET\r\n\r\n",
	})
	if err == nil {
		t.Fatal("want error for malformed request line")
	}
}
