package web

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// badusbUpload posts an executable BadUSB script to /api/fs/upload on ts and
// returns the response status + body.
func badusbUpload(t *testing.T, ts *httptest.Server) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("path", "/ext/badusb/deploy.txt")
	fw, _ := mw.CreateFormFile("file", "deploy.txt")
	_, _ = fw.Write([]byte("STRING hello world\n"))
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/fs/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// TestWebFSUpload_BadUSBFailClosedWithoutAudit pins the --web audit fix: a
// High-risk BadUSB deploy over the web surface is refused (fail-closed, like
// the agent/MCP surfaces) when no audit log is wired. RequireOpen fires before
// the device write, so no flipper is needed to prove the refusal.
func TestWebFSUpload_BadUSBFailClosedWithoutAudit(t *testing.T) {
	// Flipper present (so we pass the connectivity check and reach the gate),
	// but no audit log — the pre-fix state. RequireOpen must refuse.
	s, ts, _ := fsServer(t, mock.WithHandler("storage", func(args []string) string { return "" }))
	s.SetAuditLog(nil)
	status, body := badusbUpload(t, ts)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (RequireOpen fail-closed); body=%s", status, body)
	}
	if !strings.Contains(body, "audit log not initialized") {
		t.Fatalf("body = %q, want a RequireOpen refusal", body)
	}
}

// TestWebFSUpload_BadUSBProceedsWithAudit is the paired case: once an audit log
// is wired (as production always does), the same deploy proceeds.
func TestWebFSUpload_BadUSBProceedsWithAudit(t *testing.T) {
	// fsServer wires both a mock flipper and (now) an audit log.
	_, ts, _ := fsServer(t, mock.WithHandler("storage", func(args []string) string { return "" }))
	status, body := badusbUpload(t, ts)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (audit wired → proceeds); body=%s", status, body)
	}
}
