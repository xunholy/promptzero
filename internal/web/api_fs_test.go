//go:build linux

package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// fsServer builds a test httptest.Server with a mock Flipper wired in.
func fsServer(t *testing.T, opts ...mock.Option) (*Server, *httptest.Server, *mock.Mock) {
	t.Helper()
	m := mock.Spawn(t, opts...)
	flip := connectFlipperToMock(t, m)
	s, ts := apiServer(t, &fakeAgent{})
	s.SetFlipper(flip)
	return s, ts, m
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

func TestValidateFSPath(t *testing.T) {
	cases := []struct {
		path   string
		wantOK bool
	}{
		{"/ext", true},
		{"/ext/subghz", true},
		{"/ext/subghz/test.sub", true},
		{"", false},
		{"/int/stuff", false},
		{"/int", false},
		{"/ext/../etc", false},
		{"/home/user", false},
		{"/ext/" + strings.Repeat("a", 300), false},
		{"/ext/good\x00bad", false},
	}
	for _, tc := range cases {
		_, reason := validateFSPath(tc.path)
		if tc.wantOK && reason != "" {
			t.Errorf("validateFSPath(%q) rejected with %q, want ok", tc.path, reason)
		}
		if !tc.wantOK && reason == "" {
			t.Errorf("validateFSPath(%q) accepted, want rejection", tc.path)
		}
	}
}

// ---------------------------------------------------------------------------
// parseStorageList
// ---------------------------------------------------------------------------

func TestParseStorageList(t *testing.T) {
	// Fixture from docs/transcripts/01-storage-list.json — abbreviated.
	raw := "\t[D] update\n\t[D] lfrfid\n\t[F] Manifest 176433b\n\t[D] apps\n\t[D] apps_data\n\t[D] badusb\n\t[F] notes.txt 123b"
	entries := parseStorageList(raw)

	byName := make(map[string]fsEntry)
	for _, e := range entries {
		byName[e.Name] = e
	}

	if byName["update"].Type != "dir" {
		t.Errorf("update type = %q, want dir", byName["update"].Type)
	}
	if byName["apps_data"].Type != "dir" {
		t.Errorf("apps_data type = %q, want dir", byName["apps_data"].Type)
	}
	mani, ok := byName["Manifest"]
	if !ok {
		t.Fatal("Manifest entry not found")
	}
	if mani.Type != "file" {
		t.Errorf("Manifest type = %q, want file", mani.Type)
	}
	if mani.Size == nil || *mani.Size != 176433 {
		t.Errorf("Manifest size = %v, want 176433", mani.Size)
	}
}

func TestParseStorageListTreeFormat(t *testing.T) {
	// Fixture from docs/transcripts/03-storage-tree.json.
	raw := "\t[D] /ext/subghz/Tesla\n\t[F] /ext/subghz/Tesla/Tesla_EU_AM270.sub 5503b\n\t[F] /ext/subghz/Tesla/Tesla_EU_AM650.sub 5503b"
	entries := parseStorageList(raw)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
}

func TestParseStorageListEmpty(t *testing.T) {
	entries := parseStorageList("")
	if len(entries) != 0 {
		t.Errorf("got %d entries for empty input, want 0", len(entries))
	}
}

// TestParseStorageList_EmptyMarshalsAsArray pins the v0.171 fix.
// /api/fs/list builds a response with parseStorageList output under the
// "entries" key. Pre-fix the function returned `var out []fsEntry`, which
// stayed nil for empty / unparseable input and serialised as JSON `null` —
// breaking web-UI consumers that iterate `.entries.forEach(...)`. Same
// defect class as the v0.163-v0.167 nil-slice arc.
func TestParseStorageList_EmptyMarshalsAsArray(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty_string", ""},
		{"whitespace_only", "\n\n\t\n"},
		{"no_recognised_lines", "lorem\nipsum\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := parseStorageList(tc.raw)
			if entries == nil {
				t.Fatalf("parseStorageList returned nil slice; want non-nil empty slice")
			}
			b, err := json.Marshal(map[string]any{"entries": entries})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if got := string(b); got != `{"entries":[]}` {
				t.Errorf("marshalled = %s; want {\"entries\":[]}", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Content-type sniffing
// ---------------------------------------------------------------------------

func TestSniffFSContentType(t *testing.T) {
	cases := []struct {
		path         string
		wantMIME     string
		wantEncoding string
	}{
		{"/ext/subghz/foo.sub", "flipper/sub", "text"},
		{"/ext/nfc/tag.nfc", "flipper/nfc", "text"},
		{"/ext/lfrfid/key.rfid", "flipper/rfid", "text"},
		{"/ext/infrared/remote.ir", "flipper/ir", "text"},
		{"/ext/badusb/payload.txt", "flipper/badusb", "text"},
		{"/ext/notes.txt", "text/plain", "text"},
		{"/ext/data.csv", "text/plain", "text"},
		{"/ext/README.md", "text/plain", "text"},
		{"/ext/something.bin", "application/octet-stream", "base64"},
		{"/ext/unknown", "application/octet-stream", "base64"},
	}
	for _, tc := range cases {
		ct := sniffFSContentType(tc.path)
		if ct.mimeType != tc.wantMIME {
			t.Errorf("sniffFSContentType(%q).mimeType = %q, want %q", tc.path, ct.mimeType, tc.wantMIME)
		}
		if ct.encoding != tc.wantEncoding {
			t.Errorf("sniffFSContentType(%q).encoding = %q, want %q", tc.path, ct.encoding, tc.wantEncoding)
		}
	}
}

// ---------------------------------------------------------------------------
// GET /api/fs/list — no flipper
// ---------------------------------------------------------------------------

func TestFSListNoFlipper(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	_ = s
	// No SetFlipper call.
	code, body := getJSON(t, ts, "/api/fs/list?path=/ext")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%v", code, body)
	}
}

// ---------------------------------------------------------------------------
// GET /api/fs/list — path validation
// ---------------------------------------------------------------------------

func TestFSListBadPaths(t *testing.T) {
	_, ts, _ := fsServer(t)
	badPaths := []string{
		"/api/fs/list?path=",
		"/api/fs/list?path=/int/something",
		"/api/fs/list?path=/etc/passwd",
		"/api/fs/list?path=/ext/../etc",
	}
	for _, p := range badPaths {
		code, _ := getJSON(t, ts, p)
		if code != http.StatusBadRequest {
			t.Errorf("GET %s: status=%d, want 400", p, code)
		}
	}
}

// ---------------------------------------------------------------------------
// GET /api/fs/list — happy path
// ---------------------------------------------------------------------------

func TestFSListHappyPath(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "list" {
				return "\t[D] subghz\n\t[D] nfc\n\t[F] Manifest 176433b"
			}
			return ""
		}),
	)
	code, body := getJSON(t, ts, "/api/fs/list?path=/ext")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
	if body["path"] != "/ext" {
		t.Errorf("path = %v, want /ext", body["path"])
	}
	if body["parent"] != "/" {
		t.Errorf("parent = %v, want /", body["parent"])
	}
	entries, _ := body["entries"].([]any)
	if len(entries) != 3 {
		t.Errorf("entries len = %d, want 3", len(entries))
	}
}

func TestFSListTruncation(t *testing.T) {
	// Build a raw listing of 1025 entries.
	var sb strings.Builder
	for i := 0; i < 1025; i++ {
		fmt.Fprintf(&sb, "\t[F] file%04d.txt 10b\n", i)
	}
	listOut := sb.String()

	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "list" {
				return listOut
			}
			return ""
		}),
	)
	code, body := getJSON(t, ts, "/api/fs/list?path=/ext")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	entries, _ := body["entries"].([]any)
	if len(entries) != maxListEntries {
		t.Errorf("entries len = %d, want %d", len(entries), maxListEntries)
	}
	if body["truncated"] != true {
		t.Errorf("truncated = %v, want true", body["truncated"])
	}
}

// ---------------------------------------------------------------------------
// GET /api/fs/stat — happy path
// ---------------------------------------------------------------------------

func TestFSStatFile(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "stat" {
				return "File, size: 5503"
			}
			return ""
		}),
	)
	code, body := getJSON(t, ts, "/api/fs/stat?path=/ext/subghz/foo.sub")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
	if body["exists"] != true {
		t.Errorf("exists = %v, want true", body["exists"])
	}
	if body["is_dir"] != false {
		t.Errorf("is_dir = %v, want false", body["is_dir"])
	}
	if size, _ := body["size"].(float64); int(size) != 5503 {
		t.Errorf("size = %v, want 5503", body["size"])
	}
}

func TestFSStatDir(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "stat" {
				return "Directory"
			}
			return ""
		}),
	)
	code, body := getJSON(t, ts, "/api/fs/stat?path=/ext/subghz")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
	if body["is_dir"] != true {
		t.Errorf("is_dir = %v, want true", body["is_dir"])
	}
}

// ---------------------------------------------------------------------------
// GET /api/fs/read — size cap (413)
// ---------------------------------------------------------------------------

func TestFSReadTooBig(t *testing.T) {
	// Stat reports a file larger than 256 KiB.
	bigSize := int64(maxReadBytes + 1)
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "stat" {
				return fmt.Sprintf("File, size: %d", bigSize)
			}
			return ""
		}),
	)
	code, body := getJSON(t, ts, "/api/fs/read?path=/ext/big.bin")
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%v", code, body)
	}
	if _, ok := body["size"]; !ok {
		t.Errorf("response missing 'size' field on 413; body=%v", body)
	}
}

// ---------------------------------------------------------------------------
// GET /api/fs/read — content-type and encoding
// ---------------------------------------------------------------------------

func TestFSReadSubFile(t *testing.T) {
	const content = "Filetype: Flipper SubGhz Key File\nFrequency: 433920000\n"
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			switch {
			case len(args) >= 2 && args[0] == "stat":
				return fmt.Sprintf("File, size: %d", len(content))
			case len(args) >= 2 && args[0] == "read":
				return content
			}
			return ""
		}),
	)
	code, body := getJSON(t, ts, "/api/fs/read?path=/ext/subghz/tesla.sub")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
	if body["content_type"] != "flipper/sub" {
		t.Errorf("content_type = %v, want flipper/sub", body["content_type"])
	}
	if body["encoding"] != "text" {
		t.Errorf("encoding = %v, want text", body["encoding"])
	}
}

func TestFSReadBinaryFile(t *testing.T) {
	const content = "\x00\x01\x02binary"
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			switch {
			case len(args) >= 2 && args[0] == "stat":
				return fmt.Sprintf("File, size: %d", len(content))
			case len(args) >= 2 && args[0] == "read":
				return content
			}
			return ""
		}),
	)
	code, body := getJSON(t, ts, "/api/fs/read?path=/ext/firmware.bin")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
	if body["encoding"] != "base64" {
		t.Errorf("encoding = %v, want base64", body["encoding"])
	}
}

// ---------------------------------------------------------------------------
// POST /api/fs/upload — no flipper
// ---------------------------------------------------------------------------

func TestFSUploadNoFlipper(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	_ = s

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("path", "/ext/test.sub")
	fw, _ := mw.CreateFormFile("file", "test.sub")
	_, _ = fw.Write([]byte("Filetype: Flipper SubGhz Key File\n"))
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/fs/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// POST /api/fs/upload — happy path (no overwrite)
// ---------------------------------------------------------------------------

func TestFSUploadHappyPath(t *testing.T) {
	written := make(chan string, 1)
	_, ts, m := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			return ""
		}),
	)
	_ = m
	_ = written

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("path", "/ext/subghz/test.sub")
	fw, _ := mw.CreateFormFile("file", "test.sub")
	_, _ = fw.Write([]byte("Filetype: Flipper SubGhz Key File\nFrequency: 433920000\n"))
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/fs/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}
}

// ---------------------------------------------------------------------------
// POST /api/fs/upload — with overwrite=true
// ---------------------------------------------------------------------------

func TestFSUploadOverwrite(t *testing.T) {
	// Track whether a remove command was issued.
	var removeCalled bool
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "remove" {
				removeCalled = true
			}
			return ""
		}),
	)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("path", "/ext/test.sub")
	fw, _ := mw.CreateFormFile("file", "test.sub")
	_, _ = fw.Write([]byte("content"))
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/fs/upload?overwrite=true", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !removeCalled {
		t.Error("overwrite=true: StorageRemove was not called before write")
	}
}

// ---------------------------------------------------------------------------
// POST /api/fs/upload — bad path
// ---------------------------------------------------------------------------

func TestFSUploadBadPath(t *testing.T) {
	_, ts, _ := fsServer(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("path", "/int/malicious")
	fw, _ := mw.CreateFormFile("file", "mal.bin")
	_, _ = fw.Write([]byte("bad"))
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/fs/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// POST /api/fs/delete — happy path + bad path
// ---------------------------------------------------------------------------

func TestFSDeleteHappyPath(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			return ""
		}),
	)
	code, raw := postJSON(t, ts, "/api/fs/delete", map[string]string{"path": "/ext/old.sub"})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", code, raw)
	}
}

func TestFSDeleteBadPath(t *testing.T) {
	_, ts, _ := fsServer(t)
	code, _ := postJSON(t, ts, "/api/fs/delete", map[string]string{"path": "/int/something"})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}

// ---------------------------------------------------------------------------
// POST /api/fs/mkdir — happy path + bad path
// ---------------------------------------------------------------------------

func TestFSMkdirHappyPath(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			return ""
		}),
	)
	code, raw := postJSON(t, ts, "/api/fs/mkdir", map[string]string{"path": "/ext/newdir"})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", code, raw)
	}
}

func TestFSMkdirBadPath(t *testing.T) {
	_, ts, _ := fsServer(t)
	code, _ := postJSON(t, ts, "/api/fs/mkdir", map[string]string{"path": ""})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}

// ---------------------------------------------------------------------------
// POST /api/fs/rename — happy path + bad path
// ---------------------------------------------------------------------------

func TestFSRenameHappyPath(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			return ""
		}),
	)
	code, raw := postJSON(t, ts, "/api/fs/rename", map[string]string{
		"src": "/ext/old.sub",
		"dst": "/ext/new.sub",
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", code, raw)
	}
}

func TestFSRenameBadSrc(t *testing.T) {
	_, ts, _ := fsServer(t)
	code, _ := postJSON(t, ts, "/api/fs/rename", map[string]string{
		"src": "/int/bad",
		"dst": "/ext/ok.sub",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}

func TestFSRenameBadDst(t *testing.T) {
	_, ts, _ := fsServer(t)
	code, _ := postJSON(t, ts, "/api/fs/rename", map[string]string{
		"src": "/ext/ok.sub",
		"dst": "/int/bad",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}

// ---------------------------------------------------------------------------
// FAP-busy passthrough: firmware returns the expected error string
// ---------------------------------------------------------------------------

func TestFSListFAPBusy(t *testing.T) {
	// Use a mock that doesn't set the storage handler — we instead wire an
	// error response via the default "storage" handler returning the FAP-busy message.
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string {
			// Real firmware returns this string; the CLI layer wraps it in an error.
			// Our mock returns it as body; flipper.Exec sees no "error:" prefix so
			// it returns the raw body. That won't trigger isFAPBusy unless the
			// error string propagates. Instead we test the isFAPBusy detector directly.
			return ""
		}),
	)
	_ = ts
}

// TestFAPBusyDetector verifies isFAPBusy recognizes the firmware error string.
func TestFAPBusyDetector(t *testing.T) {
	err := fmt.Errorf("storage error: cannot be run while an application is open")
	if !isFAPBusy(err) {
		t.Error("isFAPBusy returned false for known FAP-busy error string")
	}
	if isFAPBusy(nil) {
		t.Error("isFAPBusy returned true for nil error")
	}
	other := fmt.Errorf("some other error")
	if isFAPBusy(other) {
		t.Error("isFAPBusy returned true for unrelated error")
	}
}

// ---------------------------------------------------------------------------
// Server.maxUploadBytes setter
// ---------------------------------------------------------------------------

func TestSetMaxUploadBytes(t *testing.T) {
	s := &Server{
		agent:             &fakeAgent{},
		addr:              "127.0.0.1:0",
		conns:             make(map[*sessionConn]struct{}),
		confirms:          make(map[string]chan agent.ConfirmResponse),
		heartbeatInterval: 100 * time.Millisecond,
		heartbeatTimeout:  2 * time.Second,
		writeTimeout:      2 * time.Second,
		startedAt:         time.Now(),
	}
	s.attachAgentCallbacks()
	s.SetMaxUploadBytes(512 * 1024)
	if s.maxUploadBytes != 512*1024 {
		t.Errorf("maxUploadBytes = %d, want %d", s.maxUploadBytes, 512*1024)
	}
}

// ---------------------------------------------------------------------------
// Server UI context
// ---------------------------------------------------------------------------

func TestServerUIContext(t *testing.T) {
	s := &Server{
		agent:             &fakeAgent{},
		addr:              "127.0.0.1:0",
		conns:             make(map[*sessionConn]struct{}),
		confirms:          make(map[string]chan agent.ConfirmResponse),
		heartbeatInterval: 100 * time.Millisecond,
		heartbeatTimeout:  2 * time.Second,
		writeTimeout:      2 * time.Second,
		startedAt:         time.Now(),
	}
	s.attachAgentCallbacks()

	v, p := s.UIContext()
	if v != "" || p != "" {
		t.Errorf("initial UIContext = (%q, %q), want empty", v, p)
	}

	var gotView, gotPath string
	s.OnUIContext(func(view, path string) {
		gotView = view
		gotPath = path
	})
	s.setUIContextFromWS("preview", "/ext/subghz/garage.sub")

	v, p = s.UIContext()
	if v != "preview" || p != "/ext/subghz/garage.sub" {
		t.Errorf("UIContext = (%q, %q), want (preview, /ext/subghz/garage.sub)", v, p)
	}
	if gotView != "preview" || gotPath != "/ext/subghz/garage.sub" {
		t.Errorf("onUIContext callback = (%q, %q), want (preview, /ext/subghz/garage.sub)", gotView, gotPath)
	}

	// Hostile view values are rejected; previous value remains.
	s.setUIContextFromWS("evil\" injected=\"yes", "/ext/foo")
	v, p = s.UIContext()
	if v != "preview" || p != "/ext/subghz/garage.sub" {
		t.Errorf("hostile view changed state to (%q, %q)", v, p)
	}
}

// ---------------------------------------------------------------------------
// POST /api/fs/upload — BadUSB validator gate (row 5)
// ---------------------------------------------------------------------------

// uploadBadUSB is a helper that posts a multipart upload to /api/fs/upload
// targeting a badusb path. Returns the HTTP status code and response body.
func uploadBadUSB(t *testing.T, ts *httptest.Server, path, payload, query string) (int, []byte) {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("path", path)
	fw, _ := mw.CreateFormFile("file", "payload.txt")
	_, _ = fw.Write([]byte(payload))
	mw.Close()

	url := ts.URL + "/api/fs/upload"
	if query != "" {
		url += "?" + query
	}
	req, _ := http.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// criticalBadUSBPayload is a DuckyScript payload that triggers SeverityCritical
// (rm -rf / wipes the filesystem).
const criticalBadUSBPayload = "STRING rm -rf /\n"

// TestFSUploadBadUSBCritical_RejectedWithoutBypass verifies that uploading a
// BadUSB script with a critical-severity finding is refused (422) unless
// the operator supplies ?validator_bypass=true.
func TestFSUploadBadUSBCritical_RejectedWithoutBypass(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string { return "" }),
	)

	code, body := uploadBadUSB(t, ts, "/ext/badusb/evil.txt", criticalBadUSBPayload, "")
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", code, body)
	}
	if !strings.Contains(string(body), "critical-severity") {
		t.Errorf("response body should mention critical-severity, got %s", body)
	}
}

// TestFSUploadBadUSBCritical_AllowedWithBypass verifies that uploading a
// BadUSB script with a critical finding is permitted when the operator
// sets ?validator_bypass=true.
func TestFSUploadBadUSBCritical_AllowedWithBypass(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string { return "" }),
	)

	code, body := uploadBadUSB(t, ts, "/ext/badusb/evil.txt", criticalBadUSBPayload, "validator_bypass=true")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with bypass; body=%s", code, body)
	}
}

// TestFSUploadNonBadUSB_UnchangedByValidator verifies that uploading to a
// non-badusb path (e.g. /ext/subghz/) is not affected by the validator
// gate — it should still succeed regardless of content.
func TestFSUploadNonBadUSB_UnchangedByValidator(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string { return "" }),
	)

	// Use a "dangerous" payload content but on a non-badusb path.
	code, body := uploadBadUSB(t, ts, "/ext/subghz/test.sub", criticalBadUSBPayload, "")
	if code != http.StatusOK {
		t.Fatalf("non-badusb upload should be unaffected by validator (status=%d, body=%s)", code, body)
	}
}

// TestFSUploadBadUSBClean_Accepted verifies that a clean BadUSB payload
// (no critical findings) is accepted without bypass.
func TestFSUploadBadUSBClean_Accepted(t *testing.T) {
	_, ts, _ := fsServer(t,
		mock.WithHandler("storage", func(args []string) string { return "" }),
	)

	cleanPayload := "REM benign script\nDELAY 500\nSTRING Hello World\n"
	code, body := uploadBadUSB(t, ts, "/ext/badusb/clean.txt", cleanPayload, "")
	if code != http.StatusOK {
		t.Fatalf("clean badusb payload should be accepted (status=%d, body=%s)", code, body)
	}
}
