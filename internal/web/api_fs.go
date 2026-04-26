//go:build linux

// Flipper Zero filesystem REST handlers — /api/fs/*.
//
// All mutations (upload, delete, mkdir, rename) require the Flipper to be
// connected; when s.flipper is nil every handler returns 503. Path inputs
// are validated before any serial command is issued.

package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/flipper"
)

const (
	// maxReadBytes caps the file size that /api/fs/read will download.
	maxReadBytes = 256 * 1024
	// maxListEntries caps the directory listing before truncation.
	maxListEntries = 1024
	// maxPathLen is the Flipper firmware's effective limit.
	maxPathLen = 240
	// defaultMaxUploadBytes is the default for SetMaxUploadBytes.
	defaultMaxUploadBytes = 1 << 20
)

// ---------------------------------------------------------------------------
// path validation
// ---------------------------------------------------------------------------

// validateFSPath checks that p is safe to forward to the Flipper CLI and
// returns the cleaned path callers should use. The reason is empty when
// the path is valid.
func validateFSPath(p string) (cleaned, reason string) {
	if p == "" {
		return "", "path is required"
	}
	if strings.ContainsRune(p, 0) {
		return "", "path contains NUL byte"
	}
	if len(p) > maxPathLen {
		return "", "path exceeds 240 character limit"
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", "path must not contain .. segments"
		}
	}
	cleaned = path.Clean(p)
	if cleaned == "/int" || strings.HasPrefix(cleaned, "/int/") {
		return "", "browsing /int is not supported"
	}
	if cleaned != "/ext" && !strings.HasPrefix(cleaned, "/ext/") {
		return "", "path must start with /ext"
	}
	return cleaned, ""
}

// ---------------------------------------------------------------------------
// content-type + encoding sniffing
// ---------------------------------------------------------------------------

type fsContentType struct {
	mimeType string
	encoding string // "text" or "base64"
}

func sniffFSContentType(p string) fsContentType {
	ext := strings.ToLower(path.Ext(p))
	switch ext {
	case ".sub":
		return fsContentType{"flipper/sub", "text"}
	case ".nfc":
		return fsContentType{"flipper/nfc", "text"}
	case ".rfid":
		return fsContentType{"flipper/rfid", "text"}
	case ".ir":
		return fsContentType{"flipper/ir", "text"}
	case ".fmf":
		return fsContentType{"flipper/fmf", "text"}
	case ".txt":
		// BadUSB payloads live under /ext/badusb/.
		if strings.Contains(p, "/badusb/") {
			return fsContentType{"flipper/badusb", "text"}
		}
		return fsContentType{"text/plain", "text"}
	case ".csv", ".md", ".json", ".fim":
		return fsContentType{"text/plain", "text"}
	default:
		return fsContentType{"application/octet-stream", "base64"}
	}
}

// ---------------------------------------------------------------------------
// list-output parser
// ---------------------------------------------------------------------------

// fsEntry is one row of a directory listing.
type fsEntry struct {
	Name string `json:"name"`
	Type string `json:"type"` // "dir" or "file"
	Size *int64 `json:"size,omitempty"`
}

// parseStorageList parses `storage list <path>` output.
//
// Momentum / Xtreme firmware emits lines like:
//
//	[D] foldername
//	[F] filename 1234b
func parseStorageList(raw string) []fsEntry {
	var out []fsEntry
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Each entry starts with a tab character in real firmware output.
		line = strings.TrimPrefix(line, "\t")
		if strings.HasPrefix(line, "[D] ") {
			name := strings.TrimPrefix(line, "[D] ")
			out = append(out, fsEntry{Name: strings.TrimSpace(name), Type: "dir"})
		} else if strings.HasPrefix(line, "[F] ") {
			rest := strings.TrimPrefix(line, "[F] ")
			// Strip trailing size annotation like "176433b".
			name, sizeStr := splitFileEntry(rest)
			entry := fsEntry{Name: strings.TrimSpace(name), Type: "file"}
			if sizeStr != "" {
				var sz int64
				// size string: "12345b" — strip trailing 'b'.
				numStr := strings.TrimSuffix(sizeStr, "b")
				var n int
				for _, ch := range numStr {
					if ch >= '0' && ch <= '9' {
						n = n*10 + int(ch-'0')
					}
				}
				sz = int64(n)
				entry.Size = &sz
			}
			out = append(out, entry)
		}
	}
	return out
}

// splitFileEntry splits "[F] <name> <size>b" into name and size token.
// The size token is the last whitespace-separated field if it ends with 'b'
// and is all digits before that.
func splitFileEntry(s string) (name, size string) {
	s = strings.TrimSpace(s)
	i := strings.LastIndexByte(s, ' ')
	if i < 0 {
		return s, ""
	}
	last := s[i+1:]
	if strings.HasSuffix(last, "b") {
		numPart := last[:len(last)-1]
		allDigits := numPart != "" && func() bool {
			for _, c := range numPart {
				if c < '0' || c > '9' {
					return false
				}
			}
			return true
		}()
		if allDigits {
			return s[:i], last
		}
	}
	return s, ""
}

// parentPath returns the parent directory of p, or "/" when at root.
func parentPath(p string) string {
	parent := path.Dir(p)
	if parent == "." {
		return "/"
	}
	return parent
}

// ---------------------------------------------------------------------------
// FAP-busy detection
// ---------------------------------------------------------------------------

// isFAPBusy reports whether the firmware error indicates an application is
// running, blocking CLI access.
func isFAPBusy(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "cannot be run while an application is open")
}

// ---------------------------------------------------------------------------
// audit helper
// ---------------------------------------------------------------------------

func (s *Server) fsAudit(tool, inputPath string) {
	if s.auditLog == nil {
		return
	}
	s.auditLog.Record(tool, map[string]string{"path": inputPath}, "", "low", audit.LevelAction, 0, true)
}

func (s *Server) fsAuditRename(src, dst string) {
	if s.auditLog == nil {
		return
	}
	s.auditLog.Record("web.fs.rename", map[string]string{"src": src, "dst": dst}, "", "low", audit.LevelAction, 0, true)
}

// ---------------------------------------------------------------------------
// /api/fs/list
// ---------------------------------------------------------------------------

func (s *Server) handleFSList(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "flipper not connected")
		return
	}
	if s.refuseIfMirrorActive(w) {
		return
	}
	p, reason := validateFSPath(r.URL.Query().Get("path"))
	if reason != "" {
		writeError(w, http.StatusBadRequest, reason)
		return
	}
	raw, err := s.flipper.StorageList(p)
	if err != nil {
		if isFAPBusy(err) {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	entries := parseStorageList(raw)
	truncated := false
	if len(entries) > maxListEntries {
		entries = entries[:maxListEntries]
		truncated = true
	}
	resp := map[string]any{
		"path":    p,
		"parent":  parentPath(p),
		"entries": entries,
	}
	if truncated {
		resp["truncated"] = true
	}
	respondJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// /api/fs/read
// ---------------------------------------------------------------------------

func (s *Server) handleFSRead(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "flipper not connected")
		return
	}
	if s.refuseIfMirrorActive(w) {
		return
	}
	p, reason := validateFSPath(r.URL.Query().Get("path"))
	if reason != "" {
		writeError(w, http.StatusBadRequest, reason)
		return
	}

	statRaw, err := s.flipper.StorageStat(p)
	if err != nil {
		if isFAPBusy(err) {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	stat := flipper.ParseStorageStat(statRaw)
	if stat.Error != "" {
		writeError(w, http.StatusBadGateway, stat.Error)
		return
	}
	if !stat.Exists {
		writeError(w, http.StatusNotFound, "path not found")
		return
	}
	if stat.SizeBytes > maxReadBytes {
		respondJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error": "file too large to read via API",
			"size":  stat.SizeBytes,
		})
		return
	}

	raw, err := s.flipper.StorageRead(p)
	if err != nil {
		if isFAPBusy(err) {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	ct := sniffFSContentType(p)
	resp := map[string]any{
		"path":         p,
		"size":         stat.SizeBytes,
		"content_type": ct.mimeType,
		"encoding":     ct.encoding,
	}
	if ct.encoding == "text" && utf8.ValidString(raw) {
		resp["content"] = raw
	} else {
		resp["encoding"] = "base64"
		resp["content"] = base64.StdEncoding.EncodeToString([]byte(raw))
	}
	respondJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// /api/fs/stat
// ---------------------------------------------------------------------------

func (s *Server) handleFSStat(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "flipper not connected")
		return
	}
	if s.refuseIfMirrorActive(w) {
		return
	}
	p, reason := validateFSPath(r.URL.Query().Get("path"))
	if reason != "" {
		writeError(w, http.StatusBadRequest, reason)
		return
	}
	raw, err := s.flipper.StorageStat(p)
	if err != nil {
		if isFAPBusy(err) {
			respondJSON(w, http.StatusBadGateway, map[string]any{
				"path":  p,
				"error": err.Error(),
			})
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	result := flipper.ParseStorageStat(raw)
	resp := map[string]any{
		"path":   p,
		"exists": result.Exists,
		"is_dir": result.IsDir,
	}
	if result.SizeBytes > 0 {
		resp["size"] = result.SizeBytes
	}
	if result.Error != "" {
		resp["error"] = result.Error
	}
	respondJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// /api/fs/upload
// ---------------------------------------------------------------------------

func (s *Server) handleFSUpload(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "flipper not connected")
		return
	}
	if s.refuseIfMirrorActive(w) {
		return
	}

	overwrite := r.URL.Query().Get("overwrite") == "true"

	maxBytes := s.maxUploadBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxUploadBytes
	}
	// Wrap with 4 KiB overhead for multipart boundaries.
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+4096)

	if err := r.ParseMultipartForm(maxBytes); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "upload too large or invalid multipart form")
		return
	}

	destPath, reason := validateFSPath(r.FormValue("path"))
	if reason != "" {
		writeError(w, http.StatusBadRequest, reason)
		return
	}

	var file multipart.File
	var handler *multipart.FileHeader
	var ferr error
	file, handler, ferr = r.FormFile("file")
	if ferr != nil {
		writeError(w, http.StatusBadRequest, "missing 'file' part: "+ferr.Error())
		return
	}
	defer file.Close()
	_ = handler

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading upload: "+err.Error())
		return
	}
	if int64(len(data)) > maxBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "upload exceeds limit")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if overwrite {
		if _, rerr := s.flipper.StorageRemove(destPath); rerr != nil {
			if isFAPBusy(rerr) {
				writeError(w, http.StatusBadGateway, rerr.Error())
				return
			}
			// Non-fatal: file may not exist yet.
		}
	}

	if werr := s.flipper.WriteFileCtx(ctx, destPath, data); werr != nil {
		if isFAPBusy(werr) {
			writeError(w, http.StatusBadGateway, werr.Error())
			return
		}
		writeError(w, http.StatusBadGateway, werr.Error())
		return
	}

	s.fsAudit("web.fs.upload", destPath)
	respondJSON(w, http.StatusOK, map[string]any{
		"path": destPath,
		"size": len(data),
	})
}

// ---------------------------------------------------------------------------
// /api/fs/delete
// ---------------------------------------------------------------------------

func (s *Server) handleFSDelete(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "flipper not connected")
		return
	}
	if s.refuseIfMirrorActive(w) {
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	cleaned, reason := validateFSPath(body.Path)
	if reason != "" {
		writeError(w, http.StatusBadRequest, reason)
		return
	}
	if _, err := s.flipper.StorageRemove(cleaned); err != nil {
		if isFAPBusy(err) {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.fsAudit("web.fs.delete", cleaned)
	respondJSON(w, http.StatusOK, map[string]any{"path": cleaned})
}

// ---------------------------------------------------------------------------
// /api/fs/mkdir
// ---------------------------------------------------------------------------

func (s *Server) handleFSMkdir(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "flipper not connected")
		return
	}
	if s.refuseIfMirrorActive(w) {
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	cleaned, reason := validateFSPath(body.Path)
	if reason != "" {
		writeError(w, http.StatusBadRequest, reason)
		return
	}
	if _, err := s.flipper.StorageMkdir(cleaned); err != nil {
		if isFAPBusy(err) {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.fsAudit("web.fs.mkdir", cleaned)
	respondJSON(w, http.StatusOK, map[string]any{"path": cleaned})
}

// ---------------------------------------------------------------------------
// /api/fs/rename
// ---------------------------------------------------------------------------

func (s *Server) handleFSRename(w http.ResponseWriter, r *http.Request) {
	if s.flipper == nil {
		writeError(w, http.StatusServiceUnavailable, "flipper not connected")
		return
	}
	if s.refuseIfMirrorActive(w) {
		return
	}
	var body struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	src, reason := validateFSPath(body.Src)
	if reason != "" {
		writeError(w, http.StatusBadRequest, "src: "+reason)
		return
	}
	dst, reason := validateFSPath(body.Dst)
	if reason != "" {
		writeError(w, http.StatusBadRequest, "dst: "+reason)
		return
	}
	if _, err := s.flipper.StorageRename(src, dst); err != nil {
		if isFAPBusy(err) {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.fsAuditRename(src, dst)
	respondJSON(w, http.StatusOK, map[string]any{"src": src, "dst": dst})
}
