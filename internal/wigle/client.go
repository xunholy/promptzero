// SPDX-License-Identifier: AGPL-3.0-or-later

package wigle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// DefaultUploadEndpoint is the WiGLE v2 file-upload URL. A wardrive CSV is
// POSTed here as multipart/form-data under the "file" field.
const DefaultUploadEndpoint = "https://api.wigle.net/api/v2/file/upload"

// uploadTimeout bounds a single upload round-trip. Wardrive CSVs are small
// (kilobytes to a few MB), so this exists to cap a hung connection, not to
// accommodate a large transfer.
const uploadTimeout = 60 * time.Second

// MaxUploadBytes caps the CSV size the client will send. Even a long drive is
// a few MB; this stops a runaway or fat-fingered input from streaming an
// unbounded body to WiGLE.
const MaxUploadBytes = 32 << 20 // 32 MiB

// maxResponseBytes bounds how much of WiGLE's response the client reads, so a
// misbehaving or hostile endpoint can't stream an unbounded body into memory.
const maxResponseBytes = 1 << 20 // 1 MiB

// Client uploads wardrive CSVs to the WiGLE API. It carries the operator's
// API credentials and never logs them. Construct with NewClient.
type Client struct {
	// BaseURL is the upload endpoint. Empty uses DefaultUploadEndpoint; tests
	// point it at an httptest server so no live egress occurs.
	BaseURL string
	// HTTP is the transport. Nil is replaced with a client bounded by
	// uploadTimeout on first use.
	HTTP *http.Client

	apiName  string
	apiToken string
}

// NewClient builds a WiGLE upload client. endpoint may be empty to use the
// public API. apiName/apiToken are the account's HTTP Basic credentials.
func NewClient(apiName, apiToken, endpoint string) *Client {
	return &Client{
		BaseURL:  endpoint,
		HTTP:     &http.Client{Timeout: uploadTimeout},
		apiName:  apiName,
		apiToken: apiToken,
	}
}

// UploadResult is the parsed outcome of a WiGLE upload. success and message
// are WiGLE's documented contract fields; Results carries the per-file detail
// (transaction ids etc.) opaquely, since its exact shape is not part of our
// contract.
type UploadResult struct {
	Success bool             `json:"success"`
	Message string           `json:"message,omitempty"`
	Results []map[string]any `json:"results,omitempty"`
}

// TransactionIDs best-effort extracts the WiGLE transaction ids from Results
// (the value under a "transid" key), for surfacing to the operator. Missing
// or oddly-shaped entries are skipped rather than erroring.
func (r *UploadResult) TransactionIDs() []string {
	var ids []string
	for _, res := range r.Results {
		if v, ok := res["transid"].(string); ok && v != "" {
			ids = append(ids, v)
		}
	}
	return ids
}

// Upload POSTs csv to WiGLE as a wardrive file named filename. donate marks
// the data as donated (public) when true. It returns an error for missing
// credentials, an oversized or empty CSV, a transport failure, a non-2xx
// status (401 auth failure and 429 rate limit are reported distinctly), a
// malformed body, or a success:false response.
func (c *Client) Upload(ctx context.Context, filename string, csv []byte, donate bool) (*UploadResult, error) {
	if c.apiName == "" || c.apiToken == "" {
		return nil, fmt.Errorf("wigle: missing API credentials")
	}
	if len(csv) == 0 {
		return nil, fmt.Errorf("wigle: empty CSV — nothing to upload")
	}
	if len(csv) > MaxUploadBytes {
		return nil, fmt.Errorf("wigle: CSV too large (%d bytes, max %d)", len(csv), MaxUploadBytes)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return nil, fmt.Errorf("wigle: build multipart: %w", err)
	}
	if _, err := fw.Write(csv); err != nil {
		return nil, fmt.Errorf("wigle: write csv: %w", err)
	}
	donateVal := "off"
	if donate {
		donateVal = "on"
	}
	if err := mw.WriteField("donate", donateVal); err != nil {
		return nil, fmt.Errorf("wigle: donate field: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("wigle: close multipart: %w", err)
	}

	endpoint := c.BaseURL
	if endpoint == "" {
		endpoint = DefaultUploadEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return nil, fmt.Errorf("wigle: build request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	// HTTP Basic: API name is the user, API token the password. Set on the
	// request header only — never logged.
	req.SetBasicAuth(c.apiName, c.apiToken)

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: uploadTimeout}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wigle: upload: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("wigle: read response: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("wigle: authentication failed (401) — check the WIGLE_API_NAME / WIGLE_API_TOKEN credentials")
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("wigle: rate limited (429) — the WiGLE upload quota is exhausted; retry later")
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, fmt.Errorf("wigle: upload failed: HTTP %d: %s", resp.StatusCode, snippet(respBytes))
	}

	var res UploadResult
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("wigle: malformed response: %w (body: %s)", err, snippet(respBytes))
	}
	if !res.Success {
		msg := strings.TrimSpace(res.Message)
		if msg == "" {
			msg = "upload rejected (no message)"
		}
		return nil, fmt.Errorf("wigle: %s", msg)
	}
	return &res, nil
}

// snippet returns a short, single-line preview of a response body for error
// messages — trimmed and capped so a large or multi-line body doesn't bloat
// the surfaced error.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
