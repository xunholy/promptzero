// SPDX-License-Identifier: AGPL-3.0-or-later

package wigle

import (
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockWigle spins up an httptest server that mimics the WiGLE upload endpoint.
// It never reaches the real network. The handler is supplied per test.
func mockWigle(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestClient_Upload_Success(t *testing.T) {
	var gotFile []byte
	var gotDonate, gotAuth, gotContentType string
	srv := mockWigle(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		mediaType, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if !strings.HasPrefix(mediaType, "multipart/") {
			t.Errorf("content-type = %q, want multipart", mediaType)
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(part)
			switch part.FormName() {
			case "file":
				gotFile = b
			case "donate":
				gotDonate = string(b)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"results":[{"transid":"20260101-00042"}]}`))
	})

	c := NewClient("AIDtest", "s3cr3t", srv.URL)
	res, err := c.Upload(context.Background(), "drive.csv", []byte("WigleWifi-1.4\nMAC,SSID\n"), true)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if !res.Success {
		t.Error("Success = false, want true")
	}
	if ids := res.TransactionIDs(); len(ids) != 1 || ids[0] != "20260101-00042" {
		t.Errorf("TransactionIDs = %v, want [20260101-00042]", ids)
	}
	if string(gotFile) != "WigleWifi-1.4\nMAC,SSID\n" {
		t.Errorf("uploaded file body = %q", gotFile)
	}
	if gotDonate != "on" {
		t.Errorf("donate = %q, want on", gotDonate)
	}
	// Basic auth with the API name/token.
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("AIDtest:s3cr3t"))
	if gotAuth != wantAuth {
		t.Errorf("Authorization = %q, want %q", gotAuth, wantAuth)
	}
	if !strings.HasPrefix(gotContentType, "multipart/form-data") {
		t.Errorf("Content-Type = %q", gotContentType)
	}
}

func TestClient_Upload_DonateOffByDefault(t *testing.T) {
	var gotDonate string
	srv := mockWigle(t, func(w http.ResponseWriter, r *http.Request) {
		_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			if part.FormName() == "donate" {
				b, _ := io.ReadAll(part)
				gotDonate = string(b)
			}
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	c := NewClient("n", "t", srv.URL)
	if _, err := c.Upload(context.Background(), "d.csv", []byte("x"), false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if gotDonate != "off" {
		t.Errorf("donate = %q, want off (donation must be opt-in)", gotDonate)
	}
}

func TestClient_Upload_AuthFailure(t *testing.T) {
	srv := mockWigle(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"message":"unauthorized"}`))
	})
	c := NewClient("n", "t", srv.URL)
	_, err := c.Upload(context.Background(), "d.csv", []byte("x"), false)
	if err == nil || !strings.Contains(err.Error(), "authentication failed (401)") {
		t.Errorf("want a 401 auth error, got %v", err)
	}
}

func TestClient_Upload_RateLimited(t *testing.T) {
	srv := mockWigle(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"success":false,"message":"too many"}`))
	})
	c := NewClient("n", "t", srv.URL)
	_, err := c.Upload(context.Background(), "d.csv", []byte("x"), false)
	if err == nil || !strings.Contains(err.Error(), "rate limited (429)") {
		t.Errorf("want a 429 rate-limit error, got %v", err)
	}
}

func TestClient_Upload_SuccessFalseIsError(t *testing.T) {
	srv := mockWigle(t, func(w http.ResponseWriter, _ *http.Request) {
		// 200 OK but the body reports failure — must be surfaced as an error.
		_, _ = w.Write([]byte(`{"success":false,"message":"bad columns"}`))
	})
	c := NewClient("n", "t", srv.URL)
	_, err := c.Upload(context.Background(), "d.csv", []byte("x"), false)
	if err == nil || !strings.Contains(err.Error(), "bad columns") {
		t.Errorf("want the WiGLE message surfaced, got %v", err)
	}
}

func TestClient_Upload_MalformedResponse(t *testing.T) {
	srv := mockWigle(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	})
	c := NewClient("n", "t", srv.URL)
	_, err := c.Upload(context.Background(), "d.csv", []byte("x"), false)
	if err == nil || !strings.Contains(err.Error(), "malformed response") {
		t.Errorf("want a malformed-response error, got %v", err)
	}
}

func TestClient_Upload_GuardsInputs(t *testing.T) {
	// Missing credentials, empty CSV, and oversized CSV are rejected before any
	// network call. Use a server that fails the test if it is ever hit.
	srv := mockWigle(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("server must not be reached for a locally-rejected input")
	})
	if _, err := NewClient("", "", srv.URL).Upload(context.Background(), "d.csv", []byte("x"), false); err == nil {
		t.Error("missing credentials should error")
	}
	if _, err := NewClient("n", "t", srv.URL).Upload(context.Background(), "d.csv", nil, false); err == nil {
		t.Error("empty CSV should error")
	}
	big := make([]byte, MaxUploadBytes+1)
	if _, err := NewClient("n", "t", srv.URL).Upload(context.Background(), "d.csv", big, false); err == nil {
		t.Error("oversized CSV should error")
	}
}
