// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/config"
)

// TestWigleUpload_DisabledByDefault pins gate 1: with wigle.upload_enabled
// unset (the default), the tool refuses — the egress capability is off until
// the operator deliberately arms it.
func TestWigleUpload_DisabledByDefault(t *testing.T) {
	deps := &Deps{Config: &config.Config{}}
	_, err := wigleUploadHandler(context.Background(), deps, map[string]any{"csv": "WigleWifi-1.4\n"})
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("upload must refuse when wigle.upload_enabled is false, got %v", err)
	}
}

// TestWigleUpload_RequiresCredentials: armed but no credentials → refuse before
// any network call.
func TestWigleUpload_RequiresCredentials(t *testing.T) {
	deps := &Deps{Config: &config.Config{Wigle: config.WigleConfig{UploadEnabled: true}}}
	_, err := wigleUploadHandler(context.Background(), deps, map[string]any{"csv": "x"})
	if err == nil || !strings.Contains(err.Error(), "missing credentials") {
		t.Errorf("upload must refuse without credentials, got %v", err)
	}
}

func TestWigleUpload_RequiresCSV(t *testing.T) {
	deps := &Deps{Config: &config.Config{Wigle: config.WigleConfig{
		UploadEnabled: true, APIName: "n", APIToken: "t",
	}}}
	_, err := wigleUploadHandler(context.Background(), deps, map[string]any{"csv": "   "})
	if err == nil || !strings.Contains(err.Error(), "csv is required") {
		t.Errorf("blank csv must be rejected, got %v", err)
	}
}

// TestWigleUpload_Success drives a full upload against a mock endpoint (no live
// egress), and checks the credentials are sent but never echoed into the result.
func TestWigleUpload_Success(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"success":true,"results":[{"transid":"T1"}]}`))
	}))
	defer srv.Close()

	deps := &Deps{Config: &config.Config{Wigle: config.WigleConfig{
		UploadEnabled: true, APIName: "AIDx", APIToken: "s3cr3t-tok", Endpoint: srv.URL,
	}}}
	out, err := wigleUploadHandler(context.Background(), deps, map[string]any{"csv": "WigleWifi-1.4\nMAC\n"})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if !strings.Contains(out, `"success": true`) || !strings.Contains(out, "T1") {
		t.Errorf("result missing success/transid: %s", out)
	}
	if gotAuth == "" {
		t.Error("expected a Basic auth header to be sent to WiGLE")
	}
	if strings.Contains(out, "s3cr3t-tok") {
		t.Errorf("result leaked the API token: %s", out)
	}
}

// TestWigleUpload_DonateOptIn: donate defaults false and is passed through.
func TestWigleUpload_DonateOptIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()
	deps := &Deps{Config: &config.Config{Wigle: config.WigleConfig{
		UploadEnabled: true, APIName: "n", APIToken: "t", Endpoint: srv.URL,
	}}}
	out, err := wigleUploadHandler(context.Background(), deps, map[string]any{"csv": "x"})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if !strings.Contains(out, `"donated": false`) {
		t.Errorf("donate should default to false in the result: %s", out)
	}
}

// TestWigleUpload_SurfacesRemoteError: a WiGLE-side failure (success:false)
// propagates as a tool error, not a false success.
func TestWigleUpload_SurfacesRemoteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"message":"invalid columns"}`))
	}))
	defer srv.Close()
	deps := &Deps{Config: &config.Config{Wigle: config.WigleConfig{
		UploadEnabled: true, APIName: "n", APIToken: "t", Endpoint: srv.URL,
	}}}
	_, err := wigleUploadHandler(context.Background(), deps, map[string]any{"csv": "x"})
	if err == nil || !strings.Contains(err.Error(), "invalid columns") {
		t.Errorf("a WiGLE-side failure must surface as an error, got %v", err)
	}
}
