package web

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestHealthz_LivenessUnauthenticated: /healthz returns 200 "ok" with no auth.
func TestHealthz_Liveness(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	resp, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "ok\n" {
		t.Fatalf("body = %q, want %q", b, "ok\n")
	}
}

// TestReadyz_ReadinessSnapshot: /readyz returns 200 JSON with subsystem state,
// unauthenticated, and does not flap when no device is connected.
func TestReadyz_ReadinessSnapshot(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.SetFlipperConnected(true)
	resp, err := ts.Client().Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "ready" {
		t.Errorf("status = %v, want ready", got["status"])
	}
	if got["flipper_connected"] != true {
		t.Errorf("flipper_connected = %v, want true", got["flipper_connected"])
	}
	if _, ok := got["version"]; !ok {
		t.Error("missing version field")
	}
}
