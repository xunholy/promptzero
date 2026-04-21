package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper"
)

func TestBuildDeviceStateBlock_NilFlipper(t *testing.T) {
	got := buildDeviceStateBlock(context.Background(), nil)
	if got != "" {
		t.Fatalf("nil flipper should yield empty block, got %q", got)
	}
}

func TestBuildDeviceStateBlock_ConnectedFlipper(t *testing.T) {
	f := flipper.NewForTest(flipper.Capabilities{
		FirmwareFork:    "Momentum",
		FirmwareVersion: "0.99.1",
	})
	got := buildDeviceStateBlock(context.Background(), f)
	if !strings.HasPrefix(got, "<device-state>\n") {
		t.Fatalf("missing open tag: %q", got)
	}
	if !strings.HasSuffix(got, "\n</device-state>\n\n") {
		t.Fatalf("missing close tag + newlines: %q", got)
	}
	if !strings.Contains(got, `"fork":"Momentum"`) {
		t.Errorf("block should contain fork, got: %q", got)
	}
	if !strings.Contains(got, `"connected":true`) {
		t.Errorf("block should report connected=true when caps populated, got: %q", got)
	}
}
