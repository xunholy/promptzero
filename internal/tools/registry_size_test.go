package tools_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/tools"
)

func TestRegistrySize(t *testing.T) {
	const expected = 3 // Wave 0: device_info, storage_write, nfc_detect. Bumped per wave.
	if got := len(tools.All()); got != expected {
		t.Errorf("registry size = %d, want %d (wave-by-wave checked in §D of runbook)", got, expected)
	}
}
