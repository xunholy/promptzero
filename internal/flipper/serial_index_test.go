package flipper

import (
	"bytes"
	"strings"
	"testing"
)

// TestIndexOfPrompt_NoPromptInWindowedSearch pins down a regression where a
// 1024-byte search window returned a positive false offset (`-1 + searchStart`)
// when the prompt was not yet in the tail. Buffers in the 1024-2048 byte range
// were incorrectly reported as "prompt found" partway through real output,
// truncating multi-line responses like device_info.
func TestIndexOfPrompt_NoPromptInWindowedSearch(t *testing.T) {
	// 1500 bytes of plausible device_info-like output, no prompt anywhere.
	body := strings.Repeat("hardware_uid                  : 556E686F6C790000\r\n", 30)
	if len(body) < 1500 {
		t.Fatalf("test input too short: %d", len(body))
	}
	if got := indexOfPrompt([]byte(body)); got != -1 {
		t.Fatalf("indexOfPrompt without prompt should return -1, got %d", got)
	}
}

func TestIndexOfPrompt_PromptInWindow(t *testing.T) {
	body := strings.Repeat("x", 2000) + ">: "
	got := indexOfPrompt([]byte(body))
	want := bytes.LastIndex([]byte(body), []byte(">: "))
	if got != want {
		t.Fatalf("indexOfPrompt = %d, want %d", got, want)
	}
}

func TestIndexOfPrompt_SmallBuffer(t *testing.T) {
	if got := indexOfPrompt([]byte("a")); got != -1 {
		t.Fatalf("indexOfPrompt of 1-byte input = %d, want -1", got)
	}
	if got := indexOfPrompt([]byte(">: ")); got != 0 {
		t.Fatalf("indexOfPrompt of bare prompt = %d, want 0", got)
	}
}
