package wordlists_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/wordlists"
)

func TestCommon_NonEmpty(t *testing.T) {
	lines := wordlists.Common()
	if len(lines) == 0 {
		t.Fatal("Common() returned empty list")
	}
}

func TestCommon_MinimumSize(t *testing.T) {
	lines := wordlists.Common()
	const want = 400
	if len(lines) < want {
		t.Errorf("Common() has %d entries, want at least %d", len(lines), want)
	}
}

func TestCommon_NoCommentLines(t *testing.T) {
	for i, line := range wordlists.Common() {
		if strings.HasPrefix(line, "#") {
			t.Errorf("Common()[%d] = %q: comment line leaked through", i, line)
		}
	}
}

func TestCommon_NoBlankLines(t *testing.T) {
	for i, line := range wordlists.Common() {
		if strings.TrimSpace(line) == "" {
			t.Errorf("Common()[%d]: blank line leaked through", i)
		}
	}
}

func TestCommon_ContainsExpectedPaths(t *testing.T) {
	lines := wordlists.Common()
	lineSet := make(map[string]bool, len(lines))
	for _, l := range lines {
		lineSet[l] = true
	}
	for _, want := range []string{
		"robots.txt",
		"admin",
		".git/HEAD",
		".env",
		"login",
		"api",
	} {
		if !lineSet[want] {
			t.Errorf("common.txt does not contain expected entry %q", want)
		}
	}
}

func TestCommonRaw_ContainsHeader(t *testing.T) {
	raw := wordlists.CommonRaw()
	if !strings.Contains(raw, "PromptZero") {
		t.Error("CommonRaw() does not contain expected header comment")
	}
}

func TestPasswords_NonEmpty(t *testing.T) {
	lines := wordlists.Passwords()
	if len(lines) == 0 {
		t.Fatal("Passwords() returned empty list")
	}
}

func TestPasswords_MinimumSize(t *testing.T) {
	lines := wordlists.Passwords()
	const want = 50
	if len(lines) < want {
		t.Errorf("Passwords() has %d entries, want at least %d", len(lines), want)
	}
}

func TestPasswords_NoCommentLines(t *testing.T) {
	for i, line := range wordlists.Passwords() {
		if strings.HasPrefix(line, "#") {
			t.Errorf("Passwords()[%d] = %q: comment line leaked through", i, line)
		}
	}
}

func TestPasswords_ContainsCommonEntries(t *testing.T) {
	lines := wordlists.Passwords()
	lineSet := make(map[string]bool, len(lines))
	for _, l := range lines {
		lineSet[l] = true
	}
	for _, want := range []string{"password", "123456", "admin"} {
		if !lineSet[want] {
			t.Errorf("passwords.txt does not contain expected entry %q", want)
		}
	}
}

func TestPasswordsRaw_ContainsHeader(t *testing.T) {
	raw := wordlists.PasswordsRaw()
	if !strings.Contains(raw, "PromptZero") {
		t.Error("PasswordsRaw() does not contain expected header comment")
	}
}
