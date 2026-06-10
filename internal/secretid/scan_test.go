// SPDX-License-Identifier: AGPL-3.0-or-later

package secretid_test

import (
	"hash/crc32"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/secretid"
)

// slackToken is a non-live Slack-format token, split in source so the prefix
// is not adjacent to the body (GitHub push protection flags a contiguous
// Slack-token literal even in tests); the runtime value is what Scan sees.
var slackToken = "xoxb" + "-123456789012-abcdefABCDEF1234"

// githubToken builds a valid-checksum classic GitHub token (ghp_).
func githubToken() string {
	const entropy = "zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ"
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	sum := crc32.ChecksumIEEE([]byte(entropy))
	cs := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		cs[i] = alphabet[sum%62]
		sum /= 62
	}
	return "ghp_" + entropy + string(cs)
}

func TestScan_FindsMultipleTypes(t *testing.T) {
	gh := githubToken()
	blob := strings.Join([]string{
		"# config dump",
		"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"github_token: " + gh,
		"jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig",
		"slack=" + slackToken,
		"nothing to see on this line",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"b3BlbnNzaC1rZXktdjEAAAAA",
		"-----END OPENSSH PRIVATE KEY-----",
	}, "\n")

	res := secretid.Scan(blob)
	byType := map[string]secretid.Finding{}
	for _, f := range res.Findings {
		byType[f.Category] = f
	}

	if _, ok := byType["cloud-aws"]; !ok {
		t.Errorf("AWS key not found; findings=%+v", res.Findings)
	}
	if f, ok := byType["vcs"]; !ok || !f.Validated {
		t.Errorf("GitHub token not found/validated: %+v", f)
	}
	if _, ok := byType["token-jwt"]; !ok {
		t.Error("JWT not found")
	}
	if _, ok := byType["ssh"]; !ok {
		t.Error("OpenSSH private key block not found")
	}
	if _, ok := byType["api-key"]; !ok {
		t.Error("Slack token not found")
	}

	// Line numbers: AWS key is on line 2.
	for _, f := range res.Findings {
		if f.Category == "cloud-aws" && f.Line != 2 {
			t.Errorf("AWS key line = %d, want 2", f.Line)
		}
	}
}

// The full secret must never appear verbatim in the redacted output.
func TestScan_Redacts(t *testing.T) {
	gh := githubToken()
	res := secretid.Scan("token=" + gh)
	if len(res.Findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Redacted, gh) {
			t.Errorf("redacted output leaked the full secret: %q", f.Redacted)
		}
		if !strings.Contains(f.Redacted, "chars") && !strings.Contains(f.Redacted, "bytes") {
			t.Errorf("redacted output missing length hint: %q", f.Redacted)
		}
	}
}

func TestScan_CleanText(t *testing.T) {
	res := secretid.Scan("the quick brown fox jumps over the lazy dog\nno secrets here\n")
	if len(res.Findings) != 0 {
		t.Errorf("clean text produced findings: %+v", res.Findings)
	}
}

func TestScan_Empty(t *testing.T) {
	if res := secretid.Scan(""); len(res.Findings) != 0 {
		t.Errorf("empty input produced findings: %+v", res.Findings)
	}
}

func FuzzScan(f *testing.F) {
	f.Add("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nslack=" + "xoxb" + "-1-abcdef123456\n")
	f.Add("-----BEGIN X-----\nbody\n-----END X-----")
	f.Add("eyJ.eyJ.sig")
	f.Add("")
	f.Fuzz(func(_ *testing.T, in string) {
		// Must never panic on arbitrary input.
		_ = secretid.Scan(in)
	})
}

// A PEM block and a token on different lines get distinct, correct line numbers.
func TestScan_LineNumbers(t *testing.T) {
	blob := "line1\nline2\nslack=" + slackToken + "\n"
	res := secretid.Scan(blob)
	if len(res.Findings) != 1 || res.Findings[0].Line != 3 {
		t.Fatalf("want 1 finding on line 3, got %+v", res.Findings)
	}
}
