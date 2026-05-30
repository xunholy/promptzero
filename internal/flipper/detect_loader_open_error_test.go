package flipper

import "testing"

// TestDetectLoaderOpenError covers the `loader open` silent-failure path:
// the firmware prints success as EMPTY output and a failure as a banner on
// stdout with no CLI error (verified momentum/mntm-dev:
// 'Application "<name>" not found'). A benign launch banner without an
// error marker must not be misread as a failure.
func TestDetectLoaderOpenError(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		wantErr bool
	}{
		{"app not found", `Application "__NoSuchApp__" not found`, true},
		{"missing script", "Failed to open file", true},
		{"storage error", "Storage error: x", true},
		{"clean success (empty)", "", false},
		{"clean success (whitespace)", "  \n", false},
		{"benign banner", "App started", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := detectLoaderOpenError(c.out); (err != nil) != c.wantErr {
				t.Errorf("detectLoaderOpenError(%q) err=%v; wantErr=%v", c.out, err, c.wantErr)
			}
		})
	}
}
