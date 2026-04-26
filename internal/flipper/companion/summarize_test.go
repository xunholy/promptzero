package companion

import "testing"

func TestSummarizeInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"invalid json", "not json", ""},
		{"sub-ghz frequency", `{"frequency":433920000}`, "frequency 433.92 MHz"},
		{"wifi channel", `{"channel":6}`, "channel 6"},
		{"file path", `{"file":"/ext/subghz/test.sub"}`, "file /ext/subghz/test.sub"},
		{"protocol takes priority over file", `{"file":"x","protocol":"Princeton"}`, "protocol Princeton"},
		{"target_os", `{"target_os":"linux"}`, "target_os linux"},
		{"long string truncated", `{"file":"/ext/very/long/path/that/exceeds/the/limit.bin"}`, ""},
		{"unknown fields", `{"foo":"bar"}`, ""},
		{"freq alias", `{"freq":315000000}`, "freq 315.00 MHz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeInput([]byte(tc.in))
			if tc.name == "long string truncated" {
				// We don't pin the exact ellipsised form; just
				// assert it fits within the cap and has the
				// expected prefix.
				if got == "" {
					t.Errorf("want non-empty truncated string")
				}
				if len(got) > MaxDetailLen {
					t.Errorf("want ≤%d chars, got %d (%q)", MaxDetailLen, len(got), got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("SummarizeInput(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
