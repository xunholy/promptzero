package flipper

import "testing"

// TestStripANSI_Equivalence pins the fast path in stripANSI to be
// behaviour-identical to running the regexp unconditionally: escape
// sequences are still stripped, and any string without an ESC (0x1b) byte
// is returned unchanged. The reference is the regexp-only result, so this
// guards against the fast path ever diverging from ansiEscape.
func TestStripANSI_Equivalence(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"plain", "0 | -55 | 6 | AA:BB:CC:DD:EE:FF | OPEN | HomeWifi"},
		{"empty", ""},
		{"only_escape", "\x1b[32m\x1b[0m"},
		{"colored_prompt", "\x1b[32m>: \x1b[0m"},
		{"mixed", "key: value \x1b[1mbold\x1b[0m tail"},
		{"gt_no_escape", "SSID contains > but no ESC byte"},
		{"multi_escape", "\x1b[31mred\x1b[0m and \x1b[34mblue\x1b[0m"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripANSI(c.in)
			want := ansiEscape.ReplaceAllString(c.in, "")
			if got != want {
				t.Errorf("stripANSI(%q) = %q; regexp-only = %q", c.in, got, want)
			}
		})
	}
}

// benchStripANSILines mirrors a realistic streaming batch: mostly plain
// ASCII CLI rows with a single coloured prompt at the end.
func benchStripANSILines() []string {
	out := make([]string, 0, 128)
	for i := 0; i < 127; i++ {
		out = append(out, "0 | -55 | 6 | AA:BB:CC:DD:EE:FF | OPEN | HomeWifi_2G")
	}
	return append(out, "\x1b[32m>: \x1b[0m")
}

// BenchmarkStripANSIPlain / Lines document the per-line and per-batch hot
// path (stripANSI runs once per streamed line and per tool-call response).
// The ESC fast path keeps the plain-ASCII common case allocation-free.
func BenchmarkStripANSIPlain(b *testing.B) {
	s := "0 | -55 | 6 | AA:BB:CC:DD:EE:FF | OPEN | HomeWifi_2G"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = stripANSI(s)
	}
}

func BenchmarkStripANSILines(b *testing.B) {
	lines := benchStripANSILines()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			_ = stripANSI(l)
		}
	}
}
