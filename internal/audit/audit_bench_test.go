package audit

import (
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkRecord measures the per-call cost of Record on the dispatch
// hot path. Use as a baseline before introducing prepared statements or
// async writes — re-run after a change to see whether the win is real.
//
// Run with: go test -bench=BenchmarkRecord -benchmem ./internal/audit/
func BenchmarkRecord(b *testing.B) {
	dir := b.TempDir()
	l, err := Open(filepath.Join(dir, "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()

	input := map[string]any{
		"path":      "/ext/nfc/test.nfc",
		"frequency": 433920000,
		"duration":  3,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Record("nfc_detect", input, "scanner", "low", LevelAction, 12*time.Millisecond, true)
	}
}
