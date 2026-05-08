package targetmem

import (
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targetmem.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpen_CreatesSchema(t *testing.T) {
	s := newTestStore(t)
	if s == nil {
		t.Fatal("Open returned nil")
	}
}

func TestRemember_AndLookup(t *testing.T) {
	s := newTestStore(t)
	tgt := Target{
		Identifier: "aa:bb:cc:dd:ee:ff",
		Kind:       KindBSSID,
		Facts:      map[string]any{"ssid": "home-wifi", "channel": 6},
	}
	if err := s.Remember(tgt); err != nil {
		t.Fatalf("Remember: %v", err)
	}
	got, ok, err := s.Lookup("aa:bb:cc:dd:ee:ff", KindBSSID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("Lookup should find the target")
	}
	if got.Identifier != tgt.Identifier {
		t.Errorf("Identifier = %q", got.Identifier)
	}
	facts, ok := got.Facts.(map[string]any)
	if !ok {
		t.Fatalf("Facts type = %T, want map", got.Facts)
	}
	if facts["ssid"] != "home-wifi" {
		t.Errorf("Facts[ssid] = %v", facts["ssid"])
	}
	if got.FirstSeen.IsZero() {
		t.Errorf("FirstSeen should be set")
	}
}

func TestRemember_UpsertPreservesFirstSeen(t *testing.T) {
	s := newTestStore(t)
	tgt := Target{Identifier: "ABCDEF", Kind: KindNFCUID, Facts: map[string]any{"type": "NTAG215"}}
	if err := s.Remember(tgt); err != nil {
		t.Fatalf("first Remember: %v", err)
	}
	first, _, _ := s.Lookup("ABCDEF", KindNFCUID)

	// Second remember with new facts. FirstSeen should NOT move.
	tgt.Facts = map[string]any{"type": "NTAG215", "seen_at": "office"}
	if err := s.Remember(tgt); err != nil {
		t.Fatalf("second Remember: %v", err)
	}
	second, _, _ := s.Lookup("ABCDEF", KindNFCUID)

	if !first.FirstSeen.Equal(second.FirstSeen) {
		t.Errorf("FirstSeen moved: %v vs %v", first.FirstSeen, second.FirstSeen)
	}
	// LastSeen bumped.
	if !second.LastSeen.After(first.LastSeen) && !second.LastSeen.Equal(first.LastSeen) {
		t.Errorf("LastSeen should be >= first observation: %v vs %v", second.LastSeen, first.LastSeen)
	}
	// Facts updated.
	facts := second.Facts.(map[string]any)
	if facts["seen_at"] != "office" {
		t.Errorf("Facts not upserted: %v", facts)
	}
}

func TestLookup_Missing(t *testing.T) {
	s := newTestStore(t)
	_, ok, err := s.Lookup("never-seen", KindBSSID)
	if err != nil {
		t.Errorf("Lookup: %v", err)
	}
	if ok {
		t.Error("Lookup should return ok=false for missing target")
	}
}

func TestRemember_RejectsEmptyIdentifier(t *testing.T) {
	s := newTestStore(t)
	err := s.Remember(Target{Kind: KindBSSID})
	if err == nil {
		t.Error("empty identifier should error")
	}
}

func TestRemember_DefaultsKind(t *testing.T) {
	s := newTestStore(t)
	if err := s.Remember(Target{Identifier: "x"}); err != nil {
		t.Fatalf("Remember: %v", err)
	}
	// Default kind is KindBSSID.
	got, ok, _ := s.Lookup("x", KindBSSID)
	if !ok {
		t.Fatal("default-kind target not found under KindBSSID")
	}
	if got.Kind != KindBSSID {
		t.Errorf("Kind = %q", got.Kind)
	}
}

func TestRecent(t *testing.T) {
	s := newTestStore(t)
	for i, id := range []string{"a", "b", "c"} {
		if err := s.Remember(Target{Identifier: id, Kind: KindBSSID, Facts: map[string]any{"n": i}}); err != nil {
			t.Fatalf("Remember %s: %v", id, err)
		}
	}
	recent, err := s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 3 {
		t.Fatalf("len = %d, want 3", len(recent))
	}
}

// TestRecent_CapsAtMaxRecent pins the upper-bound clamp on Recent(n).
// Without the cap an LLM tool call asking for limit=1000000 would
// scan the entire targets table and serialise a multi-MB JSON tool
// result. Seed MaxRecent+5 rows, ask for 999999, confirm the result
// length is exactly MaxRecent.
func TestRecent_CapsAtMaxRecent(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; seeds 1005 rows — rerun without -short")
	}
	s := newTestStore(t)
	// Seed MaxRecent+5 rows so the cap fires.
	for i := 0; i < MaxRecent+5; i++ {
		if err := s.Remember(Target{
			Identifier: "t-" + strings.Repeat("0", 4-len(strings.TrimLeft(intToStr(i), "0"))) + intToStr(i),
			Kind:       KindBSSID,
		}); err != nil {
			t.Fatalf("Remember %d: %v", i, err)
		}
	}
	recent, err := s.Recent(999999)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != MaxRecent {
		t.Errorf("len(recent) = %d, want MaxRecent = %d", len(recent), MaxRecent)
	}
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	const digits = "0123456789"
	var buf []byte
	for i > 0 {
		buf = append([]byte{digits[i%10]}, buf...)
		i /= 10
	}
	return string(buf)
}

// TestLookup_CorruptFactsJSON confirms that a row with malformed
// facts JSON (e.g. due to an external edit or schema drift) doesn't
// fail the whole lookup — the row is returned with empty Facts and
// the unmarshal error surfaces via obs warning instead of vanishing.
func TestLookup_CorruptFactsJSON(t *testing.T) {
	s := newTestStore(t)
	_, err := s.db.Exec(`INSERT INTO targets (identifier, kind, facts, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)`,
		"corrupt-id", KindBSSID, "not valid json{",
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, ok, err := s.Lookup("corrupt-id", KindBSSID)
	if err != nil {
		t.Fatalf("Lookup: %v (want nil — corrupt facts should not fail lookup)", err)
	}
	if !ok {
		t.Fatal("Lookup should still find the row")
	}
	if got.Identifier != "corrupt-id" {
		t.Errorf("Identifier = %q", got.Identifier)
	}
	if got.Facts != nil {
		t.Errorf("Facts = %v; want nil on unmarshal failure", got.Facts)
	}
}

func TestForget(t *testing.T) {
	s := newTestStore(t)
	_ = s.Remember(Target{Identifier: "doomed", Kind: KindBSSID})
	if err := s.Forget("doomed", KindBSSID); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	_, ok, _ := s.Lookup("doomed", KindBSSID)
	if ok {
		t.Error("target still present after Forget")
	}
	// Forget on missing is a no-op.
	if err := s.Forget("nonexistent", KindBSSID); err != nil {
		t.Errorf("Forget on missing should not error: %v", err)
	}
}

func TestDefaultPath_IsPromptzeroScoped(t *testing.T) {
	p, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if !strings.HasSuffix(p, filepath.Join(".promptzero", "targetmem.db")) {
		t.Errorf("unexpected default path: %q", p)
	}
}
