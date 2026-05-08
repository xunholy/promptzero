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
