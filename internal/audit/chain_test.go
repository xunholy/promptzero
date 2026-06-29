// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"testing"
	"time"
)

func TestChainHash_Deterministic(t *testing.T) {
	a := chainHash("prev", "2026-01-01T00:00:00Z", "nfc", "{}", "out", "low", "action", "s1", 12, true)
	b := chainHash("prev", "2026-01-01T00:00:00Z", "nfc", "{}", "out", "low", "action", "s1", 12, true)
	if a != b {
		t.Fatal("chainHash is not deterministic")
	}
	if len(a) != 64 {
		t.Errorf("hex sha256 length = %d, want 64", len(a))
	}
	// Any field change must change the hash.
	if a == chainHash("prev", "2026-01-01T00:00:00Z", "nfc", "{}", "OUT", "low", "action", "s1", 12, true) {
		t.Error("hash unchanged after output change")
	}
	if a == chainHash("PREV", "2026-01-01T00:00:00Z", "nfc", "{}", "out", "low", "action", "s1", 12, true) {
		t.Error("hash unchanged after prevHash change (chain link)")
	}
	if a == chainHash("prev", "2026-01-01T00:00:00Z", "nfc", "{}", "out", "low", "action", "s1", 12, false) {
		t.Error("hash unchanged after success change")
	}
}

func TestVerifyChain_Intact(t *testing.T) {
	l := openTestLog(t)
	for i := 0; i < 5; i++ {
		l.Record("nfc_detect", map[string]int{"i": i}, "ok", "low", LevelAction, time.Millisecond, true)
	}
	res, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.Valid || res.HashedRows != 5 || res.LegacyRows != 0 || res.FirstBrokenID != 0 {
		t.Errorf("got %+v", res)
	}
	if res.HeadHash == "" {
		t.Error("HeadHash should be set for a non-empty chain")
	}
}

func TestVerifyChain_DetectsTamper(t *testing.T) {
	l := openTestLog(t)
	for i := 0; i < 4; i++ {
		l.Record("nfc", map[string]int{"i": i}, "ok", "low", LevelAction, 0, true)
	}
	// Edit row id=2's output directly (as a sqlite3 attacker would), without
	// recomputing the chain.
	if _, err := l.db.Exec(`UPDATE audit_log SET output='HACKED' WHERE id=2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	res, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Valid {
		t.Fatal("tamper not detected")
	}
	if res.FirstBrokenID != 2 {
		t.Errorf("FirstBrokenID = %d, want 2", res.FirstBrokenID)
	}
}

func TestVerifyChain_DetectsDeletion(t *testing.T) {
	l := openTestLog(t)
	for i := 0; i < 5; i++ {
		l.Record("nfc", map[string]int{"i": i}, "ok", "low", LevelAction, 0, true)
	}
	if _, err := l.db.Exec(`DELETE FROM audit_log WHERE id=3`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	res, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Valid {
		t.Fatal("deletion not detected")
	}
	// The row after the hole breaks (its prev-link pointed at the deleted row).
	if res.FirstBrokenID != 4 {
		t.Errorf("FirstBrokenID = %d, want 4", res.FirstBrokenID)
	}
}

func TestVerifyChain_LegacyPrefixCountedSuffixVerified(t *testing.T) {
	l := openTestLog(t)
	// A pre-hash-chain row: insert directly with no entry_hash.
	if _, err := l.db.Exec(`INSERT INTO audit_log
		(timestamp, tool, input, output, risk, level, session_id, duration_ms, success)
		VALUES ('2020-01-01T00:00:00Z','legacy','{}','x','low','action','old',0,1)`); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	// New rows chain from genesis (head is still empty — the legacy row carries
	// no hash).
	l.Record("nfc", map[string]int{"i": 0}, "ok", "low", LevelAction, 0, true)
	l.Record("nfc", map[string]int{"i": 1}, "ok", "low", LevelAction, 0, true)

	res, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.LegacyRows != 1 {
		t.Errorf("LegacyRows = %d, want 1", res.LegacyRows)
	}
	if res.HashedRows != 2 {
		t.Errorf("HashedRows = %d, want 2", res.HashedRows)
	}
	if !res.Valid {
		t.Errorf("hashed suffix should verify over a legacy prefix: %+v", res)
	}
}

// TestVerifyChain_LegacyTailDoesNotFalsePositive guards the head re-seed
// against a hashless row sitting at the TAIL (e.g. written by a pre-chain
// binary after a version downgrade, or inserted directly). Open must re-seed
// the chain head from the last HASHED row, not the literal last row — else the
// next insert chains from genesis while earlier hashed rows exist, and
// VerifyChain (which skips hashless rows but keeps the running prevHash) reports
// a false break on an untampered log.
func TestVerifyChain_LegacyTailDoesNotFalsePositive(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.db"

	l1, err := Open(path)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	l1.Record("nfc", map[string]int{"i": 0}, "ok", "low", LevelAction, 0, true)
	l1.Record("nfc", map[string]int{"i": 1}, "ok", "low", LevelAction, 0, true)
	wantHead := l1.headHash
	// A hashless row appended AFTER the hashed rows (legacy tail).
	if _, err := l1.db.Exec(`INSERT INTO audit_log
		(timestamp, tool, input, output, risk, level, session_id, duration_ms, success)
		VALUES ('2020-01-01T00:00:00Z','legacy','{}','x','low','action','old',0,1)`); err != nil {
		t.Fatalf("legacy tail insert: %v", err)
	}
	l1.Close()

	l2, err := Open(path)
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer l2.Close()
	// Head must be re-seeded from the last hashed row, NOT reset to empty by
	// the hashless tail.
	if l2.headHash != wantHead {
		t.Errorf("reopened headHash = %q, want %q (hashless tail reset the head)", l2.headHash, wantHead)
	}
	l2.Record("nfc", map[string]int{"i": 2}, "ok", "low", LevelAction, 0, true)

	res, err := l2.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.Valid {
		t.Errorf("untampered log with a legacy tail must verify, got break at id %d: %+v", res.FirstBrokenID, res)
	}
	if res.HashedRows != 3 || res.LegacyRows != 1 {
		t.Errorf("HashedRows=%d LegacyRows=%d, want 3 and 1", res.HashedRows, res.LegacyRows)
	}
}

// TestVerifyChain_ContinuesAcrossReopen confirms Open re-seeds the chain head
// so a reopened log extends rather than forks the existing chain.
func TestVerifyChain_ContinuesAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.db"

	l1, err := Open(path)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	l1.Record("nfc", map[string]int{"i": 0}, "ok", "low", LevelAction, 0, true)
	l1.Record("nfc", map[string]int{"i": 1}, "ok", "low", LevelAction, 0, true)
	headBefore := l1.headHash
	l1.Close()

	l2, err := Open(path)
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer l2.Close()
	if l2.headHash != headBefore {
		t.Errorf("reopened headHash = %q, want %q (chain not re-seeded)", l2.headHash, headBefore)
	}
	l2.Record("nfc", map[string]int{"i": 2}, "ok", "low", LevelAction, 0, true)

	res, err := l2.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.Valid || res.HashedRows != 3 {
		t.Errorf("chain should span the reopen: %+v", res)
	}
}
