// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"database/sql"
	"testing"
)

// rechainAll simulates a sophisticated attacker who, after editing content,
// recomputes the ENTIRE hash chain so the in-DB check (VerifyChain) passes
// again. The out-of-band anchor is what still catches this.
func rechainAll(t *testing.T, l *Log) {
	t.Helper()
	rows, err := l.db.Query(`SELECT id, timestamp, tool, input, output, risk, level, session_id, duration_ms, success
		FROM audit_log WHERE entry_hash IS NOT NULL AND entry_hash <> '' ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("rechain query: %v", err)
	}
	type r struct {
		id                int64
		ts, tool, lvl     string
		in, out, rk, sess sql.NullString
		dur               sql.NullInt64
		ok                bool
	}
	var all []r
	for rows.Next() {
		var x r
		if err := rows.Scan(&x.id, &x.ts, &x.tool, &x.in, &x.out, &x.rk, &x.lvl, &x.sess, &x.dur, &x.ok); err != nil {
			rows.Close()
			t.Fatalf("rechain scan: %v", err)
		}
		all = append(all, x)
	}
	rows.Close()
	prev := ""
	for _, x := range all {
		h := chainHash(prev, x.ts, x.tool, x.in.String, x.out.String, x.rk.String, x.lvl, x.sess.String, x.dur.Int64, x.ok)
		if _, err := l.db.Exec(`UPDATE audit_log SET entry_hash=? WHERE id=?`, h, x.id); err != nil {
			t.Fatalf("rechain update: %v", err)
		}
		prev = h
	}
}

func TestVerifyChainAgainst_AnchorMatchesAndProtectsPrefix(t *testing.T) {
	l := openTestLog(t)
	for i := 0; i < 3; i++ {
		l.Record("nfc", map[string]int{"i": i}, "ok", "low", LevelAction, 0, true)
	}
	base, _ := l.VerifyChain()
	if base.AnchorChecked {
		t.Error("VerifyChain() (nil anchor) must report AnchorChecked=false")
	}
	anchor := &CheckpointAnchor{HashedRows: base.HashedRows, HeadHash: base.HeadHash}

	// Appending new rows after the checkpoint is legitimate; the anchor
	// protects the prefix it covers, not future growth.
	l.Record("nfc", map[string]int{"i": 3}, "ok", "low", LevelAction, 0, true)
	l.Record("nfc", map[string]int{"i": 4}, "ok", "low", LevelAction, 0, true)

	res, err := l.VerifyChainAgainst(anchor)
	if err != nil {
		t.Fatalf("VerifyChainAgainst: %v", err)
	}
	if !res.Valid || !res.AnchorChecked || !res.AnchorValid {
		t.Errorf("anchor should validate over a grown chain: %+v", res)
	}
}

// TestVerifyChainAgainst_DetectsFullRewrite is the crown-jewel case: a
// consistent full-chain rewrite passes the in-DB check, but the anchor
// catches it.
func TestVerifyChainAgainst_DetectsFullRewrite(t *testing.T) {
	l := openTestLog(t)
	for i := 0; i < 4; i++ {
		l.Record("nfc", map[string]int{"i": i}, "ok", "low", LevelAction, 0, true)
	}
	base, _ := l.VerifyChain()
	anchor := &CheckpointAnchor{HashedRows: base.HashedRows, HeadHash: base.HeadHash}

	// Tamper a row AND recompute the whole chain (the sophisticated attack).
	if _, err := l.db.Exec(`UPDATE audit_log SET output='HACKED' WHERE id=2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	rechainAll(t, l)

	res, err := l.VerifyChainAgainst(anchor)
	if err != nil {
		t.Fatalf("VerifyChainAgainst: %v", err)
	}
	// The in-DB chain is now internally consistent — this is exactly the gap.
	if !res.Valid {
		t.Error("a consistently re-hashed chain should pass the in-DB check (demonstrating the gap)")
	}
	// ...but the anchor must catch the rewrite.
	if res.AnchorValid {
		t.Error("anchor failed to detect a full-chain rewrite")
	}
	if res.AnchorDetail == "" {
		t.Error("expected an anchor detail describing the rewrite")
	}
}

func TestVerifyChainAgainst_DetectsTailTruncation(t *testing.T) {
	l := openTestLog(t)
	for i := 0; i < 5; i++ {
		l.Record("nfc", map[string]int{"i": i}, "ok", "low", LevelAction, 0, true)
	}
	base, _ := l.VerifyChain()
	anchor := &CheckpointAnchor{HashedRows: base.HashedRows, HeadHash: base.HeadHash} // 5 rows

	// Delete the two newest rows.
	if _, err := l.db.Exec(`DELETE FROM audit_log WHERE id IN (4,5)`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	res, err := l.VerifyChainAgainst(anchor)
	if err != nil {
		t.Fatalf("VerifyChainAgainst: %v", err)
	}
	// The surviving prefix is internally consistent, so the in-DB check
	// passes — only the anchor reveals the truncation.
	if !res.Valid {
		t.Error("truncated prefix should still pass the in-DB check")
	}
	if res.AnchorValid {
		t.Error("anchor failed to detect tail truncation")
	}
}

func TestVerifyChainAgainst_InvalidAnchor(t *testing.T) {
	l := openTestLog(t)
	l.Record("nfc", map[string]int{"i": 0}, "ok", "low", LevelAction, 0, true)
	res, err := l.VerifyChainAgainst(&CheckpointAnchor{HashedRows: 0, HeadHash: ""})
	if err != nil {
		t.Fatalf("VerifyChainAgainst: %v", err)
	}
	if !res.AnchorChecked || res.AnchorValid {
		t.Errorf("invalid anchor should be checked and invalid: %+v", res)
	}
}
