package audit

import "testing"

// A row whose success column is NULL or a non-0/1 value (which an attacker with
// DB write could set — success is an independent column from the hash chain)
// must NOT vanish from the query surfaces. The old code scanned success into a
// bare bool, so such a row failed the scan and was silently dropped (continue),
// hiding it from an operator reviewing the audit log — while VerifyChain still
// flagged the tamper, the forensic *read* omitted the row entirely. All four
// query paths now scan success as NullInt64 (NULL/tampered -> false, row kept).
func TestQuery_PoisonedSuccessRowRetained(t *testing.T) {
	for _, poke := range []string{
		`UPDATE audit_log SET success=NULL WHERE id=2`,
		`UPDATE audit_log SET success=2 WHERE id=2`,
	} {
		t.Run(poke, func(t *testing.T) {
			l := openTestLog(t)
			for i := 0; i < 4; i++ {
				l.Record("nfc", map[string]int{"i": i}, "ok", "low", LevelAction, 0, true)
			}
			if _, err := l.db.Exec(poke); err != nil {
				t.Fatalf("poison: %v", err)
			}

			hasID2 := func(entries []Entry) bool {
				for _, e := range entries {
					if e.ID == 2 {
						if e.Success {
							t.Errorf("poisoned row 2 should report Success=false, got true")
						}
						return true
					}
				}
				return false
			}

			q, err := l.Query(100)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(q) != 4 || !hasID2(q) {
				t.Errorf("Query dropped the poisoned row: got %d rows, id2 present=%v (want 4, true)", len(q), hasID2(q))
			}

			bs, err := l.QueryBySession(l.SessionID())
			if err != nil {
				t.Fatalf("QueryBySession: %v", err)
			}
			if len(bs) != 4 || !hasID2(bs) {
				t.Errorf("QueryBySession dropped the poisoned row: got %d (want 4)", len(bs))
			}

			qf, err := l.QueryFiltered(Filter{})
			if err != nil {
				t.Fatalf("QueryFiltered: %v", err)
			}
			if len(qf) != 4 || !hasID2(qf) {
				t.Errorf("QueryFiltered dropped the poisoned row: got %d (want 4)", len(qf))
			}

			qs, err := l.QuerySince(0)
			if err != nil {
				t.Fatalf("QuerySince: %v", err)
			}
			if len(qs) != 4 || !hasID2(qs) {
				t.Errorf("QuerySince dropped the poisoned row: got %d (want 4)", len(qs))
			}
		})
	}
}
