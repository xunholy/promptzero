// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
)

// chainHash computes the tamper-evidence hash for one audit row:
// SHA-256(prevHash ‖ row fields), each field length-prefixed so no field
// value can forge a boundary with the next. prevHash is the hex hash of the
// preceding row (empty for the first/genesis row). The result is hex.
//
// The fields are exactly the persisted columns, in column order, so
// VerifyChain can recompute the identical input by reading the row back.
func chainHash(prevHash, timestamp, tool, input, output, risk, level, sessionID string, durationMs int64, success bool) string {
	h := sha256.New()
	writeChainField(h, prevHash)
	writeChainField(h, timestamp)
	writeChainField(h, tool)
	writeChainField(h, input)
	writeChainField(h, output)
	writeChainField(h, risk)
	writeChainField(h, level)
	writeChainField(h, sessionID)
	writeChainField(h, strconv.FormatInt(durationMs, 10))
	writeChainField(h, boolToChainField(success))
	return hex.EncodeToString(h.Sum(nil))
}

// writeChainField writes a length-prefixed field into the running hash so
// concatenation is unambiguous (an 8-byte big-endian length, then the bytes).
func writeChainField(h interface{ Write([]byte) (int, error) }, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}

func boolToChainField(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// VerifyResult reports the outcome of an audit-log integrity check.
type VerifyResult struct {
	// Valid is true when every hashed row's recomputed hash matches what
	// was stored and links correctly to its predecessor.
	Valid bool `json:"valid"`
	// TotalRows is every row in the log.
	TotalRows int `json:"total_rows"`
	// HashedRows is the number of rows carrying a chain hash (the verified
	// suffix). LegacyRows predate the hash chain and cannot be verified.
	HashedRows int `json:"hashed_rows"`
	LegacyRows int `json:"legacy_rows"`
	// FirstBrokenID is the id of the first row whose hash failed, or 0 when
	// the chain is intact.
	FirstBrokenID int64 `json:"first_broken_id,omitempty"`
	// HeadHash is the hash of the last hashed row — record it out-of-band to
	// anchor against a full-chain rewrite (which this in-DB chain alone,
	// without an external anchor, cannot detect).
	HeadHash string `json:"head_hash,omitempty"`
	// Detail is a human-readable summary.
	Detail string `json:"detail"`
}

// VerifyChain walks the audit log in id order and recomputes the hash chain,
// detecting any post-hoc modification, mid-chain deletion, reorder, or forged
// insert made directly against the database.
//
// Scope: this is tamper-EVIDENCE against casual edits (e.g. someone opening
// the DB in sqlite3 and changing or deleting a row without recomputing the
// chain). It does NOT defend against an attacker who rewrites the entire
// chain in place, nor against truncation of the newest rows — both need an
// out-of-band anchor of HeadHash, which callers can record from this result.
func (l *Log) VerifyChain() (*VerifyResult, error) {
	rows, err := l.db.Query(`
		SELECT id, timestamp, tool, input, output, risk, level, session_id, duration_ms, success, entry_hash
		FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("audit verify: query: %w", err)
	}
	defer rows.Close()

	res := &VerifyResult{Valid: true}
	prevHash := "" // genesis link for the first hashed row

	for rows.Next() {
		var (
			id                             int64
			timestamp, tool, level         string
			input, output, risk, sessionID sql.NullString
			durationMs                     sql.NullInt64
			success                        bool
			storedHash                     sql.NullString
		)
		if err := rows.Scan(&id, &timestamp, &tool, &input, &output, &risk, &level,
			&sessionID, &durationMs, &success, &storedHash); err != nil {
			return nil, fmt.Errorf("audit verify: scan: %w", err)
		}
		res.TotalRows++

		// Rows that predate the hash chain carry no hash; count them but
		// don't fold them into the chain (their predecessor link is genesis
		// for the first hashed row that follows).
		if !storedHash.Valid || storedHash.String == "" {
			res.LegacyRows++
			continue
		}
		res.HashedRows++

		want := chainHash(prevHash, timestamp, tool, input.String, output.String,
			risk.String, level, sessionID.String, durationMs.Int64, success)
		if want != storedHash.String {
			if res.Valid { // record only the first break
				res.Valid = false
				res.FirstBrokenID = id
			}
		}
		// Chain onto the STORED hash so a single tampered row pinpoints to
		// itself rather than cascading every later row into "broken".
		prevHash = storedHash.String
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit verify: rows: %w", err)
	}

	res.HeadHash = prevHash
	switch {
	case res.HashedRows == 0:
		res.Detail = fmt.Sprintf("no hashed rows to verify (%d legacy rows predate the chain)", res.LegacyRows)
	case res.Valid:
		res.Detail = fmt.Sprintf("chain intact: %d hashed rows verified (%d legacy)", res.HashedRows, res.LegacyRows)
	default:
		res.Detail = fmt.Sprintf("chain BROKEN at row id %d — the log was modified after it was written", res.FirstBrokenID)
	}
	return res, nil
}
