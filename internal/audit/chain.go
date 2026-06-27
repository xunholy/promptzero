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
	// HeadHash is the hash of the last hashed row — record it (with
	// HashedRows) out-of-band as a CheckpointAnchor to later detect a
	// full-chain rewrite or tail truncation, which the in-DB chain alone
	// cannot.
	HeadHash string `json:"head_hash,omitempty"`

	// Anchor* are populated only when an anchor is supplied to
	// VerifyChainAgainst. AnchorChecked distinguishes "anchor matched"
	// (AnchorValid true) from "no anchor was provided" (AnchorChecked false).
	AnchorChecked bool   `json:"anchor_checked"`
	AnchorValid   bool   `json:"anchor_valid"`
	AnchorDetail  string `json:"anchor_detail,omitempty"`

	// Detail is a human-readable summary.
	Detail string `json:"detail"`
}

// CheckpointAnchor is an out-of-band record of the chain's state at a point
// in time: the head hash after HashedRows hashed rows. Recording one (e.g.
// to git, a remote store, or paper) and later passing it to
// VerifyChainAgainst closes the two gaps the in-DB chain cannot cover on its
// own — a consistent full-chain rewrite (the re-hashed prefix yields a
// different head than the anchor) and truncation of the newest rows (the
// current chain holds fewer hashed rows than the anchor).
type CheckpointAnchor struct {
	HashedRows int    `json:"hashed_rows"`
	HeadHash   string `json:"head_hash"`
}

// VerifyChain walks the audit log in id order and recomputes the hash chain,
// detecting any post-hoc modification, mid-chain deletion, reorder, or forged
// insert made directly against the database.
//
// Scope: on its own this is tamper-EVIDENCE against casual edits (e.g.
// someone opening the DB in sqlite3 and changing or deleting a row without
// recomputing the chain). To also catch a consistent full-chain rewrite or
// truncation of the newest rows, record a CheckpointAnchor from HeadHash +
// HashedRows out-of-band and pass it to VerifyChainAgainst.
func (l *Log) VerifyChain() (*VerifyResult, error) {
	return l.VerifyChainAgainst(nil)
}

// VerifyChainAgainst performs the in-DB chain verification of VerifyChain
// and, when anchor is non-nil, additionally checks the chain against that
// out-of-band anchor: the chain re-walked to anchor.HashedRows rows must
// still yield anchor.HeadHash (else the anchored prefix was rewritten), and
// the current chain must still hold at least that many hashed rows (else the
// newest rows were truncated). Together with the in-DB check this detects
// every direct-to-database tampering class.
func (l *Log) VerifyChainAgainst(anchor *CheckpointAnchor) (*VerifyResult, error) {
	rows, err := l.db.Query(`
		SELECT id, timestamp, tool, input, output, risk, level, session_id, duration_ms, success, entry_hash
		FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("audit verify: query: %w", err)
	}
	defer rows.Close()

	res := &VerifyResult{Valid: true}
	prevHash := "" // genesis link for the first hashed row
	headAtAnchor := ""
	anchorPosReached := false

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

		// Capture the running head at the anchored position so a rewrite of
		// the anchored prefix shows up as a head mismatch below.
		if anchor != nil && !anchorPosReached && res.HashedRows == anchor.HashedRows {
			headAtAnchor = prevHash
			anchorPosReached = true
		}
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

	if anchor != nil {
		res.AnchorChecked = true
		switch {
		case anchor.HashedRows <= 0 || anchor.HeadHash == "":
			res.AnchorDetail = "invalid anchor: hashed_rows must be > 0 and head_hash non-empty"
		case res.HashedRows < anchor.HashedRows:
			res.AnchorDetail = fmt.Sprintf("TAIL TRUNCATED: %d hashed rows now, anchor recorded %d — newest rows were deleted",
				res.HashedRows, anchor.HashedRows)
		case !anchorPosReached || headAtAnchor != anchor.HeadHash:
			res.AnchorDetail = fmt.Sprintf("PREFIX REWRITTEN: head after %d hashed rows does not match the anchored hash — the log was rewritten",
				anchor.HashedRows)
		default:
			res.AnchorValid = true
			res.AnchorDetail = fmt.Sprintf("anchor matched: the first %d hashed rows are unchanged since the checkpoint", anchor.HashedRows)
		}
	}
	return res, nil
}
