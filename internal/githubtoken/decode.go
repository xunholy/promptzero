// SPDX-License-Identifier: AGPL-3.0-or-later

// Package githubtoken identifies and validates a GitHub authentication token —
// the prefixed, checksummed formats GitHub adopted in April 2021 (ghp_, gho_,
// ghu_, ghs_, ghr_, github_pat_). A leaked GitHub token is the single most
// common secret found in repos, dumps, logs, and CI configs, and the format
// carries a **CRC32 checksum** that lets a finder confirm offline whether a
// captured string is a **genuine, well-formed token** (vs. a redaction, a typo,
// or a fabricated lookalike) — a positive secret-scanning detection from the
// token alone, with no API call to GitHub. Pure offline transform; no network or
// device.
//
// # Wrap-vs-native judgement
//
// Native. A GitHub token is `<prefix><30-char base62 entropy><6-char base62
// CRC32 checksum>`; validation is a CRC32 (stdlib hash/crc32) of the entropy
// compared to the base62-decoded checksum. A hash + a base conversion, stdlib
// only — nothing to wrap.
//
// # What this covers / defers
//
//   - The five classic token types (ghp_ / gho_ / ghu_ / ghs_ / ghr_) get full
//     prefix identification + CRC32 checksum validation (the entropy is the part
//     after the prefix, excluding the trailing 6 checksum characters).
//   - Fine-grained PATs (github_pat_) are identified by prefix but their
//     internal structure differs (an embedded underscore) and is not vector-
//     verified here, so the checksum is **not asserted** for them.
//   - Legacy 40-hex tokens (pre-April-2021) carry no prefix or checksum and are
//     indistinguishable from any other 40-hex string, so they are not claimed.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the canonical example token (prefix ghp_, entropy
// zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ, checksum 0mLq17): the entropy's CRC32
// (714468973) equals the base62-decoded checksum — confirming both the algorithm
// and the vector. A token whose checksum does not validate is
// reported as such (likely a typo / redaction / fake), not asserted genuine; a
// non-recognised prefix is rejected.
package githubtoken

import (
	"fmt"
	"hash/crc32"
	"strings"
)

// base62Dict is the GitHub token Base62 alphabet (digits, upper, lower).
const base62Dict = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var base62Rev = func() [256]int {
	var r [256]int
	for i := range r {
		r[i] = -1
	}
	for i := 0; i < len(base62Dict); i++ {
		r[base62Dict[i]] = i
	}
	return r
}()

// classicPrefixes are the token types that share the 30-entropy + 6-checksum
// layout and so support full checksum validation.
var classicPrefixes = map[string]string{
	"ghp_": "personal access token (classic)",
	"gho_": "OAuth access token",
	"ghu_": "user-to-server token (GitHub App)",
	"ghs_": "server-to-server token (GitHub App installation)",
	"ghr_": "refresh token",
}

// Result is the decoded view of a GitHub token.
type Result struct {
	// Type is the human description of the token kind.
	Type string `json:"type"`
	// Prefix is the recognised token prefix.
	Prefix string `json:"prefix"`
	// ChecksumChecked is true when this token type's CRC32 checksum was validated.
	ChecksumChecked bool `json:"checksum_checked"`
	// ChecksumValid is the result of that validation (meaningful only when
	// ChecksumChecked).
	ChecksumValid bool `json:"checksum_valid"`
	// Note carries the validity verdict or a caveat.
	Note string `json:"note,omitempty"`
}

// Decode identifies a GitHub token by prefix and, for the classic types,
// validates its CRC32 checksum. A non-GitHub-prefixed string is rejected.
func Decode(token string) (*Result, error) {
	t := strings.TrimSpace(token)

	if strings.HasPrefix(t, "github_pat_") {
		return &Result{
			Type:   "fine-grained personal access token",
			Prefix: "github_pat_",
			Note:   "fine-grained PAT — prefix identified; its checksum scheme differs and is not validated here",
		}, nil
	}

	if len(t) < 4 {
		return nil, fmt.Errorf("githubtoken: too short to be a GitHub token")
	}
	prefix := t[:4]
	desc, ok := classicPrefixes[prefix]
	if !ok {
		return nil, fmt.Errorf("githubtoken: %q is not a recognised GitHub token prefix (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)", prefix)
	}

	body := t[4:]
	if len(body) < 7 { // need at least 1 entropy char + 6 checksum chars
		return nil, fmt.Errorf("githubtoken: token body too short for a checksum")
	}
	entropy := body[:len(body)-6]
	checksum := body[len(body)-6:]

	dec, ok := base62Decode(checksum)
	if !ok {
		return nil, fmt.Errorf("githubtoken: checksum is not valid Base62")
	}
	if !allBase62(entropy) {
		return nil, fmt.Errorf("githubtoken: token body contains non-Base62 characters")
	}

	res := &Result{
		Type:            desc,
		Prefix:          prefix,
		ChecksumChecked: true,
		ChecksumValid:   uint64(crc32.ChecksumIEEE([]byte(entropy))) == dec,
	}
	if res.ChecksumValid {
		res.Note = "checksum valid — a genuine, well-formed GitHub token"
	} else {
		res.Note = "checksum does NOT validate — likely a typo, redaction, or fabricated lookalike, not a real token"
	}
	return res, nil
}

// base62Decode decodes a Base62 string to a uint64; the second return is false
// on a non-Base62 character.
func base62Decode(s string) (uint64, bool) {
	var v uint64
	for i := 0; i < len(s); i++ {
		d := base62Rev[s[i]]
		if d < 0 {
			return 0, false
		}
		v = v*62 + uint64(d)
	}
	return v, true
}

func allBase62(s string) bool {
	for i := 0; i < len(s); i++ {
		if base62Rev[s[i]] < 0 {
			return false
		}
	}
	return true
}
