// SPDX-License-Identifier: AGPL-3.0-or-later

// Package discordtoken decodes a Discord authentication token into the account
// it belongs to. A Discord token is the **single most common credential in
// infostealer / RAT logs** (RedLine, Raccoon, and friends harvest them en
// masse), and a captured token is not opaque: its first segment is the account's
// user ID, from which the account's creation time falls straight out of the
// Discord snowflake. Identifying the owning account + its age offline — with no
// API call to Discord, no token use, no detection — is standard IR / OSINT
// triage. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. A Discord user/bot token is three Base64url segments joined by '.':
// base64url(userID-string) . base64url(mint-timestamp) . HMAC. Decoding the
// account is a Base64 decode + the in-tree snowflake decoder (internal/snowflake,
// already anchored to Discord's documented snowflake example). Stdlib + an
// existing package; nothing to wrap.
//
// # What this covers / defers
//
//   - User / bot tokens: the user ID (segment 1) and, via the snowflake, the
//     **account creation time**.
//   - The token mint timestamp (segment 2) is surfaced **raw and uninterpreted**:
//     Discord's epoch offset for this field is documented as uncertain ("add
//     1.1e9-1.3e9"), so converting it to a date would be a confidently-wrong
//     guess. The HMAC (segment 3) is opaque.
//   - `mfa.`-prefixed tokens carry no embedded user ID and are identified as
//     such, not decoded.
//
// # Verifiable / no confidently-wrong output
//
// The account-creation decode chains through internal/snowflake, which is
// anchored to Discord's own documented example (175928847299117063 →
// 2016-04-30T11:18:25.796Z). A round-trip test builds a token from that user ID
// and confirms the decode recovers it and the documented creation time. A string
// whose first segment does not Base64-decode to ASCII digits is rejected (not a
// Discord token).
package discordtoken

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/snowflake"
)

// Result is the decoded view of a Discord token.
type Result struct {
	// Type is "Discord user/bot token" or "Discord MFA token".
	Type string `json:"type"`
	// UserID is the account snowflake from segment 1 (empty for MFA tokens).
	UserID string `json:"user_id,omitempty"`
	// AccountCreatedUTC is the account creation time derived from the snowflake.
	AccountCreatedUTC string `json:"account_created_utc,omitempty"`
	// TokenMintRaw is segment 2 decoded but uninterpreted (its epoch offset is
	// uncertain, so it is not converted to a date).
	TokenMintRaw string `json:"token_mint_raw,omitempty"`
	// HasHMAC is true when the opaque signature segment is present.
	HasHMAC bool `json:"has_hmac"`
	// Note carries caveats.
	Note string `json:"note,omitempty"`
}

// Decode parses a Discord token and recovers the owning account.
func Decode(token string) (*Result, error) {
	t := strings.TrimSpace(token)
	if t == "" {
		return nil, fmt.Errorf("discordtoken: empty input")
	}
	if strings.HasPrefix(t, "mfa.") {
		return &Result{
			Type: "Discord MFA token",
			Note: "MFA token — carries no embedded user ID; the account cannot be derived from the token alone",
		}, nil
	}

	parts := strings.Split(t, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("discordtoken: not a Discord token (expected dot-separated segments)")
	}

	idBytes, ok := b64Decode(parts[0])
	if !ok || !allDigits(idBytes) || len(idBytes) == 0 {
		return nil, fmt.Errorf("discordtoken: first segment does not decode to a user ID — not a Discord token")
	}
	userID := string(idBytes)

	res := &Result{Type: "Discord user/bot token", UserID: userID, HasHMAC: len(parts) >= 3 && parts[2] != ""}

	// Account creation time via the Discord snowflake.
	if sf, err := snowflake.Decode(userID, "discord"); err == nil && len(sf.Candidates) == 1 {
		res.AccountCreatedUTC = sf.Candidates[0].TimestampUTC
	}

	// Segment 2: the token mint timestamp, surfaced raw and uninterpreted.
	if len(parts) >= 2 {
		if b, ok := b64Decode(parts[1]); ok && len(b) > 0 {
			res.TokenMintRaw = string(b)
		}
	}
	res.Note = "the token mint timestamp (segment 2) is surfaced raw; its epoch offset is uncertain so it is " +
		"not converted to a date. The HMAC (segment 3) is opaque."
	return res, nil
}

// b64Decode tries the Base64url and standard alphabets, padded and unpadded.
func b64Decode(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// allDigits reports whether every byte is an ASCII decimal digit.
func allDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
