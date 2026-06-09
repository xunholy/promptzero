// SPDX-License-Identifier: AGPL-3.0-or-later

// Package awskey decodes an AWS access key ID (AKIA…/ASIA…/AROA… — the 20-char
// unique IDs AWS issues for keys, roles, users, and policies) into the **AWS
// account ID** bit-packed inside it and the **credential type**. A leaked AWS
// key is prime cloud-pentest / IR loot, and recovering the owning account ID +
// the key type **offline, without calling AWS** (no `sts get-access-key-info`,
// no log entry, no detection) is a standard recon technique. Pure offline
// transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. The account ID is encoded in the key ID: strip the 4-char type
// prefix, base32-decode the rest, read the first 6 bytes big-endian, mask with
// 0x7FFFFFFFFF80 and right-shift 7. A base32 decode + a shift, stdlib only —
// nothing to wrap. The bit layout was reverse-engineered by Aidan Steele /
// WithSecure / Truffle Security and is implemented identically across the
// public tools (e.g. github.com/psanford/aws-account-id-from-key).
//
// # Verifiable / no confidently-wrong output
//
// Anchored to two published vectors — ASIAY34FZKBOKMUTVV7A → 609629065308 and
// ASIAQNZGKIQY56JQ7WML → 029608264753 (the latter is the psanford reference
// implementation's own test vector). To avoid emitting a bogus account ID for an
// arbitrary base32 string, only the recognised AWS unique-ID prefixes are
// accepted; an unknown prefix, a wrong length, or a non-base32 body is rejected.
package awskey

import (
	"encoding/base32"
	"fmt"
	"strings"
)

// prefixDesc maps each AWS unique-ID prefix to the resource it identifies
// (AWS IAM identifier prefixes). All embed the account ID via the same scheme.
var prefixDesc = map[string]string{
	"ABIA": "STS bearer token",
	"ACCA": "context-specific credential",
	"AGPA": "IAM group unique ID",
	"AIDA": "IAM user unique ID",
	"AIPA": "EC2 instance profile unique ID",
	"AKIA": "long-term IAM access key",
	"ANPA": "managed policy unique ID",
	"ANVA": "managed policy version unique ID",
	"APKA": "public key (SSH / CodeCommit) unique ID",
	"AROA": "IAM role unique ID",
	"ASCA": "certificate unique ID",
	"ASIA": "temporary STS access key",
}

// Result is the decoded view of an AWS access key ID.
type Result struct {
	// KeyID is the input (upper-cased).
	KeyID string `json:"key_id"`
	// KeyType is the 4-char prefix (AKIA, ASIA, AROA, …).
	KeyType string `json:"key_type"`
	// Description is the human meaning of the prefix.
	Description string `json:"description"`
	// AccountID is the 12-digit AWS account ID embedded in the key.
	AccountID string `json:"account_id"`
	// Usable is true for the prefixes that are actual access keys you can
	// authenticate with (AKIA long-term, ASIA temporary); the others are
	// resource unique IDs that merely leak the account.
	Usable bool `json:"usable_credential"`
}

// accountMask isolates the account-ID bits in the first 6 bytes of the
// base32-decoded key body (Aidan Steele / WithSecure analysis).
const accountMask = 0x7fffffffff80

// Decode recovers the AWS account ID and credential type from a 20-character AWS
// access key ID. A wrong length, an unrecognised prefix, or a non-base32 body is
// rejected rather than decoded into a bogus account.
func Decode(keyID string) (*Result, error) {
	k := strings.ToUpper(strings.TrimSpace(keyID))
	if len(k) != 20 {
		return nil, fmt.Errorf("awskey: an AWS access key ID is 20 characters, got %d", len(k))
	}
	keyType := k[:4]
	desc, known := prefixDesc[keyType]
	if !known {
		return nil, fmt.Errorf("awskey: %q is not a recognised AWS key-ID prefix (AKIA/ASIA/AROA/…)", keyType)
	}

	dec, err := base32.StdEncoding.DecodeString(k[4:])
	if err != nil {
		return nil, fmt.Errorf("awskey: key body is not valid base32: %w", err)
	}
	if len(dec) < 6 {
		return nil, fmt.Errorf("awskey: decoded key body is too short")
	}

	var v uint64
	for i := 0; i < 6; i++ {
		v = v<<8 | uint64(dec[i])
	}
	account := (v & accountMask) >> 7

	return &Result{
		KeyID:       k,
		KeyType:     keyType,
		Description: desc,
		AccountID:   fmt.Sprintf("%012d", account),
		Usable:      keyType == "AKIA" || keyType == "ASIA",
	}, nil
}
