// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webauthn decodes the WebAuthn / FIDO2 authenticator-data
// structure (the `authData` byte string returned in a registration
// attestation or an assertion). Operators analysing passkey / security-key
// flows — captured registrations, attestation objects, credential dumps —
// get the structured fields out of the opaque blob: which user gestures
// occurred (present / verified), the backup-eligibility bits that mark a
// syncable passkey, the signature counter (a value that goes backwards is
// the classic cloned-authenticator tell), the authenticator model
// (AAGUID), the credential ID, and the credential public key.
//
// The structure is fixed-layout (W3C WebAuthn §6.1) with no checksum, so
// decoding is deterministic field extraction. The one variable-length
// subtlety is that the attested credential public key is a CBOR object of
// unknown byte length, optionally followed by a CBOR extensions map; a
// small RFC 8949 item-length scanner finds the key's exact extent so the
// two are split correctly. All length-driven reads are bounds-checked
// against the buffer.
package webauthn

import (
	"encoding/binary"
	"fmt"
)

// minAuthDataLen is the fixed prefix: 32-byte RP ID hash + 1 flags byte +
// 4-byte signature counter.
const minAuthDataLen = 37

// Flags is the decoded authenticator-data flags byte (W3C WebAuthn §6.1).
type Flags struct {
	UserPresent            bool `json:"user_present"`             // UP, bit 0
	UserVerified           bool `json:"user_verified"`            // UV, bit 2
	BackupEligible         bool `json:"backup_eligible"`          // BE, bit 3 — credential may be synced
	BackupState            bool `json:"backup_state"`             // BS, bit 4 — credential is currently backed up
	AttestedCredentialData bool `json:"attested_credential_data"` // AT, bit 6
	ExtensionData          bool `json:"extension_data"`           // ED, bit 7
	Raw                    byte `json:"raw"`
}

// AuthData is the decoded WebAuthn authenticator data.
type AuthData struct {
	RPIDHashHex string `json:"rp_id_hash_hex"` // SHA-256 of the Relying Party ID (32 bytes)
	Flags       Flags  `json:"flags"`
	SignCount   uint32 `json:"sign_count"`

	// The following are present only when Flags.AttestedCredentialData.
	AAGUIDHex        string `json:"aaguid_hex,omitempty"`
	AAGUID           string `json:"aaguid,omitempty"` // canonical 8-4-4-4-12 UUID form
	CredentialIDLen  int    `json:"credential_id_len,omitempty"`
	CredentialIDHex  string `json:"credential_id_hex,omitempty"`
	CredentialKeyHex string `json:"credential_public_key_hex,omitempty"` // raw COSE_Key (CBOR); decode with cbor_decode
	CredentialKeyLen int    `json:"credential_public_key_len,omitempty"`

	// Present only when Flags.ExtensionData: the raw CBOR extensions map.
	ExtensionsHex string `json:"extensions_hex,omitempty"`
}

// Decode parses a WebAuthn authenticator-data byte string. It validates the
// fixed prefix and every length-driven field against the buffer, returning
// an error rather than reading out of bounds on malformed input.
func Decode(data []byte) (*AuthData, error) {
	if len(data) < minAuthDataLen {
		return nil, fmt.Errorf("authData too short: %d bytes, need at least %d", len(data), minAuthDataLen)
	}

	flags := data[32]
	ad := &AuthData{
		RPIDHashHex: toHex(data[:32]),
		SignCount:   binary.BigEndian.Uint32(data[33:37]),
		Flags: Flags{
			UserPresent:            flags&0x01 != 0,
			UserVerified:           flags&0x04 != 0,
			BackupEligible:         flags&0x08 != 0,
			BackupState:            flags&0x10 != 0,
			AttestedCredentialData: flags&0x40 != 0,
			ExtensionData:          flags&0x80 != 0,
			Raw:                    flags,
		},
	}

	off := minAuthDataLen

	if ad.Flags.AttestedCredentialData {
		// Attested credential data: 16-byte AAGUID + 2-byte credential ID
		// length + credential ID + COSE public key.
		if len(data) < off+18 {
			return nil, fmt.Errorf("authData truncated in attested credential data header (have %d bytes, need %d)", len(data), off+18)
		}
		ad.AAGUIDHex = toHex(data[off : off+16])
		ad.AAGUID = formatUUID(data[off : off+16])
		off += 16

		credLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if credLen > len(data)-off {
			return nil, fmt.Errorf("credential ID length %d exceeds remaining %d bytes", credLen, len(data)-off)
		}
		ad.CredentialIDLen = credLen
		ad.CredentialIDHex = toHex(data[off : off+credLen])
		off += credLen

		// The credential public key is a CBOR object of unknown length.
		// Find its exact extent so any trailing extensions are not folded
		// into the key.
		keyLen, err := cborItemLen(data[off:])
		if err != nil {
			return nil, fmt.Errorf("credential public key (COSE): %w", err)
		}
		ad.CredentialKeyLen = keyLen
		ad.CredentialKeyHex = toHex(data[off : off+keyLen])
		off += keyLen
	}

	if ad.Flags.ExtensionData {
		if off >= len(data) {
			return nil, fmt.Errorf("extension-data flag set but no extensions bytes present")
		}
		// Validate the extensions are a well-formed CBOR item that consumes
		// exactly the remaining bytes — a mismatch means a malformed frame.
		extLen, err := cborItemLen(data[off:])
		if err != nil {
			return nil, fmt.Errorf("extensions (CBOR): %w", err)
		}
		if off+extLen != len(data) {
			return nil, fmt.Errorf("extensions length %d does not consume the remaining %d bytes", extLen, len(data)-off)
		}
		ad.ExtensionsHex = toHex(data[off:])
		off += extLen
	}

	// Any leftover bytes mean the structure didn't account for the whole
	// buffer — surface it rather than silently ignoring trailing data.
	if off != len(data) {
		return nil, fmt.Errorf("trailing %d bytes after decoded authData", len(data)-off)
	}
	return ad, nil
}

func toHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// formatUUID renders 16 bytes as a canonical 8-4-4-4-12 UUID string.
func formatUUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	h := toHex(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}
