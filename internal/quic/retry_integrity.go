// SPDX-License-Identifier: AGPL-3.0-or-later

package quic

// QUIC Retry packet integrity verification (RFC 9001 §5.8).
//
// Wrap-vs-native judgement
//
//	Native. A server's Retry packet carries a 16-byte Retry
//	Integrity Tag: an AES-128-GCM tag, with empty plaintext,
//	over the "Retry Pseudo-Packet" (the original Destination
//	Connection ID the client chose, length-prefixed, followed
//	by the Retry packet minus its tag), keyed by a fixed
//	per-version key and nonce published in the RFC. There is
//	no secret involved — anyone with the packet bytes and the
//	original DCID can recompute the tag — so verifying a Retry
//	is a pure, deterministic, offline transform with a single
//	published test vector (RFC 9001 Appendix A.4). The whole
//	construction is Go-stdlib AES-128-GCM; no new dependency,
//	no shell-out.
//
// What this covers
//
//   - QUIC v1 (version 0x00000001) Retry integrity tags. The
//     tag authenticates that the server genuinely received the
//     client's first Initial (which carried the original DCID),
//     so a mismatch flags a forged, corrupted, or off-path
//     Retry — useful for spotting Retry-injection attacks and
//     validating captures.
//
// What this does NOT cover (deliberately out of scope)
//
//   - QUIC v2 (RFC 9369) and the drafts use different Retry
//     integrity keys/nonces. Only the v1 key/nonce is anchored
//     to a published vector here, so v2/draft Retries report a
//     note rather than risk a confidently-wrong verdict.
//
//   - The original DCID is NOT present in the Retry packet — it
//     is the connection ID the client put in its first Initial.
//     The caller must supply it (from the same capture's client
//     Initial, or connection state); without it no verification
//     is possible.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// retryKeyV1 / retryNonceV1 are the fixed QUIC v1 Retry integrity
// secrets (RFC 9001 §5.8).
var (
	retryKeyV1 = []byte{
		0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
		0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
	}
	retryNonceV1 = []byte{
		0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
	}
)

// VerifyRetryIntegrity recomputes the Retry Integrity Tag (RFC 9001
// §5.8) over the Retry Pseudo-Packet and reports whether it matches
// the 16-byte tag carried at the end of the packet. odcid is the
// Destination Connection ID the client chose in its first Initial
// (echoed by the server's integrity check but absent from the Retry
// packet itself). The comparison is constant-time.
func VerifyRetryIntegrity(packet, odcid []byte) (bool, error) {
	// Long header (1) + version (4) + DCIDlen (1) + SCIDlen (1) +
	// 16-byte tag is the bare minimum; a real Retry also has an SCID
	// and a token, but those are covered by the length check below.
	if len(packet) < 1+4+2+16 {
		return false, fmt.Errorf("retry packet too short (%d bytes)", len(packet))
	}
	if packet[0]&0x80 == 0 || (packet[0]>>4)&0x03 != 3 {
		return false, fmt.Errorf("not a Retry packet (long packet type must be 3)")
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	if version != 0x00000001 {
		return false, fmt.Errorf("retry integrity verification only implemented for "+
			"QUIC v1 (0x00000001); got 0x%08X", version)
	}
	if len(odcid) > 20 {
		return false, fmt.Errorf("original DCID too long (%d bytes; max 20)", len(odcid))
	}

	tag := packet[len(packet)-16:]
	retryWithoutTag := packet[:len(packet)-16]

	// Retry Pseudo-Packet: ODCID Length || ODCID || Retry (sans tag).
	pseudo := make([]byte, 0, 1+len(odcid)+len(retryWithoutTag))
	pseudo = append(pseudo, byte(len(odcid)))
	pseudo = append(pseudo, odcid...)
	pseudo = append(pseudo, retryWithoutTag...)

	block, err := aes.NewCipher(retryKeyV1)
	if err != nil {
		return false, fmt.Errorf("retry cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return false, fmt.Errorf("retry gcm: %w", err)
	}
	// Empty plaintext → Seal returns just the 16-byte authentication tag.
	computed := aead.Seal(nil, retryNonceV1, nil, pseudo)
	return subtle.ConstantTimeCompare(computed, tag) == 1, nil
}

// VerifyRetryIntegrityHex is the hex front door to VerifyRetryIntegrity,
// accepting the same separators ('-', ':', '_', whitespace, '0x') as
// Decode for both the Retry packet and the original DCID.
func VerifyRetryIntegrityHex(packetHex, odcidHex string) (bool, error) {
	pkt, err := hex.DecodeString(stripSeparators(packetHex))
	if err != nil {
		return false, fmt.Errorf("retry packet hex: %w", err)
	}
	odcid, err := hex.DecodeString(stripSeparators(odcidHex))
	if err != nil {
		return false, fmt.Errorf("original DCID hex: %w", err)
	}
	return VerifyRetryIntegrity(pkt, odcid)
}
