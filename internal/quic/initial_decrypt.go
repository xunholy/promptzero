// SPDX-License-Identifier: AGPL-3.0-or-later

package quic

// QUIC Initial-packet decryption (RFC 9001 §5).
//
// Wrap-vs-native judgement
//
//	Native. The Initial packet is the one long-header packet
//	whose protection keys are *public*: they are derived
//	deterministically from a fixed per-version salt and the
//	client's Destination Connection ID (which travels in the
//	clear in the long header), with no TLS-handshake secret
//	involved (RFC 9001 §5.2). That makes the Initial fully
//	decryptable offline from the packet bytes alone — exactly
//	the kind of pure, deterministic, vector-anchored transform
//	this project favours. The construction is HKDF-Extract +
//	HKDF-Expand-Label (RFC 8446 §7.1) for key/iv/hp, AES-128
//	in ECB over a 16-byte ciphertext sample for header-protection
//	removal (RFC 9001 §5.4.1), and AES-128-GCM for packet
//	protection (RFC 9001 §5.3). All three are in the Go standard
//	library plus golang.org/x/crypto/hkdf, which is already a
//	dependency — no new runtime dep, no shell-out.
//
// What this covers
//
//   - QUIC v1 (version 0x00000001) client and server Initial
//     packets. The initial secret is HKDF-Extract(salt, DCID);
//     the client/server secret is HKDF-Expand-Label(secret,
//     "client in"/"server in"); key/iv/hp follow via
//     "quic key" (16) / "quic iv" (12) / "quic hp" (16).
//
//   - Header-protection removal: AES-ECB(hp, sample) where the
//     sample is the 16 bytes at pn_offset+4; the low 4 bits of
//     the first byte and the 1-4 packet-number bytes are
//     unmasked (RFC 9001 §5.4.1, long-header variant).
//
//   - AEAD_AES_128_GCM decryption: nonce = iv XOR
//     left-padded packet number; AAD = the unprotected header
//     (first byte + ... + unprotected packet number).
//
//   - Frame-layer dissection of the decrypted payload: PADDING
//     (run-collapsed), PING, ACK / ACK-ECN (parsed to skip
//     correctly), CRYPTO (offset+length+data), and
//     CONNECTION_CLOSE. CRYPTO fragments are reassembled by
//     offset into the contiguous TLS handshake stream, and a
//     leading handshake-type byte of 0x01 is surfaced as a
//     ClientHello (0x02 ServerHello for server Initials) — the
//     bytes you feed straight into tls_handshake_decode for the
//     full ClientHello / JA4 / ALPN / SNI view that QUIC's
//     encryption otherwise hides.
//
//   - The **JA4 QUIC fingerprint** (FoxIO, protocol prefix "q")
//     computed over the recovered ClientHello / ServerHello via
//     tlsdecode.QUICHandshakeJA4 — JA4 for a client Initial,
//     JA4S for a server Initial. The computation is identical to
//     the TLS-over-TCP JA4 bar the leading "q", and is verified
//     end-to-end (pcap -> decrypt -> ClientHello -> JA4) against
//     FoxIO's published QUIC snapshot
//     q13d0310h3_55b375c5d22e_cd85d2d88918. Only emitted for a
//     complete, contiguous handshake — a partial ClientHello
//     would fingerprint wrong, so nothing is surfaced rather
//     than a confidently-wrong value.
//
// What this does NOT cover (deliberately out of scope)
//
//   - QUIC v2 (RFC 9369) and the various drafts use different
//     salts and "quicv2 " key labels. Only v1 is anchored to a
//     published test vector (RFC 9001 Appendix A), so only v1 is
//     decrypted; other versions are reported with a note rather
//     than risk a confidently-wrong decode.
//
//   - 0-RTT / Handshake / 1-RTT packets are protected with
//     TLS-handshake-derived secrets that are not on the wire,
//     so they remain undecryptable offline and are surfaced as
//     protected hex only.
//
//   - Packet-number reconstruction across a connection: a single
//     offline packet has no "largest acknowledged" context, so
//     the truncated packet number is used verbatim as the full
//     number (correct for first-flight Initials, which is the
//     decryptable case).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/xunholy/promptzero/internal/tlsdecode"
	"golang.org/x/crypto/hkdf"
)

// quicV1InitialSalt is the version-1 Initial salt (RFC 9001 §5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// DecryptedInitial is the cleartext view of a QUIC Initial packet
// recovered with the public Initial keys.
type DecryptedInitial struct {
	Role            string      `json:"role"` // "client" or "server"
	PacketNumber    uint64      `json:"packet_number"`
	PacketNumberLen int         `json:"packet_number_length"`
	KeyHex          string      `json:"key_hex"`
	IVHex           string      `json:"iv_hex"`
	HPHex           string      `json:"hp_hex"`
	PayloadLen      int         `json:"decrypted_payload_length"`
	Frames          []QUICFrame `json:"frames"`
	CryptoStreamLen int         `json:"crypto_stream_length,omitempty"`
	CryptoStreamHex string      `json:"crypto_stream_hex,omitempty"`
	TLSMessage      string      `json:"tls_message,omitempty"`
	// JA4 is the QUIC client/server fingerprint (protocol prefix "q")
	// computed over the reassembled ClientHello / ServerHello. JA4 for a
	// ClientHello, JA4S for a ServerHello — empty if the CRYPTO stream is
	// incomplete or not a (Client/Server)Hello.
	JA4   string   `json:"ja4,omitempty"`
	Notes []string `json:"notes,omitempty"`
}

// QUICFrame is one parsed frame from the decrypted payload.
type QUICFrame struct {
	Type     string `json:"type"`
	TypeByte uint64 `json:"type_byte"`
	Count    int    `json:"count,omitempty"`  // PADDING run length
	Offset   uint64 `json:"offset,omitempty"` // CRYPTO
	Length   uint64 `json:"length,omitempty"` // CRYPTO data length
}

// DecryptInitial recovers the cleartext payload of a QUIC v1
// Initial packet from its full on-the-wire bytes. role is "client"
// for a client Initial and "server" for a server Initial — they
// derive from different HKDF labels ("client in" / "server in").
// Returns an error only on a malformed header or a GCM
// authentication failure (wrong role / corrupt packet / not
// actually an Initial).
func DecryptInitial(packet []byte, role string) (*DecryptedInitial, error) {
	if role != "client" && role != "server" {
		return nil, fmt.Errorf("role must be \"client\" or \"server\", got %q", role)
	}
	if len(packet) < 7 {
		return nil, fmt.Errorf("packet too short (%d bytes)", len(packet))
	}
	if packet[0]&0x80 == 0 {
		return nil, fmt.Errorf("not a long-header packet")
	}
	if (packet[0]>>4)&0x03 != 0 {
		return nil, fmt.Errorf("long packet type %d is not Initial", (packet[0]>>4)&0x03)
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	if version != 0x00000001 {
		return nil, fmt.Errorf("initial decryption only implemented for QUIC v1 "+
			"(0x00000001); got 0x%08X", version)
	}

	// Walk the long header to the packet-number offset.
	off := 5
	dcidLen := int(packet[off])
	off++
	if dcidLen > 20 || off+dcidLen+1 > len(packet) {
		return nil, fmt.Errorf("DCID length %d invalid/truncated", dcidLen)
	}
	dcid := packet[off : off+dcidLen]
	off += dcidLen
	scidLen := int(packet[off])
	off++
	if scidLen > 20 || off+scidLen > len(packet) {
		return nil, fmt.Errorf("SCID length %d invalid/truncated", scidLen)
	}
	off += scidLen
	tokLen, n, err := readVLI(packet[off:])
	if err != nil {
		return nil, fmt.Errorf("token length: %w", err)
	}
	off += n
	if uint64(off)+tokLen > uint64(len(packet)) {
		return nil, fmt.Errorf("token (%d bytes) overruns packet", tokLen)
	}
	off += int(tokLen)
	length, n2, err := readVLI(packet[off:])
	if err != nil {
		return nil, fmt.Errorf("length: %w", err)
	}
	off += n2
	pnOffset := off

	// The header-protection sample is the 16 bytes at pn_offset+4
	// (RFC 9001 §5.4.2: a 4-byte sample offset accommodates the
	// maximum packet-number length).
	if pnOffset+4+16 > len(packet) {
		return nil, fmt.Errorf("packet too short for header-protection sample")
	}
	if uint64(pnOffset)+length > uint64(len(packet)) || length < 20 {
		return nil, fmt.Errorf("declared length %d inconsistent with %d-byte packet",
			length, len(packet))
	}

	// Derive the Initial keys from the DCID (RFC 9001 §5.2).
	initialSecret := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	secret := expandLabel(initialSecret, role+" in", 32)
	key := expandLabel(secret, "quic key", 16)
	iv := expandLabel(secret, "quic iv", 12)
	hp := expandLabel(secret, "quic hp", 16)

	// Remove header protection (RFC 9001 §5.4.1).
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, fmt.Errorf("hp cipher: %w", err)
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, packet[pnOffset+4:pnOffset+4+16])
	firstByte := packet[0] ^ (mask[0] & 0x0f) // long header: low 4 bits
	pnLen := int(firstByte&0x03) + 1
	if pnOffset+pnLen > len(packet) {
		return nil, fmt.Errorf("packet number overruns packet")
	}
	pnBytes := make([]byte, pnLen)
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = packet[pnOffset+i] ^ mask[1+i]
		pn = pn<<8 | uint64(pnBytes[i])
	}

	// AAD is the unprotected header up to and including the
	// packet number (RFC 9001 §5.3).
	header := make([]byte, pnOffset+pnLen)
	copy(header, packet[:pnOffset+pnLen])
	header[0] = firstByte
	copy(header[pnOffset:], pnBytes)

	// Nonce = iv XOR left-padded packet number (RFC 9001 §5.3).
	nonce := make([]byte, 12)
	copy(nonce, iv)
	var pnPad [8]byte
	binary.BigEndian.PutUint64(pnPad[:], pn)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnPad[i]
	}

	// AEAD ciphertext spans from after the packet number to the
	// end of the declared length (payload + 16-byte GCM tag).
	ciphertext := packet[pnOffset+pnLen : pnOffset+int(length)]
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead cipher: %w", err)
	}
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("GCM authentication failed (wrong role, corrupt packet, "+
			"or not a v1 Initial): %w", err)
	}

	d := &DecryptedInitial{
		Role:            role,
		PacketNumber:    pn,
		PacketNumberLen: pnLen,
		KeyHex:          hex.EncodeToString(key),
		IVHex:           hex.EncodeToString(iv),
		HPHex:           hex.EncodeToString(hp),
		PayloadLen:      len(plaintext),
	}
	parseFrames(plaintext, d)
	return d, nil
}

// expandLabel implements HKDF-Expand-Label (RFC 8446 §7.1) with the
// QUIC "tls13 " prefix and an empty context, as used throughout
// RFC 9001 §5.
func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 3+len(full)+1)
	info = append(info, byte(length>>8), byte(length), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context
	out := make([]byte, length)
	r := hkdf.Expand(sha256.New, secret, info)
	// hkdf.Expand over SHA-256 never short-reads for length ≤ 255*32.
	_, _ = r.Read(out)
	return out
}

// parseFrames walks the decrypted payload and records each frame,
// reassembling CRYPTO fragments into the TLS handshake stream
// (RFC 9000 §19). Unknown frame types stop the walk with a note
// rather than risk a misparse.
func parseFrames(p []byte, d *DecryptedInitial) {
	type fragment struct {
		offset uint64
		data   []byte
	}
	var crypto []fragment
	i := 0
	for i < len(p) {
		t, tn, err := readVLI(p[i:])
		if err != nil {
			d.Notes = append(d.Notes, "truncated frame type")
			break
		}
		switch t {
		case 0x00: // PADDING — collapse the run.
			start := i
			for i < len(p) && p[i] == 0x00 {
				i++
			}
			d.Frames = append(d.Frames, QUICFrame{
				Type: "PADDING", TypeByte: 0x00, Count: i - start,
			})
			continue
		case 0x01: // PING
			d.Frames = append(d.Frames, QUICFrame{Type: "PING", TypeByte: 0x01})
			i += tn
		case 0x02, 0x03: // ACK / ACK-ECN
			j, ok := skipACK(p, i+tn, t == 0x03)
			d.Frames = append(d.Frames, QUICFrame{Type: "ACK", TypeByte: t})
			if !ok {
				d.Notes = append(d.Notes, "truncated ACK frame")
				i = len(p)
				break
			}
			i = j
		case 0x06: // CRYPTO: offset + length + data
			cursor := i + tn
			coff, on, err := readVLI(p[cursor:])
			if err != nil {
				d.Notes = append(d.Notes, "truncated CRYPTO offset")
				i = len(p)
				break
			}
			cursor += on
			clen, ln, err := readVLI(p[cursor:])
			if err != nil {
				d.Notes = append(d.Notes, "truncated CRYPTO length")
				i = len(p)
				break
			}
			cursor += ln
			if uint64(cursor)+clen > uint64(len(p)) {
				d.Notes = append(d.Notes, "CRYPTO data overruns payload")
				i = len(p)
				break
			}
			frag := make([]byte, clen)
			copy(frag, p[cursor:cursor+int(clen)])
			crypto = append(crypto, fragment{offset: coff, data: frag})
			d.Frames = append(d.Frames, QUICFrame{
				Type: "CRYPTO", TypeByte: 0x06, Offset: coff, Length: clen,
			})
			i = cursor + int(clen)
		case 0x1c, 0x1d: // CONNECTION_CLOSE
			j, ok := skipConnectionClose(p, i+tn, t == 0x1c)
			d.Frames = append(d.Frames, QUICFrame{Type: "CONNECTION_CLOSE", TypeByte: t})
			if !ok {
				d.Notes = append(d.Notes, "truncated CONNECTION_CLOSE frame")
				i = len(p)
				break
			}
			i = j
		default:
			d.Notes = append(d.Notes, fmt.Sprintf(
				"stopped at unhandled frame type 0x%02X (%d bytes remain)", t, len(p)-i))
			i = len(p)
		}
	}

	if len(crypto) == 0 {
		return
	}
	// Reassemble the CRYPTO stream by offset.
	sort.Slice(crypto, func(a, b int) bool { return crypto[a].offset < crypto[b].offset })
	var stream []byte
	var next uint64
	contiguous := true
	for _, f := range crypto {
		if f.offset != next {
			contiguous = false
			break
		}
		stream = append(stream, f.data...)
		next += uint64(len(f.data))
	}
	if !contiguous {
		d.Notes = append(d.Notes,
			"CRYPTO fragments are non-contiguous; stream reassembly is partial")
	}
	if len(stream) == 0 {
		return
	}
	d.CryptoStreamLen = len(stream)
	if len(stream) > 512 {
		d.CryptoStreamHex = strings.ToUpper(hex.EncodeToString(stream[:512])) + "..."
	} else {
		d.CryptoStreamHex = strings.ToUpper(hex.EncodeToString(stream))
	}
	switch stream[0] {
	case 0x01:
		d.TLSMessage = "ClientHello (feed crypto_stream_hex to tls_handshake_decode)"
	case 0x02:
		d.TLSMessage = "ServerHello (feed crypto_stream_hex to tls_handshake_decode)"
	}
	// Compute the QUIC JA4 / JA4S fingerprint (protocol prefix "q") over
	// the full reassembled handshake message. Only when the stream is
	// contiguous and complete — a partial ClientHello would fingerprint
	// wrong, so we surface nothing rather than a confidently-wrong value.
	if contiguous {
		if fp, _, err := tlsdecode.QUICHandshakeJA4(stream); err == nil {
			d.JA4 = fp
		}
	}
}

// skipACK advances past an ACK (0x02) or ACK-ECN (0x03) frame body,
// starting just after the type byte (RFC 9000 §19.3). Returns the
// new index and whether the frame was fully in-bounds.
func skipACK(p []byte, i int, ecn bool) (int, bool) {
	// Largest Acknowledged, ACK Delay.
	for k := 0; k < 2; k++ {
		_, n, err := readVLI(p[i:])
		if err != nil {
			return i, false
		}
		i += n
	}
	// ACK Range Count, First ACK Range.
	rangeCount, n, err := readVLI(p[i:])
	if err != nil {
		return i, false
	}
	i += n
	if _, n, err = readVLI(p[i:]); err != nil { // First ACK Range
		return i, false
	}
	i += n
	// rangeCount × (Gap, ACK Range Length).
	for r := uint64(0); r < rangeCount; r++ {
		for k := 0; k < 2; k++ {
			if _, n, err = readVLI(p[i:]); err != nil {
				return i, false
			}
			i += n
		}
	}
	// ECN variant adds ECT0, ECT1, ECN-CE counts.
	if ecn {
		for k := 0; k < 3; k++ {
			if _, n, err = readVLI(p[i:]); err != nil {
				return i, false
			}
			i += n
		}
	}
	return i, true
}

// skipConnectionClose advances past a CONNECTION_CLOSE frame body,
// starting just after the type byte. transport is true for the
// 0x1c (transport-error) variant, which carries an extra Frame Type
// field that the 0x1d (application-error) variant omits.
func skipConnectionClose(p []byte, i int, transport bool) (int, bool) {
	// Error Code.
	_, n, err := readVLI(p[i:])
	if err != nil {
		return i, false
	}
	i += n
	if transport {
		_, n, err = readVLI(p[i:]) // Frame Type
		if err != nil {
			return i, false
		}
		i += n
	}
	rl, n, err := readVLI(p[i:]) // Reason Phrase Length
	if err != nil {
		return i, false
	}
	i += n
	if uint64(i)+rl > uint64(len(p)) {
		return i, false
	}
	return i + int(rl), true
}
