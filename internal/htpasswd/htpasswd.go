// Package htpasswd classifies the password hashes in an Apache / nginx
// htpasswd basic-auth file.
//
// An htpasswd file is a list of "username:hash" lines (RFC-less but stable,
// documented by the Apache httpd `htpasswd` and nginx auth_basic_user_file
// tooling). Each hash carries a self-identifying prefix that names the scheme:
// bcrypt ($2a/$2b/$2x/$2y$), the Apache-specific iterated MD5 ($apr1$), the
// crypt(3) family ($1$ MD5, $5$ SHA-256, $6$ SHA-512, $7$/$y$ yescrypt), the
// LDAP-style base64 digests ({SHA}, {SSHA}), the traditional 13-character DES
// crypt, and unhashed plaintext (the htpasswd -p mode). After an operator
// recovers such a file the question is "which of these are weak / crackable,
// and with what hashcat mode?" — this answers it without touching the hashes.
//
// For each entry this surfaces the username, the recognised scheme, the
// matching hashcat -m mode, a strength tier (strong / weak / very weak /
// critical), and a per-entry note; the result summarises the weakest entries
// and flags any plaintext.
//
// No confidently-wrong output: a scheme is named only from its unambiguous
// prefix (or, for DES crypt, the exact 13-char crypt-alphabet shape); an
// unrecognised field is surfaced as "plaintext / unknown" with a note, never
// guessed as a specific hash; the password is never cracked, only classified.
//
// Wrap-vs-native: native — a line + prefix classifier, stdlib only, no new
// go.mod dependency. Anchored to real openssl / x-crypto / hashcat-example
// vectors (see the test).
package htpasswd

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// Entry is one classified htpasswd line.
type Entry struct {
	Line        int    `json:"line"`
	Username    string `json:"username"`
	Scheme      string `json:"scheme"`
	HashcatMode string `json:"hashcat_mode,omitempty"`
	Strength    string `json:"strength"`
	Hash        string `json:"hash"`
	Note        string `json:"note,omitempty"`
}

// Result is the classified file.
type Result struct {
	Format       string   `json:"format"`
	EntryCount   int      `json:"entry_count"`
	Entries      []Entry  `json:"entries,omitempty"`
	WeakUsers    []string `json:"weak_users,omitempty"`
	PlaintextHit bool     `json:"plaintext_present,omitempty"`
	Malformed    int      `json:"malformed_lines,omitempty"`
	Note         string   `json:"note"`
}

// Strength tiers.
const (
	strong   = "strong"
	weak     = "weak"
	veryWeak = "very weak"
	critical = "critical"
)

// Decode classifies an htpasswd file.
func Decode(data []byte) (*Result, error) {
	res := &Result{Format: "htpasswd"}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimRight(sc.Text(), "\r")
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		// Username and hash split on the FIRST colon (no recognised hash
		// scheme contains a colon, so the remainder is the hash verbatim).
		idx := strings.IndexByte(raw, ':')
		if idx < 0 {
			res.Malformed++
			continue
		}
		user := raw[:idx]
		hash := raw[idx+1:]
		e := classify(hash)
		e.Line = line
		e.Username = user
		e.Hash = hash
		res.Entries = append(res.Entries, e)
		if e.Strength == weak || e.Strength == veryWeak || e.Strength == critical {
			res.WeakUsers = append(res.WeakUsers, user)
		}
		if e.Scheme == "plaintext / unknown" {
			res.PlaintextHit = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("htpasswd: %w", err)
	}
	res.EntryCount = len(res.Entries)
	res.Note = summarize(res)
	return res, nil
}

// classify names the hash scheme from its self-identifying prefix (or DES
// crypt's exact 13-char shape), with the hashcat mode and strength tier.
func classify(h string) Entry {
	switch {
	case hasBcryptPrefix(h):
		return Entry{Scheme: "bcrypt", HashcatMode: "3200", Strength: strong,
			Note: "bcrypt — slow, salted; the recommended htpasswd scheme."}
	case strings.HasPrefix(h, "$apr1$"):
		return Entry{Scheme: "apache-md5 (apr1)", HashcatMode: "1600", Strength: weak,
			Note: "Apache iterated MD5 — fast to crack; prefer bcrypt."}
	case strings.HasPrefix(h, "$1$"):
		return Entry{Scheme: "md5-crypt", HashcatMode: "500", Strength: weak,
			Note: "crypt(3) MD5 — fast to crack; prefer bcrypt."}
	case strings.HasPrefix(h, "$5$"):
		return Entry{Scheme: "sha256-crypt", HashcatMode: "7400", Strength: strong,
			Note: "crypt(3) SHA-256 — iterated, salted."}
	case strings.HasPrefix(h, "$6$"):
		return Entry{Scheme: "sha512-crypt", HashcatMode: "1800", Strength: strong,
			Note: "crypt(3) SHA-512 — iterated, salted."}
	case strings.HasPrefix(h, "$7$"), strings.HasPrefix(h, "$y$"), strings.HasPrefix(h, "$gy$"):
		return Entry{Scheme: "yescrypt", Strength: strong,
			Note: "yescrypt — memory-hard; no standard hashcat mode."}
	case strings.HasPrefix(h, "{SSHA}"):
		return Entry{Scheme: "salted-sha1 (ssha)", HashcatMode: "111", Strength: weak,
			Note: "salted SHA-1 — fast hash; prefer bcrypt."}
	case strings.HasPrefix(h, "{SHA}"):
		return Entry{Scheme: "sha1-base64", Strength: weak,
			Note: "unsalted base64 SHA-1 — fast and unsalted; base64-decode to hex for hashcat -m 100."}
	case strings.HasPrefix(h, "{PLAIN}"):
		return Entry{Scheme: "plaintext / unknown", Strength: critical,
			Note: "explicit plaintext — the password is stored in the clear."}
	case isDESCrypt(h):
		return Entry{Scheme: "des-crypt", HashcatMode: "1500", Strength: veryWeak,
			Note: "traditional DES crypt — only 8 significant chars; trivially cracked (could also be a 13-char plaintext)."}
	default:
		return Entry{Scheme: "plaintext / unknown", Strength: critical,
			Note: "no recognised hash scheme — stored as plaintext (htpasswd -p), or an unrecognised format."}
	}
}

// hasBcryptPrefix reports whether h is a bcrypt hash ($2 + variant + $).
func hasBcryptPrefix(h string) bool {
	if len(h) < 4 || h[0] != '$' || h[1] != '2' {
		return false
	}
	switch h[2] {
	case 'a', 'b', 'x', 'y':
		return h[3] == '$'
	default:
		return false
	}
}

// isDESCrypt reports whether h is a traditional 13-character DES crypt hash:
// exactly 13 bytes drawn from the crypt(3) alphabet [./0-9A-Za-z].
func isDESCrypt(h string) bool {
	if len(h) != 13 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := c == '.' || c == '/' ||
			(c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z')
		if !ok {
			return false
		}
	}
	return true
}

func summarize(res *Result) string {
	if res.EntryCount == 0 {
		base := "No htpasswd entries found."
		if res.Malformed > 0 {
			base += fmt.Sprintf(" %d malformed line(s) (no ':' separator).", res.Malformed)
		}
		return base
	}
	base := fmt.Sprintf("%d entr%s classified. ", res.EntryCount, plural(res.EntryCount))
	if res.PlaintextHit {
		return base + "CRITICAL: at least one password is stored in plaintext / an unrecognised format. " +
			"Weak/crackable users: " + strings.Join(res.WeakUsers, ", ") + ". Re-hash with bcrypt."
	}
	if len(res.WeakUsers) > 0 {
		return base + "Weak (fast-to-crack) schemes present for: " + strings.Join(res.WeakUsers, ", ") +
			". Prefer bcrypt. Hashes are classified only, never cracked."
	}
	return base + "All entries use strong schemes (bcrypt / sha256-crypt / sha512-crypt / yescrypt). " +
		"Hashes are classified only, never cracked."
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
