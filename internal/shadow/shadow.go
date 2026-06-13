// Package shadow decodes a Linux /etc/shadow file for credential triage.
//
// /etc/shadow is the single highest-value Linux post-exploitation artifact: it
// holds every local account's password hash. This parses a looted shadow file
// offline and, per user, classifies the password field — the hashing scheme
// (sha512crypt / sha256crypt / md5crypt / bcrypt / yescrypt / descrypt / …), the
// matching crack mode (hashcat mode + john format), and the account status
// (active / locked / no-password / disabled). It surfaces the two findings that
// matter most: accounts with a crackable hash (with the exact mode to feed the
// cracker) and accounts with NO password at all.
//
// No confidently-wrong output: the password field is classified only by its
// documented crypt id ($6$, $2y$, …) or shape (13-char descrypt, status markers
// * / ! / empty); an unrecognised field is reported scheme "unknown" with no
// crack mode, never guessed; a hashcat mode is emitted only for schemes hashcat
// supports natively (yescrypt/gost-yescrypt are reported john-only). A locked
// account whose hash is still present ("!$6$…") is flagged locked *and*
// crackable — the lock only disables login, the hash is still recoverable. Input
// with no shadow-shaped line is rejected; a passwd-style "x" placeholder is
// reported as shadowed, not a hash.
//
// Wrap-vs-native: native — a field split over the documented shadow(5) format
// and crypt(5) id prefixes; stdlib only, no new go.mod dependency. Crack modes
// per the hashcat and John the Ripper format tables.
package shadow

import (
	"fmt"
	"strconv"
	"strings"
)

// Entry is one decoded shadow line.
type Entry struct {
	User string `json:"user"`
	// Status is "active", "locked", "no-password", "disabled", or "shadowed".
	Status string `json:"status"`
	Locked bool   `json:"locked,omitempty"`
	// HashScheme names the crypt scheme when a hash is present.
	HashScheme string `json:"hash_scheme,omitempty"`
	// HashcatMode is the hashcat -m mode, 0 when none/unknown or hashcat lacks a
	// native mode for the scheme (see JohnFormat / Note).
	HashcatMode int    `json:"hashcat_mode,omitempty"`
	JohnFormat  string `json:"john_format,omitempty"`
	// Crackable is true when a real password hash is present (regardless of lock).
	Crackable bool `json:"crackable"`

	LastChangeDays int    `json:"last_change_days,omitempty"`
	MaxAgeDays     int    `json:"max_age_days,omitempty"`
	ExpireDays     int    `json:"expire_days,omitempty"`
	Note           string `json:"note,omitempty"`
}

// Result is the decoded shadow file.
type Result struct {
	Format          string  `json:"format"`
	Entries         []Entry `json:"entries"`
	CrackableCount  int     `json:"crackable_count"`
	NoPasswordCount int     `json:"no_password_count"`
	LockedCount     int     `json:"locked_count"`
	Note            string  `json:"note"`
}

// scheme describes a crypt id.
type scheme struct {
	name        string
	hashcatMode int // 0 when hashcat has no native mode
	john        string
	note        string
}

// schemesByID maps a crypt "$id$" prefix to its crack parameters (hashcat mode
// and John format per the published format tables).
var schemesByID = map[string]scheme{ //nolint:gochecknoglobals
	"1":    {"md5crypt", 500, "md5crypt", ""},
	"2a":   {"bcrypt", 3200, "bcrypt", ""},
	"2b":   {"bcrypt", 3200, "bcrypt", ""},
	"2x":   {"bcrypt", 3200, "bcrypt", ""},
	"2y":   {"bcrypt", 3200, "bcrypt", ""},
	"5":    {"sha256crypt", 7400, "sha256crypt", ""},
	"6":    {"sha512crypt", 1800, "sha512crypt", ""},
	"sha1": {"sha1crypt", 15100, "sha1crypt", ""},
	"7":    {"scrypt", 8900, "scrypt", ""},
	"md5":  {"SunMD5", 3300, "SunMD5", ""},
	"apr1": {"md5crypt (Apache apr1)", 1600, "md5crypt-apache", ""},
	"y":    {"yescrypt", 0, "yescrypt", "hashcat has no native yescrypt mode — crack with John the Ripper (yescrypt)"},
	"gy":   {"gost-yescrypt", 0, "gost-yescrypt", "hashcat has no native gost-yescrypt mode — crack with John the Ripper"},
}

// Decode parses an /etc/shadow file.
func Decode(input string) (*Result, error) {
	res := &Result{Format: "shadow"}
	recognised := false

	for _, raw := range strings.Split(input, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		e, ok := decodeEntry(fields)
		if !ok {
			continue
		}
		recognised = true
		switch {
		case e.Crackable:
			res.CrackableCount++
		case e.Status == "no-password":
			res.NoPasswordCount++
		}
		if e.Locked {
			res.LockedCount++
		}
		res.Entries = append(res.Entries, *e)
	}

	if !recognised {
		return nil, fmt.Errorf("shadow: no shadow-format entry found (expected user:password[:aging…] lines)")
	}
	res.Note = noteFor(res)
	return res, nil
}

// decodeEntry classifies one colon-split shadow line.
func decodeEntry(fields []string) (*Entry, bool) {
	user := fields[0]
	pw := fields[1]
	if user == "" {
		return nil, false
	}
	e := &Entry{User: user}
	parseAging(e, fields)

	classifyPassword(e, pw)
	return e, true
}

// classifyPassword fills the hash/status fields from the password column.
func classifyPassword(e *Entry, pw string) {
	switch {
	case pw == "":
		e.Status = "no-password"
		e.Note = "EMPTY password field — this account authenticates with NO password."
		return
	case pw == "x":
		e.Status = "shadowed"
		e.Note = "passwd-style 'x' placeholder — the hash lives in /etc/shadow, not here."
		return
	case pw == "*" || strings.EqualFold(pw, "*LK*") || pw == "!*":
		e.Status = "disabled"
		e.Note = "no valid hash — password login disabled (typical of service accounts)."
		return
	case pw == "!" || pw == "!!":
		e.Status = "locked"
		e.Locked = true
		e.Note = "locked with no hash — no crack target."
		return
	}

	// A "!" or "*" prefix locks login but may still carry a recoverable hash.
	locked := false
	body := pw
	for len(body) > 0 && (body[0] == '!' || body[0] == '*') {
		locked = true
		body = body[1:]
	}

	if !classifyHash(e, body) {
		e.Status = "unknown"
		e.Note = "unrecognised password field — not a known crypt hash or status marker."
		e.Locked = locked
		if locked {
			e.Status = "locked"
		}
		return
	}

	e.Crackable = true
	e.Locked = locked
	if locked {
		e.Status = "locked"
		e.Note = "account is locked, but the hash is still present and recoverable (the lock only disables login)."
	} else {
		e.Status = "active"
	}
}

// classifyHash recognises a crypt hash body and fills the scheme/mode fields.
// It returns false when body is not a recognised hash.
func classifyHash(e *Entry, body string) bool {
	if strings.HasPrefix(body, "$") {
		parts := strings.SplitN(body, "$", 3)
		// "$id$rest" → parts = ["", id, rest]; require a non-empty id and a salt/hash body.
		if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
			return false
		}
		sc, ok := schemesByID[strings.ToLower(parts[1])]
		if !ok {
			e.HashScheme = "unknown ($" + parts[1] + "$)"
			return true
		}
		e.HashScheme = sc.name
		e.HashcatMode = sc.hashcatMode
		e.JohnFormat = sc.john
		if sc.note != "" {
			e.Note = sc.note
		}
		return true
	}

	// Traditional DES crypt: exactly 13 chars from the crypt alphabet.
	if isDescrypt(body) {
		e.HashScheme = "descrypt (traditional DES)"
		e.HashcatMode = 1500
		e.JohnFormat = "descrypt"
		return true
	}
	return false
}

// isDescrypt reports whether s is a 13-character traditional-DES crypt hash.
func isDescrypt(s string) bool {
	if len(s) != 13 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '/':
		default:
			return false
		}
	}
	return true
}

// parseAging fills the optional password-aging fields when present and numeric.
func parseAging(e *Entry, fields []string) {
	get := func(i int) (int, bool) {
		if i >= len(fields) || fields[i] == "" {
			return 0, false
		}
		n, err := strconv.Atoi(fields[i])
		if err != nil {
			return 0, false
		}
		return n, true
	}
	if n, ok := get(2); ok {
		e.LastChangeDays = n
	}
	if n, ok := get(4); ok {
		e.MaxAgeDays = n
	}
	if n, ok := get(7); ok {
		e.ExpireDays = n
	}
}

func noteFor(res *Result) string {
	n := fmt.Sprintf("%d entr%s; %d with a crackable hash, %d locked, %d with NO password. ",
		len(res.Entries), plural(len(res.Entries)), res.CrackableCount, res.LockedCount, res.NoPasswordCount)
	n += "Each crackable entry carries its hashcat mode / John format to feed straight into the cracker. " +
		"Triage only — no hash is cracked. Offline; no network, no device."
	return n
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
