// Package ansiblevault triages an Ansible Vault file for password cracking.
//
// Ansible Vault (`$ANSIBLE_VAULT;…`) is the standard at-rest encryption for
// secrets in Ansible playbooks/roles — ubiquitous in DevOps and
// infrastructure-as-code repositories, and so a common loot artifact on a
// CI/ops host or in a pulled repo. The vault password is the single secret
// protecting every value inside, and it is a slow PBKDF2-HMAC-SHA256 target:
// this parses the header offline and reports the version, cipher, optional
// vault-id, and the matching hashcat mode (16900) so the result feeds straight
// into the project's hash/cracking tooling.
//
// No confidently-wrong output: the file is recognised only by its
// `$ANSIBLE_VAULT;` magic header; it reports the *envelope parameters* only — it
// does not crack or decrypt (the password is never recovered); and a non-vault
// input is rejected. When the body is a well-formed AES256 envelope it also
// rebuilds the ready-to-crack ansible2john hash (`$ansible$0*0*…`, hashcat mode
// 16900) offline — the body is hexlify(hexlify(salt)+"\n"+hmac+"\n"+hexlify(ct)),
// so a single hex-decode yields the three fields verbatim. The rebuild is
// structurally guarded (32-byte salt + 32-byte HMAC, valid-hex ciphertext): on
// any deviation it emits no hash rather than a wrong one.
//
// Wrap-vs-native: native — a header parse + an offline ansible2john rebuild over
// the documented format (ansible lib/ansible/parsing/vault/__init__.py); stdlib
// only, no new go.mod dependency. Anchored to real ansible-vault output.
package ansiblevault

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded Ansible Vault envelope.
type Result struct {
	Format  string `json:"format"`
	Version string `json:"version"`
	Cipher  string `json:"cipher"`
	// VaultID is the label from a 1.2 header (e.g. "prod"), empty for 1.1.
	VaultID string `json:"vault_id,omitempty"`
	// BodyBytes is the size of the hex-decoded vault envelope (salt + HMAC +
	// ciphertext), 0 if the body is absent or not valid hex.
	BodyBytes int `json:"body_bytes"`

	// JohnHash is the ready-to-crack ansible2john / hashcat-16900 string
	// ("$ansible$0*0*salt*hmac*ciphertext"), rebuilt offline from the body when
	// it is a well-formed AES256 envelope; empty when the body is absent or its
	// structure does not match (no confidently-wrong output).
	JohnHash string `json:"john_hash,omitempty"`

	HashcatMode int    `json:"hashcat_mode"`
	JohnTool    string `json:"john_tool"`
	Note        string `json:"note"`
}

const magic = "$ANSIBLE_VAULT;"

// Decode parses an Ansible Vault file's header.
func Decode(input string) (*Result, error) {
	s := strings.TrimSpace(input)
	if !strings.HasPrefix(s, magic) {
		return nil, fmt.Errorf("ansiblevault: not an Ansible Vault file (missing %q header)", magic)
	}
	lines := strings.SplitN(s, "\n", 2)
	header := strings.TrimSpace(lines[0])
	fields := strings.Split(header, ";")
	if len(fields) < 3 {
		return nil, fmt.Errorf("ansiblevault: malformed header %q", header)
	}

	res := &Result{
		Format:      "ansible-vault",
		Version:     strings.TrimSpace(fields[1]),
		Cipher:      strings.TrimSpace(fields[2]),
		HashcatMode: 16900,
		JohnTool:    "ansible2john",
		Note: "Triage only — not cracked or decrypted (the password is never recovered). When the body is a " +
			"well-formed AES256 envelope the ready-to-crack ansible2john hash ($ansible$0*0*…) is rebuilt " +
			"offline (john_hash). KDF is PBKDF2-HMAC-SHA256 (10000 iterations) over AES-256-CTR + HMAC-SHA256 " +
			"— a slow per-guess target; hashcat -m 16900.",
	}
	if len(fields) >= 4 {
		res.VaultID = strings.TrimSpace(fields[3])
	}

	if len(lines) == 2 {
		clean, n := cleanHexBody(lines[1])
		res.BodyBytes = n
		// ansible2john / -m 16900 covers only the AES256 envelope; don't synth a
		// hash for an unrecognised cipher.
		if res.Cipher == "AES256" {
			if h, ok := ansible2john(clean); ok {
				res.JohnHash = h
			}
		}
	}
	return res, nil
}

// cleanHexBody strips whitespace (line wrapping / indentation) from a vault body
// and returns the contiguous hex string plus its decoded byte length, or ("", 0)
// if the body holds any non-hex content.
func cleanHexBody(body string) (string, int) {
	var b strings.Builder
	for _, c := range body {
		switch {
		case c == ' ' || c == '\n' || c == '\r' || c == '\t':
			// skip whitespace
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			b.WriteRune(c)
		default:
			return "", 0 // non-hex content
		}
	}
	s := b.String()
	return s, len(s) / 2
}

// ansible2john rebuilds the John the Ripper / hashcat-16900 hash string from a
// whitespace-stripped vault body. VaultAES256.encrypt
// (ansible lib/ansible/parsing/vault/__init__.py) emits the body as
// hexlify(hexlify(salt) + "\n" + hmac_hexdigest + "\n" + hexlify(ciphertext)),
// so a single hex-decode yields the three newline-separated hex fields verbatim.
// The structure is pinned to AES256 (32-byte salt and 32-byte HMAC-SHA256 → 64
// hex chars each, valid-hex non-empty ciphertext); on any deviation it returns
// ok=false so the caller emits no hash rather than a wrong one.
func ansible2john(cleanHex string) (string, bool) {
	if cleanHex == "" || len(cleanHex)%2 != 0 {
		return "", false
	}
	raw, err := hex.DecodeString(cleanHex)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(raw), "\n")
	if len(parts) != 3 {
		return "", false
	}
	salt, mac, ct := parts[0], parts[1], parts[2]
	if !isHex(salt) || len(salt) != 64 ||
		!isHex(mac) || len(mac) != 64 ||
		!isHex(ct) || len(ct)%2 != 0 {
		return "", false
	}
	return fmt.Sprintf("$ansible$0*0*%s*%s*%s", salt, mac, ct), true
}

// isHex reports whether s is a non-empty run of hex digits.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			// hex digit
		default:
			return false
		}
	}
	return true
}
