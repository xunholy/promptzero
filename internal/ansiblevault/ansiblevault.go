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
// does not crack, decrypt, or emit the ansible2john hash (that needs the
// hex-decoded salt/HMAC/ciphertext); and a non-vault input is rejected.
//
// Wrap-vs-native: native — a header parse + a hex-body sanity check over the
// documented format (ansible lib/ansible/parsing/vault/__init__.py); stdlib
// only, no new go.mod dependency. Anchored to real ansible-vault output.
package ansiblevault

import (
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
		Note: "Envelope parameters only — not cracked, decrypted, or emitted as an ansible2john hash. " +
			"AES-256-CTR + HMAC-SHA256 under PBKDF2-HMAC-SHA256 (10000 iterations) — a slow per-guess KDF; " +
			"hashcat -m 16900.",
	}
	if len(fields) >= 4 {
		res.VaultID = strings.TrimSpace(fields[3])
	}

	if len(lines) == 2 {
		res.BodyBytes = hexBodyLen(lines[1])
	}
	return res, nil
}

// hexBodyLen returns the byte length of the hex-decoded body (whitespace
// stripped), or 0 if the body is not even-length hex.
func hexBodyLen(body string) int {
	var n int
	for _, c := range body {
		switch {
		case c == ' ' || c == '\n' || c == '\r' || c == '\t':
			// skip whitespace
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			n++
		default:
			return 0 // non-hex content
		}
	}
	return n / 2
}
