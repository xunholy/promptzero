// ldap_password.go — host-side LDAP userPassword (RFC 2307 + pw-sha2) compute +
// verify Spec, delegating to internal/ldappw.
//
// Wrap-vs-native: native — every scheme is a single digest (crypto/{md5,sha1,
// sha256,sha512}) plus encoding/base64, with no key-stretching. It is an
// offline credential primitive: compute the userPassword storage string for a
// candidate password, or verify a candidate against a captured value (e.g. from
// a slapcat dump). Complements hash_identify (which recognises {SSHA}/{SHA}/
// {MD5}) and hash_crack (which attacks them). Offline compute from
// operator-supplied strings; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ldappw"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ldapPasswordSpec)
}

var ldapPasswordSpec = Spec{
	Name: "ldap_password",
	Description: "Compute or verify an LDAP userPassword value — the directory-server credential " +
		"format used by OpenLDAP slapd, 389 Directory Server, Dovecot, and Atlassian Crowd, and the " +
		"compute/verify side of the credential toolkit (hash_identify recognises {SSHA}/{SHA}/{MD5} as " +
		"hashcat 111 / 101 / 1001, hash_crack attacks them). Use it to confirm a password recovered from a " +
		"slapcat / directory backup, build a userPassword entry for an authorized lab, or check a candidate " +
		"against a captured value.\n\n" +
		"Every scheme is `{SCHEME}base64( H(password ‖ salt) ‖ salt )` with no key-stretching: the unsalted " +
		"forms ({SHA}, {MD5}, {SHA256}, {SHA384}, {SHA512}) are a bare digest; the salted forms ({SSHA}, " +
		"{SMD5}, {SSHA256}, {SSHA384}, {SSHA512}) append a random salt after the digest. On verify the salt " +
		"length is recovered from the blob (slapd defaults to 4 bytes, Dovecot to longer — both verify), and " +
		"the digest is compared constant-time.\n\n" +
		"Provide **password** and either a full **hash** ({SCHEME}…) to verify against, or — for compute mode " +
		"— a **scheme** (default {SSHA}) and optional **salt** (used verbatim for salted schemes; a 4-byte " +
		"random salt is generated if omitted; rejected for unsalted schemes). Output is the userPassword " +
		"string in compute mode, or matched true/false plus the detected scheme + salt length in verify mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so it " +
		"is Low risk. {CRYPT} (RFC 2307 delegates it to crypt(3)) and {CLEARTEXT} are out of scope — use " +
		"md5crypt / sha_crypt / bcrypt for {CRYPT}. Verified in-tree against the OpenLDAP `slappasswd` oracle " +
		"({SHA}/{SSHA}/{MD5}) and the definitional pw-sha2 / Dovecot vectors (SHA-2 variants). Wrap-vs-native: " +
		"native — crypto/{md5,sha1,sha256,sha512} + encoding/base64, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"hash":{"type":"string","description":"A full {SCHEME}base64… userPassword value to verify the password against (verify mode)."},
			"scheme":{"type":"string","description":"Compute-mode scheme (default {SSHA}). Case-insensitive; braces optional.","enum":["{MD5}","{SMD5}","{SHA}","{SSHA}","{SHA256}","{SSHA256}","{SHA384}","{SSHA384}","{SHA512}","{SSHA512}"]},
			"salt":{"type":"string","description":"Compute-mode salt for salted schemes (used verbatim; random 4-byte salt if omitted). Rejected for unsalted schemes."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ldapPasswordHandler,
}

func ldapPasswordHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("ldap_password: 'password' is required")
	}

	// Verify mode: a full hash was supplied.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		res, err := ldappw.Verify(password, h)
		if err != nil {
			return "", fmt.Errorf("ldap_password: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": res.Matched, "scheme": res.Scheme,
			"salted": res.Salted, "salt_len": res.SaltLen,
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	scheme := strings.TrimSpace(str(p, "scheme"))
	if scheme == "" {
		scheme = "{SSHA}"
	}
	hash, err := ldappw.Compute(scheme, password, str(p, "salt"))
	if err != nil {
		return "", fmt.Errorf("ldap_password: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "scheme": ldappw.Identify(hash), "hash": hash,
	}, "", "  ")
	return string(out), nil
}
