// Package sshpub triages OpenSSH *public* keys — the authorized_keys /
// known_hosts / bare public-key lines an operator finds on a host during IR or
// an audit. It is the public-key counterpart to the private-key decoders
// (ssh_privkey_decode, pem_privkey_decode, putty_privkey_decode): given a line
// (or a whole file of lines), it reports per key the type, key size, and the
// SHA256 + MD5 fingerprints exactly as `ssh-keygen -l` prints them, plus the
// comment, any authorized_keys options, and any known_hosts marker / host
// field.
//
// Two forensic levers beyond plain parsing:
//
//   - For an ssh-rsa key it surfaces the modulus (hex) so the key chains
//     straight into roca_detect — fingerprint the key, then screen the RSA
//     ones for the Infineon ROCA weakness.
//   - For a hashed known_hosts entry (|1|salt|hash) it can test a candidate
//     hostname against the HMAC-SHA1, deanonymising which host the entry refers
//     to — the same check `ssh-keygen -F` performs, the standard technique for
//     mapping lateral movement off a captured known_hosts file.
//
// Wrap-vs-native: native — the public-key wire blob is parsed directly off the
// RFC 4253 length-prefixed format (a sequence of uint32-prefixed strings) and
// the fingerprints are stdlib crypto/sha256 + crypto/md5 + crypto/hmac over
// that blob. No x/crypto/ssh dependency (and so none of its govulncheck
// surface) and no new go.mod entry. The fingerprint, key-size, and
// hashed-host computations are pinned against `ssh-keygen -l` / `-H` / `-F`.
package sshpub

import (
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // MD5 fingerprints are an SSH wire format, not a security primitive here.
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is the known_hosts hashed-host format, fixed by OpenSSH.
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Key is one parsed public-key entry.
type Key struct {
	// Type is the declared/embedded key algorithm, e.g. "ssh-ed25519",
	// "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-dss",
	// "sk-ssh-ed25519@openssh.com".
	Type string `json:"type"`
	// Label is the friendly type ssh-keygen prints in parentheses
	// (ED25519 / RSA / ECDSA / DSA / ED25519-SK / ECDSA-SK).
	Label string `json:"label"`
	// Bits is the key size as ssh-keygen reports it.
	Bits int `json:"bits"`
	// FingerprintSHA256 is "SHA256:" + base64(SHA-256(blob)) without padding.
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	// FingerprintMD5 is "MD5:" + colon-separated lowercase hex of MD5(blob).
	FingerprintMD5 string `json:"fingerprint_md5"`
	// Comment is the trailing comment field, if any.
	Comment string `json:"comment,omitempty"`
	// Options is the authorized_keys options field, when the prefix parsed as
	// options (contained "=" or a known option keyword).
	Options string `json:"options,omitempty"`
	// Marker is a known_hosts marker: "@cert-authority" or "@revoked".
	Marker string `json:"marker,omitempty"`
	// Hosts is the known_hosts host field (raw — may be a comma list, a
	// [host]:port form, or a |1|salt|hash hashed entry).
	Hosts string `json:"hosts,omitempty"`
	// HashedHost is true when Hosts is a |1|salt|hash hashed known_hosts entry.
	HashedHost bool `json:"hashed_host,omitempty"`
	// HostMatch is set to the candidate hostname when it was supplied and
	// matched this entry's host field (hashed via HMAC-SHA1, or plaintext).
	HostMatch string `json:"host_match,omitempty"`
	// RSAModulusHex is the ssh-rsa modulus in hex, for chaining into
	// roca_detect. Empty for non-RSA keys.
	RSAModulusHex string `json:"rsa_modulus_hex,omitempty"`
	// Note carries interpretation guidance (weak key size, ROCA chaining, …).
	Note string `json:"note,omitempty"`
}

// Result is the outcome of a Decode call.
type Result struct {
	// Keys is one entry per parsed line.
	Keys []Key `json:"keys"`
	// Count is len(Keys).
	Count int `json:"count"`
}

// labels maps key-type prefixes to the friendly label ssh-keygen prints.
var labels = map[string]string{
	"ssh-ed25519":                        "ED25519",
	"ssh-rsa":                            "RSA",
	"ssh-dss":                            "DSA",
	"ecdsa-sha2-nistp256":                "ECDSA",
	"ecdsa-sha2-nistp384":                "ECDSA",
	"ecdsa-sha2-nistp521":                "ECDSA",
	"sk-ssh-ed25519@openssh.com":         "ED25519-SK",
	"sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
}

// Decode parses one or many OpenSSH public-key lines (newline-separated).
// candidateHost, when non-empty, is tested against each entry's host field —
// matching hashed (|1|salt|hash) entries via HMAC-SHA1 and plaintext host lists
// directly. Blank lines and #-comments are skipped. A line that does not parse
// is reported as a Key with a Note rather than aborting the whole batch.
func Decode(input, candidateHost string) (*Result, error) {
	res := &Result{}
	for _, raw := range strings.Split(input, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := parseLine(line, candidateHost)
		if err != nil {
			res.Keys = append(res.Keys, Key{Note: "unparsed: " + err.Error()})
			continue
		}
		res.Keys = append(res.Keys, *k)
	}
	res.Count = len(res.Keys)
	if res.Count == 0 {
		return nil, errors.New("no public-key lines found")
	}
	return res, nil
}

// parseLine parses a single line by locating the base64 key blob whose embedded
// algorithm name matches the preceding type token — that self-consistency is
// the anchor and the validity gate. Everything before the type token is the
// prefix (options or marker+hosts); everything after the blob is the comment.
func parseLine(line, candidateHost string) (*Key, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, errors.New("too few fields")
	}

	typeIdx := -1
	var blob []byte
	for j := 1; j < len(fields); j++ {
		decoded, algo, ok := tryBlob(fields[j])
		if ok && algo == fields[j-1] {
			typeIdx, blob = j-1, decoded
			break
		}
	}
	if typeIdx < 0 {
		return nil, errors.New("no key blob whose embedded type matches its declared type")
	}

	k := &Key{Type: fields[typeIdx]}
	k.Label = labels[k.Type]
	if k.Label == "" {
		k.Label = strings.ToUpper(k.Type)
	}
	k.FingerprintSHA256, k.FingerprintMD5 = fingerprints(blob)
	if c := strings.Join(fields[typeIdx+2:], " "); c != "" {
		k.Comment = c
	}
	parsePrefix(k, fields[:typeIdx], candidateHost)

	bits, modHex, note := inspectBlob(k.Type, blob)
	k.Bits = bits
	k.RSAModulusHex = modHex
	k.Note = note
	return k, nil
}

// parsePrefix classifies the tokens before the type field: a known_hosts marker
// (@cert-authority / @revoked), then either authorized_keys options or a
// known_hosts host field (plaintext or |1| hashed), running the candidate-host
// test where applicable.
func parsePrefix(k *Key, prefix []string, candidateHost string) {
	if len(prefix) == 0 {
		return
	}
	rest := prefix
	if rest[0] == "@cert-authority" || rest[0] == "@revoked" {
		k.Marker = rest[0]
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return
	}
	token := strings.Join(rest, " ")
	switch {
	case strings.HasPrefix(token, "|1|"):
		k.Hosts = token
		k.HashedHost = true
		if candidateHost != "" && matchHashedHost(token, candidateHost) {
			k.HostMatch = candidateHost
		}
	case k.Marker == "" && len(rest) == 1 && strings.Contains(token, "=") && !looksLikeHostList(token):
		k.Options = token
	default:
		// A marker is only valid in known_hosts, so anything after it is a host
		// field; otherwise a single non-options token is a host list.
		k.Hosts = token
		if candidateHost != "" && matchPlainHost(token, candidateHost) {
			k.HostMatch = candidateHost
		}
	}
}

// looksLikeHostList reports whether a token is more plausibly a known_hosts host
// field than an authorized_keys options string — it carries host separators and
// no '=' option assignment beyond a bracketed port.
func looksLikeHostList(token string) bool {
	return strings.HasPrefix(token, "[") && strings.Contains(token, "]:")
}

// fingerprints computes the SHA256 (base64, unpadded) and MD5 (colon-hex)
// fingerprints of a raw public-key blob, formatted as ssh-keygen prints them.
func fingerprints(blob []byte) (sha, md string) {
	s := sha256.Sum256(blob)
	sha = "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])
	m := md5.Sum(blob) //nolint:gosec // SSH MD5 fingerprint format.
	parts := make([]string, len(m))
	for i, b := range m {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	md = "MD5:" + strings.Join(parts, ":")
	return sha, md
}

// inspectBlob parses the algorithm-specific body to derive the key size and,
// for ssh-rsa, the modulus hex, returning an interpretation note.
func inspectBlob(keyType string, blob []byte) (bits int, modHex, note string) {
	switch {
	case keyType == "ssh-rsa":
		// blob: string "ssh-rsa", mpint e, mpint n.
		_, rest, err := sshString(blob)
		if err != nil {
			return 0, "", "could not parse rsa blob"
		}
		_, rest, err = sshString(rest) // e
		if err != nil {
			return 0, "", "could not parse rsa exponent"
		}
		n, _, err := sshString(rest) // n
		if err != nil {
			return 0, "", "could not parse rsa modulus"
		}
		mod := new(big.Int).SetBytes(n)
		bits = mod.BitLen()
		modHex = mod.Text(16)
		note = "RSA modulus surfaced for roca_detect (CVE-2017-15361) screening."
		if bits < 2048 {
			note = fmt.Sprintf("weak: %d-bit RSA is below the 2048-bit minimum. ", bits) + note
		}
		return bits, modHex, note
	case keyType == "ssh-dss":
		// blob: string "ssh-dss", mpint p, q, g, y. Bits = bitlen(p).
		_, rest, err := sshString(blob)
		if err != nil {
			return 0, "", "could not parse dss blob"
		}
		p, _, err := sshString(rest)
		if err != nil {
			return 0, "", "could not parse dss prime"
		}
		bits = new(big.Int).SetBytes(p).BitLen()
		return bits, "", "DSA (ssh-dss) is deprecated and disabled by default in modern OpenSSH."
	case strings.Contains(keyType, "nistp256"):
		return 256, "", ecdsaNote(keyType)
	case strings.Contains(keyType, "nistp384"):
		return 384, "", ecdsaNote(keyType)
	case strings.Contains(keyType, "nistp521"):
		return 521, "", ecdsaNote(keyType)
	case strings.Contains(keyType, "ed25519"):
		if strings.HasPrefix(keyType, "sk-") {
			return 256, "", "FIDO/U2F hardware-backed (security key) Ed25519."
		}
		return 256, "", ""
	default:
		return 0, "", "unrecognised key type; fingerprint computed over the raw blob."
	}
}

func ecdsaNote(keyType string) string {
	if strings.HasPrefix(keyType, "sk-") {
		return "FIDO/U2F hardware-backed (security key) ECDSA."
	}
	return ""
}

// matchHashedHost tests candidate against a |1|salt|hash known_hosts entry:
// base64(HMAC-SHA1(key=salt, msg=candidate)) must equal the stored hash.
func matchHashedHost(token, candidate string) bool {
	parts := strings.Split(token, "|")
	// Format is |1|salt|hash → ["", "1", salt, hash].
	if len(parts) != 4 || parts[1] != "1" {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt) //nolint:gosec // known_hosts fixed format.
	mac.Write([]byte(candidate))
	return hmac.Equal(mac.Sum(nil), want)
}

// matchPlainHost tests candidate against a plaintext known_hosts host field: a
// comma-separated list of patterns, with '*'/'?' globs and [host]:port forms.
func matchPlainHost(token, candidate string) bool {
	for _, pat := range strings.Split(token, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		// Strip a [host]:port bracket form to its host for comparison.
		if strings.HasPrefix(pat, "[") {
			if i := strings.Index(pat, "]"); i > 0 {
				pat = pat[1:i]
			}
		}
		if globMatch(pat, candidate) {
			return true
		}
	}
	return false
}

// globMatch matches the OpenSSH host patterns '*' (any run) and '?' (one char).
func globMatch(pattern, s string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == s
	}
	return globRec(pattern, s)
}

func globRec(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			if len(p) == 1 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globRec(p[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if len(s) == 0 || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return len(s) == 0
}

// tryBlob base64-decodes a field and reads its embedded algorithm name; it
// reports the decoded blob, the algorithm, and whether the field was a
// well-formed key blob.
func tryBlob(field string) (blob []byte, algo string, ok bool) {
	if len(field) < 12 {
		return nil, "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(field)
	if err != nil {
		return nil, "", false
	}
	name, _, err := sshString(decoded)
	if err != nil {
		return nil, "", false
	}
	return decoded, string(name), true
}

// sshString consumes one uint32-length-prefixed field from b, returning it and
// the remaining bytes.
func sshString(b []byte) (field, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("truncated length prefix")
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, errors.New("field length exceeds buffer")
	}
	return b[4 : 4+n], b[4+n:], nil
}
