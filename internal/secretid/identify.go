// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secretid identifies a captured string as a known secret / credential
// type — the triage entry point for "I found this in loot, what is it?". It is
// the credential analogue of hash_identify: an operator who pulls an unknown
// token out of a repo, a config, a log, an env dump, or a memory capture pastes
// it here and learns the type (and, where the format carries a checksum or
// structure, whether it validates). It reuses the in-tree decoders for the
// formats that can be validated (AWS key, GitHub token, Azure SAS, BIP-39, JWT)
// and recognises a curated set of well-documented prefix formats for the rest.
// Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native orchestration. The structured formats are routed to the existing native
// decoders (internal/awskey, internal/githubtoken, internal/azuresas,
// internal/bip39, internal/jwtdecode); the prefix recognition is a lookup table
// of published vendor token prefixes. No new dependency.
//
// # Verifiable / no confidently-wrong output
//
// Identification is conservative and full-string: a result asserts the **format**
// (and, when a checksum/structure was checked, its **validity**), never that a
// credential is live. Validated formats carry their decoder's own
// reference-anchored verification; prefix-only formats are labelled
// `validated:false` (a format match, not a checksum). An unrecognised string is
// returned unmatched with a shape hint rather than guessed at.
package secretid

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/awskey"
	"github.com/xunholy/promptzero/internal/azuresas"
	"github.com/xunholy/promptzero/internal/bip39"
	"github.com/xunholy/promptzero/internal/discordtoken"
	"github.com/xunholy/promptzero/internal/githubtoken"
	"github.com/xunholy/promptzero/internal/jwtdecode"
	"github.com/xunholy/promptzero/internal/pypitoken"
)

// Result is the identification outcome.
type Result struct {
	// Matched is true when the input was recognised as a known credential format.
	Matched bool `json:"matched"`
	// Type is the human-readable credential type.
	Type string `json:"type,omitempty"`
	// Category groups the type (cloud-aws / cloud-azure / vcs / api-key /
	// crypto-wallet / token-jwt / pgp / ssh / x509).
	Category string `json:"category,omitempty"`
	// Validated is true when a checksum or structure was actually verified (not
	// merely a prefix match).
	Validated bool `json:"validated"`
	// Valid is the result of that verification (meaningful only when Validated).
	Valid bool `json:"valid,omitempty"`
	// Detail carries format-specific specifics (AWS account ID, checksum status,
	// JWT alg, SAS expiry, mnemonic word count, …).
	Detail string `json:"detail,omitempty"`
	// Note carries a caveat or, when unmatched, a shape hint.
	Note string `json:"note,omitempty"`
}

// Identify classifies a single captured credential string.
func Identify(s string) *Result {
	in := strings.TrimSpace(s)
	if in == "" {
		return &Result{Matched: false, Note: "empty input"}
	}

	// 1. PEM / ASCII-armor blocks (PGP, SSH, private keys, certificates).
	if strings.HasPrefix(in, "-----BEGIN ") {
		return identifyPEM(in)
	}

	// 2. AWS access key ID (20 chars, known prefix, Base32 body — checksum-free
	//    but the account-ID decode succeeds only for a real key shape).
	if len(in) == 20 {
		if r, err := awskey.Decode(in); err == nil {
			return &Result{
				Matched: true, Type: "AWS " + r.Description, Category: "cloud-aws",
				Validated: true, Valid: true,
				Detail: fmt.Sprintf("type %s, account %s", r.KeyType, r.AccountID),
			}
		}
	}

	// 3. GitHub / fine-grained token (CRC32 checksum on the classic types).
	if hasAnyPrefix(in, "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_") {
		if r, err := githubtoken.Decode(in); err == nil {
			res := &Result{
				Matched: true, Type: "GitHub " + r.Type, Category: "vcs",
				Validated: r.ChecksumChecked, Valid: r.ChecksumValid,
			}
			if r.ChecksumChecked {
				res.Detail = "checksum " + validWord(r.ChecksumValid)
			} else {
				res.Detail = "prefix-identified (checksum not validated)"
			}
			return res
		}
	}

	// 4. JSON Web Token (three base64url parts, header decodes to JSON).
	if looksLikeJWT(in) {
		if t, err := jwtdecode.Decode(in); err == nil {
			return &Result{
				Matched: true, Type: "JSON Web Token (JWT)", Category: "token-jwt",
				Validated: true, Valid: true,
				Detail: "alg=" + t.HeaderAlgorithm,
			}
		}
	}

	// 4b. Discord user/bot/MFA token (mfa.-prefixed, or first segment decodes to a
	//     user-ID snowflake — checked after JWT, whose first segment is JSON).
	if strings.HasPrefix(in, "mfa.") || strings.Count(in, ".") >= 1 {
		if d, err := discordtoken.Decode(in); err == nil {
			res := &Result{Matched: true, Type: d.Type, Category: "token-discord", Validated: false}
			if d.UserID != "" {
				res.Detail = fmt.Sprintf("user %s, account created %s", d.UserID, d.AccountCreatedUTC)
			}
			return res
		}
	}

	// 5. Azure Storage SAS token (a query string carrying sig= and sv=/sp=).
	if strings.Contains(in, "sig=") && (strings.Contains(in, "sv=") || strings.Contains(in, "sp=")) {
		if r, err := azuresas.Decode(in); err == nil {
			return &Result{
				Matched: true, Type: "Azure Storage " + r.Type, Category: "cloud-azure",
				Validated: false,
				Detail:    "expiry " + emptyDash(r.Expiry),
				Note:      "permissions and scope via azure_sas_decode; the HMAC signature is opaque",
			}
		}
	}

	// 5b. PyPI API token (pypi- + a macaroon whose caveats decode to a scope).
	if strings.HasPrefix(in, "pypi-") {
		if r, err := pypitoken.Decode(in); err == nil {
			return &Result{
				Matched: true, Type: "PyPI API token (macaroon)", Category: "api-key",
				Validated: r.WellFormed, Valid: r.WellFormed,
				Detail: "scope: " + r.Scope,
				Note:   "full caveat breakdown via pypi_token_decode; liveness needs a PyPI call",
			}
		}
	}

	// 6. Vendor prefix formats (no checksum to validate — a format match).
	if m := matchVendorPrefix(in); m != nil {
		return m
	}

	// 7. BIP-39 mnemonic / wallet seed phrase (SHA-256 checksum).
	if isWordList(in) {
		if r, err := bip39.Decode(in, ""); err == nil {
			return &Result{
				Matched: true, Type: "BIP-39 mnemonic (wallet seed phrase)", Category: "crypto-wallet",
				Validated: true, Valid: r.ChecksumValid,
				Detail: fmt.Sprintf("%d words, %d-bit entropy, checksum %s",
					r.WordCount, r.EntropyBits, validWord(r.ChecksumValid)),
			}
		}
	}

	return &Result{Matched: false, Note: shapeHint(in)}
}

// identifyPEM classifies a PEM / ASCII-armor block by its BEGIN line.
func identifyPEM(in string) *Result {
	head := in
	if i := strings.IndexByte(in, '\n'); i >= 0 {
		head = in[:i]
	}
	switch {
	case strings.HasPrefix(head, "-----BEGIN PGP"):
		return &Result{Matched: true, Type: "PGP / OpenPGP block (" + armorKind(head) + ")", Category: "pgp",
			Validated: false, Note: "decode with pgp_packet_decode"}
	case strings.Contains(head, "OPENSSH PRIVATE KEY"):
		return &Result{Matched: true, Type: "OpenSSH private key", Category: "ssh",
			Validated: false, Note: "triage with ssh_privkey_decode"}
	case strings.Contains(head, "PRIVATE KEY"):
		return &Result{Matched: true, Type: "PEM private key (" + armorKind(head) + ")", Category: "ssh",
			Validated: false, Note: "an unprotected private key is directly usable"}
	case strings.Contains(head, "CERTIFICATE"):
		return &Result{Matched: true, Type: "X.509 certificate (PEM)", Category: "x509",
			Validated: false, Note: "decode with x509_certificate_decode"}
	case strings.Contains(head, "PUBLIC KEY"):
		return &Result{Matched: true, Type: "PEM public key", Category: "x509", Validated: false}
	default:
		return &Result{Matched: true, Type: "PEM block (" + armorKind(head) + ")", Category: "pem", Validated: false}
	}
}

// armorKind extracts the label from a -----BEGIN X----- line.
func armorKind(head string) string {
	s := strings.TrimPrefix(head, "-----BEGIN ")
	s = strings.TrimSuffix(strings.TrimRight(s, "-"), "-----")
	return strings.TrimSpace(s)
}

// vendorPrefix maps a documented token prefix to its type. Order matters: more
// specific prefixes (sk-ant-) must precede their broader siblings (sk-).
var vendorPrefixes = []struct{ prefix, typ, category string }{
	{"xoxb-", "Slack bot token", "api-key"},
	{"xoxp-", "Slack user token", "api-key"},
	{"xoxa-", "Slack app token", "api-key"},
	{"xoxs-", "Slack session token", "api-key"},
	{"xoxr-", "Slack refresh token", "api-key"},
	{"xapp-", "Slack app-level token", "api-key"},
	{"glpat-", "GitLab personal access token", "vcs"},
	{"gldt-", "GitLab deploy token", "vcs"},
	{"glrt-", "GitLab runner token", "vcs"},
	{"npm_", "npm access token", "api-key"},
	{"pypi-", "PyPI API token (macaroon)", "api-key"},
	{"dop_v1_", "DigitalOcean personal access token", "cloud"},
	{"doo_v1_", "DigitalOcean OAuth token", "cloud"},
	{"shpat_", "Shopify access token", "api-key"},
	{"shpss_", "Shopify shared secret", "api-key"},
	{"shpca_", "Shopify custom-app token", "api-key"},
	{"sk-ant-", "Anthropic API key", "api-key"},
	{"sk-proj-", "OpenAI project API key", "api-key"},
	{"sk-", "OpenAI / LLM-provider API key (sk- prefix)", "api-key"},
	{"rk_live_", "Stripe restricted live key", "api-key"},
	{"rk_test_", "Stripe restricted test key", "api-key"},
	{"sk_live_", "Stripe secret live key", "api-key"},
	{"sk_test_", "Stripe secret test key", "api-key"},
	{"pk_live_", "Stripe publishable live key", "api-key"},
	{"pk_test_", "Stripe publishable test key", "api-key"},
	{"SG.", "SendGrid API key", "api-key"},
	{"AIza", "Google API key", "cloud"},
	{"ya29.", "Google OAuth access token", "cloud"},
	{"AccountKey=", "Azure Storage connection string (shared key)", "cloud-azure"},
}

// matchVendorPrefix returns a format-match result for a recognised vendor prefix.
func matchVendorPrefix(in string) *Result {
	for _, v := range vendorPrefixes {
		if strings.HasPrefix(in, v.prefix) {
			return &Result{
				Matched: true, Type: v.typ, Category: v.category,
				Validated: false, Detail: "matched the " + v.prefix + " prefix format (no checksum to validate)",
			}
		}
	}
	return nil
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// looksLikeJWT reports whether s has the three-dot base64url JWT shape.
func looksLikeJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, p := range parts {
		for _, c := range p {
			if !isBase64URLChar(c) {
				return false
			}
		}
	}
	return true
}

// isBase64URLChar reports whether c is a base64url character (or '=' padding).
func isBase64URLChar(c rune) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '='
}

// isWordList reports whether s is a space-separated list of a BIP-39-valid word
// count — the guard before attempting a (PBKDF2-bearing) mnemonic decode.
func isWordList(s string) bool {
	n := len(strings.Fields(s))
	return n == 12 || n == 15 || n == 18 || n == 21 || n == 24
}

// shapeHint describes an unrecognised string's shape without claiming a type.
func shapeHint(in string) string {
	switch {
	case isHex(in) && len(in) == 40:
		return "unrecognised — a 40-hex string (could be a SHA-1, a legacy GitHub token, or other digest; try hash_identify)"
	case isHex(in):
		return fmt.Sprintf("unrecognised — looks like %d hex characters", len(in))
	case isBase64(in):
		return "unrecognised — looks like base64 data"
	default:
		return "unrecognised — not a known credential format"
	}
}

func isHex(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

// isHexChar reports whether c is a hexadecimal digit.
func isHexChar(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isBase64(s string) bool {
	if len(s) < 8 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return true
	}
	_, err = base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

func validWord(ok bool) string {
	if ok {
		return "valid"
	}
	return "INVALID"
}

func emptyDash(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
