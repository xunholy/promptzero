// Package dockercfg decodes a Docker registry credential config into the
// registries it authenticates to and the credential each entry carries.
//
// Docker registry creds turn up constantly in loot: `~/.docker/config.json` on
// developer and CI hosts, the legacy `.dockercfg`, and — most consequentially —
// the Kubernetes `kubernetes.io/dockerconfigjson` image-pull secret, whose
// decoded payload is exactly this format. A registry credential with push
// access is a supply-chain primitive (publish a malicious image tag), so when
// one turns up the questions are which registries it reaches, what username it
// authenticates as, and whether the credential is embedded (usable as-is) or
// delegated to a credential helper (`credHelpers` / `credsStore`, which needs
// the operator's own login).
//
// No confidently-wrong output: this reports the registry, username, and
// credential *shape* — it does NOT emit the decoded password (presence is
// flagged, the secret is not echoed), never contacts a registry, and never
// asserts the credential is live. Input that is not a recognisable Docker
// config is rejected rather than guessed at.
//
// Wrap-vs-native: native — encoding/json + encoding/base64 over the documented
// Docker config schema (github.com/docker/cli config/configfile + types/auth);
// no new go.mod dependency.
package dockercfg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Registry is one registry credential entry.
type Registry struct {
	Registry string `json:"registry"`
	Username string `json:"username,omitempty"`
	// HasPassword is true when the auth field decoded to a user:password pair
	// (the password itself is never emitted).
	HasPassword bool `json:"has_password"`
	// IdentityToken is true when the entry carries an OAuth2 identity token
	// (a refresh token) rather than (or in addition to) a password.
	IdentityToken bool `json:"identity_token"`
	// CredHelper names a per-registry credential helper, if set (the credential
	// is stored externally, not in this file).
	CredHelper string `json:"cred_helper,omitempty"`
	// Malformed flags an auth field that was present but did not base64-decode
	// to a user:password pair.
	Malformed bool `json:"malformed,omitempty"`
}

// Result is the decoded Docker config.
type Result struct {
	// Format is "config.json" (modern) or "dockercfg-legacy".
	Format string `json:"format"`
	// CredsStore is the global credential helper, if set (external store).
	CredsStore string     `json:"creds_store,omitempty"`
	Registries []Registry `json:"registries"`
	// HasEmbeddedCredentials is true when any entry carries an in-file
	// credential (password or identity token), as opposed to only helpers.
	HasEmbeddedCredentials bool   `json:"has_embedded_credentials"`
	Note                   string `json:"note"`
}

// authEntry mirrors one registry's auth object.
type authEntry struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
	Email         string `json:"email"`
}

// modernConfig mirrors ~/.docker/config.json.
type modernConfig struct {
	Auths       map[string]authEntry `json:"auths"`
	CredsStore  string               `json:"credsStore"`
	CredHelpers map[string]string    `json:"credHelpers"`
}

// Decode parses a Docker registry config. It returns an error for input that is
// not JSON or not a recognisable Docker config.
func Decode(input string) (*Result, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("dockercfg: empty input")
	}

	// Modern config.json: an object with auths / credsStore / credHelpers.
	var mc modernConfig
	if err := json.Unmarshal([]byte(input), &mc); err == nil &&
		(mc.Auths != nil || mc.CredsStore != "" || mc.CredHelpers != nil) {
		return decodeModern(&mc), nil
	}

	// Legacy .dockercfg: a top-level map of registry -> auth entry.
	var legacy map[string]authEntry
	if err := json.Unmarshal([]byte(input), &legacy); err == nil && looksLikeLegacy(legacy) {
		return decodeLegacy(legacy), nil
	}

	return nil, fmt.Errorf("dockercfg: not a recognisable Docker config (no auths/credHelpers/credsStore and not a registry->auth map)")
}

// looksLikeLegacy reports whether a parsed top-level map looks like a legacy
// .dockercfg (at least one entry carrying an auth or identitytoken field),
// guarding against treating arbitrary JSON objects as a config.
func looksLikeLegacy(m map[string]authEntry) bool {
	if len(m) == 0 {
		return false
	}
	for _, e := range m {
		if e.Auth != "" || e.IdentityToken != "" || e.Username != "" {
			return true
		}
	}
	return false
}

// decodeModern builds the result from a modern config.json.
func decodeModern(mc *modernConfig) *Result {
	res := newResult("config.json")
	res.CredsStore = mc.CredsStore

	for reg, e := range mc.Auths {
		r := buildRegistry(reg, e)
		if h, ok := mc.CredHelpers[reg]; ok {
			r.CredHelper = h
		}
		appendRegistry(res, r)
	}
	// credHelpers entries without a matching auths entry are still registries
	// the host can authenticate to (via the helper).
	for reg, helper := range mc.CredHelpers {
		if _, inAuths := mc.Auths[reg]; inAuths {
			continue
		}
		appendRegistry(res, Registry{Registry: reg, CredHelper: helper})
	}
	return res
}

// decodeLegacy builds the result from a legacy .dockercfg map.
func decodeLegacy(m map[string]authEntry) *Result {
	res := newResult("dockercfg-legacy")
	for reg, e := range m {
		appendRegistry(res, buildRegistry(reg, e))
	}
	return res
}

// buildRegistry interprets a single auth entry without emitting the password.
func buildRegistry(reg string, e authEntry) Registry {
	r := Registry{Registry: reg, IdentityToken: e.IdentityToken != ""}
	// Explicit username/password fields take precedence when present.
	if e.Username != "" {
		r.Username = e.Username
	}
	if e.Password != "" {
		r.HasPassword = true
	}
	if e.Auth != "" {
		user, hasPass, ok := splitAuth(e.Auth)
		if !ok {
			r.Malformed = true
		} else {
			if r.Username == "" {
				r.Username = user
			}
			if hasPass {
				r.HasPassword = true
			}
		}
	}
	return r
}

// splitAuth base64-decodes a docker auth field and splits "user:password",
// reporting the username and whether a non-empty password was present. The
// password value itself is intentionally discarded.
func splitAuth(auth string) (user string, hasPassword bool, ok bool) {
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth))
	if err != nil {
		// Some configs use the raw-url alphabet / omit padding.
		dec, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(auth))
		if err != nil {
			return "", false, false
		}
	}
	s := string(dec)
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", false, false
	}
	return s[:i], len(s) > i+1, true
}

func newResult(format string) *Result {
	return &Result{
		Format:     format,
		Registries: make([]Registry, 0, 4),
		Note: "Registry, username, and credential shape only — the decoded password is NOT emitted, no " +
			"registry is contacted, and liveness is not asserted. credHelpers/credsStore are external stores.",
	}
}

// appendRegistry adds a registry and updates the embedded-credential summary.
func appendRegistry(res *Result, r Registry) {
	if r.HasPassword || r.IdentityToken {
		res.HasEmbeddedCredentials = true
	}
	res.Registries = append(res.Registries, r)
}
