// Package gcpsakey decodes a Google Cloud service-account JSON key into the
// identity and blast radius it carries.
//
// A GCP service-account key is the JSON file `gcloud iam service-accounts keys
// create` emits — `{"type":"service_account","project_id":…,"client_email":…,
// "private_key":"-----BEGIN PRIVATE KEY-----…"}`. It is among the most damaging
// and most frequently-leaked cloud credentials: it is a long-lived, often
// highly-privileged identity committed to repos, baked into CI configs, and
// dropped in container images. When one turns up in loot the questions are
// *whose* identity it is, in *which* project, and whether the embedded key is a
// genuine, well-formed RSA key — all answerable offline, with no GCP call.
//
// This decoder surfaces the JSON identity fields (project, client_email,
// client_id, private_key_id), classifies the account (user-managed vs the
// default Compute Engine / App Engine SAs, which are broadly privileged by
// default), parses the embedded PKCS#8 RSA private key to confirm it is real and
// report its size + a SubjectPublicKeyInfo SHA-256 fingerprint, and runs the
// ROCA (CVE-2017-15361) weak-key test on the modulus (see internal/roca).
//
// No confidently-wrong output: it asserts the key's *structure and identity
// only* — never that the key is live or its IAM bindings (that needs a GCP API
// call). A private_key that fails to parse is reported as such, not asserted
// genuine; a JSON without the service_account shape is rejected.
//
// Wrap-vs-native: native — encoding/json + stdlib crypto/x509 PKCS#8 parsing +
// internal/roca; no new go.mod dependency. The key-file schema is Google's
// documented service-account key format.
package gcpsakey

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/roca"
)

// Result is the decoded service-account key.
type Result struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id,omitempty"`
	ClientEmail  string `json:"client_email,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	PrivateKeyID string `json:"private_key_id,omitempty"`
	TokenURI     string `json:"token_uri,omitempty"`

	// AccountKind classifies the identity by its client_email pattern:
	// "user-managed", "default-compute", "default-appengine", "gcp-managed", or
	// "unknown". The default Compute Engine / App Engine SAs carry the broadly
	// privileged Editor role by default, so a key for one is higher-impact.
	AccountKind string `json:"account_kind"`

	// PrivateKeyValid is true when the embedded private_key parsed to a real RSA
	// key — positive evidence the JSON is a genuine, well-formed SA key.
	PrivateKeyValid bool   `json:"private_key_valid"`
	KeyAlgorithm    string `json:"key_algorithm,omitempty"`
	KeyBits         int    `json:"key_bits,omitempty"`
	// PublicKeySHA256 is the SHA-256 of the SubjectPublicKeyInfo DER (a stable
	// identifier for matching/dedup; not a GCP-native value).
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
	// ROCAVulnerable is true when the RSA modulus carries the Infineon RSALib
	// fingerprint (CVE-2017-15361) — the key would be factorable.
	ROCAVulnerable bool `json:"roca_vulnerable"`

	Note string `json:"note"`
}

// saKeyFile mirrors the documented service-account key JSON schema.
type saKeyFile struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	TokenURI     string `json:"token_uri"`
}

// Decode parses a GCP service-account JSON key. It returns an error for input
// that is not JSON or not a service-account key; a key whose private_key fails
// to parse is returned with PrivateKeyValid=false rather than as an error, so
// the identity fields are still surfaced.
func Decode(input string) (*Result, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("gcpsakey: empty input")
	}
	var f saKeyFile
	if err := json.Unmarshal([]byte(input), &f); err != nil {
		return nil, fmt.Errorf("gcpsakey: not valid JSON: %w", err)
	}
	if f.Type != "service_account" {
		return nil, fmt.Errorf("gcpsakey: not a service-account key (type=%q, want %q)", f.Type, "service_account")
	}

	res := &Result{
		Type:         f.Type,
		ProjectID:    f.ProjectID,
		ClientEmail:  f.ClientEmail,
		ClientID:     f.ClientID,
		PrivateKeyID: f.PrivateKeyID,
		TokenURI:     f.TokenURI,
		AccountKind:  classifyEmail(f.ClientEmail),
		Note: "Structure and identity only — not checked against GCP (the key's IAM " +
			"bindings and whether it is still enabled need an API call).",
	}
	analyzeKey(res, f.PrivateKey)
	return res, nil
}

// analyzeKey parses the PKCS#8 private_key PEM and fills the key-derived fields.
// On any parse failure it leaves PrivateKeyValid false and records why.
func analyzeKey(res *Result, pemStr string) {
	if strings.TrimSpace(pemStr) == "" {
		res.Note = "no private_key field present; " + res.Note
		return
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		res.Note = "private_key is not valid PEM (redacted or malformed); " + res.Note
		return
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		res.Note = "private_key PEM did not parse as a PKCS#8 key; " + res.Note
		return
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		res.KeyAlgorithm = fmt.Sprintf("%T", key)
		res.Note = "private_key is not RSA (GCP SA keys are RSA); " + res.Note
		return
	}

	res.PrivateKeyValid = true
	res.KeyAlgorithm = "RSA"
	res.KeyBits = rsaKey.N.BitLen()
	if der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey); err == nil {
		sum := sha256.Sum256(der)
		res.PublicKeySHA256 = hex.EncodeToString(sum[:])
	}
	res.ROCAVulnerable = roca.HasFingerprint(rsaKey.N)
	if res.ROCAVulnerable {
		res.Note = "ROCA (CVE-2017-15361) weak key — factorable; rotate immediately. " + res.Note
	}
}

// classifyEmail maps a service-account email to its kind. The default Compute
// Engine and App Engine SAs are broadly privileged by default, so a key for one
// is higher impact than a typical user-managed SA.
func classifyEmail(email string) string {
	switch {
	case email == "":
		return "unknown"
	case strings.HasSuffix(email, "-compute@developer.gserviceaccount.com"):
		return "default-compute"
	case strings.HasSuffix(email, "@appspot.gserviceaccount.com"):
		return "default-appengine"
	case strings.HasSuffix(email, ".iam.gserviceaccount.com"):
		return "user-managed"
	case strings.HasSuffix(email, "@cloudservices.gserviceaccount.com"),
		strings.HasSuffix(email, ".gserviceaccount.com"):
		return "gcp-managed"
	default:
		return "unknown"
	}
}
