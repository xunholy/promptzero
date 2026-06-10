package gcpsakey

import (
	"encoding/json"
	"strings"
	"testing"
)

// saPrivKeyPEM is a throwaway RSA-2048 key generated with
// `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`. Its
// SubjectPublicKeyInfo SHA-256 was computed independently with
// `openssl pkey -pubout -outform DER | openssl dgst -sha256` and pinned below,
// so the test anchors the fingerprint to an external tool, not a round-trip.
const saPrivKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBgfae5ftv8lyW
hbc7O++WJ602StXXNuiGHJkD3oDO43sbSoWmpkqRiNaln4nuqvy2qBYUJvGVj/OG
HlFh0TZ3IoZHSaVFgtlmjGVwNpDAXEvfHRwNusdmQ2JX5sEdRoKBfmLLyGg6K0lh
ICIvCzRg+3AgYPIRYlNRPKHQPpCHO/0lRsdd0mo4wKln//f0WKinrVsuw03TRP7+
XtzziHbC0lUoFKexMaaWjNJzSc0PAqTrdP3LJO8QpWi5dGLItiKE04LqrQIQkbae
yd5I2UTWqn4vDo6EsYJn/h4+XoXIesNKhZLzIrtxsU5NtFqTwNlhfIVWRcOGQ35j
vrvwQNarAgMBAAECggEAKdKhj2lMhT8AJOZEmnBTUYREyxG0kx3Cds3ygmQSOeTv
pA/gwAp73mWRYt2O7b8V/JJqpzNdjoI803V1CGuz1l7nX7v6lQH5Y9EfUXfxpCmu
mkvL1unSE/enZzEv9thY94zt5HZtlHjrlKrhyIIm8XkWnGDnoLs8H7g3ju8exKNh
1j+q0GoOo4/GbY26SMI/ezeIh3aO9xi3wEqBdcHMIqfukIJZEYpHjY2mdDhtGKdH
MR7X7UKf2Q9o+nY1saChk2GUKJ2tk4qpNL1fG+x2ZRfueN0IvjaI/cYQ7SnsFZjX
SLjot/o/4vB12wxlvKqE2jiNfETT4EHeEcyjrWS1bQKBgQDgNrntn4Z4cPtqoKxc
gJpuV+GIMT3iQwvFxLmRCHgIWeDVvJLGrWerH3mvAU0q6wi6tp1cdVQJqqxu2su6
iK7TLKAdwYiYRo6T+4m/Ei2mDuVtepqEl8SdshyPgEDf8+XsR24YKKMwHpus8NCc
h2QrvPH1HHPMoBkG4rXJw5QqNQKBgQDc8NYeaVz+5kMEk5Rr1D7C2PRgV5Hv8Ffl
ko/bZddCGEyAiqPo4PSSCYmb8VDXJfLQmSq2ankREbpeiBfVKAMhnmUWTZuxosCs
1A5gtL+xqC5CkF6lpBpRLA/LbcYBb1FY2+MaqTCJ/iR7NbhX1VL0WbODjPYCVoYF
QBWm6E4ZXwKBgEGn5OQvfZoRQ54itLZVtmMvesx91uhFx9G+3LQarcOMRilwke55
4syaZ/CWSfmSX7kFNqlXdidqghnoGhZiZgdSnwR3or8skh3FX73C3fktjYN0joDb
TGj9Oh3Paa/q5N4+wH90juzNWbrXvc7IWs3wA05KaaJ3Ez0P8DnH+sAtAoGBAMec
ZzbupnA9BMt7shqBlXpgnNj2BQmsMR1efs4Pgp1aarOvjkr2AsB2EXdsXEclJ+1C
lI5eP6cmRyTk+/M+xSV4f4fY8hNZIY6Dv8GrS41sju7glEI+svAnSNXYBY6CThJk
BxitRwdFLxyJ+lSQjPPqnv75OcH+/fJ8ZZN4SictAoGBANz+jxeBUMpyTSA57vAM
M+yLCEVdaHTUfKiHB7AC6bZsaXcSUy2ADPXcgYEDNTF9B8HLBW+ZKls/HY/xsPdV
tjHh1iIFsaEP8qBK4SxiLBjFKr6Sx/FeD4Xv7Qvdl/pUa7ttPe2hMpMdiDB0b6he
IIGtw4YuMD1q1CyUhMOJ7CfL
-----END PRIVATE KEY-----
`

const wantPubSHA256 = "4b141fa8e1dab0a7a7eeda02f674bcfa570ec1e41da6eec8a9a571d6a4ad97e3"

// buildSAJSON marshals a service-account key file, letting encoding/json escape
// the PEM newlines exactly as a real key file does.
func buildSAJSON(t *testing.T, email, pem string) string {
	t.Helper()
	m := map[string]string{
		"type":           "service_account",
		"project_id":     "my-project-123",
		"private_key_id": "abcdef1234567890abcdef1234567890abcdef12",
		"private_key":    pem,
		"client_email":   email,
		"client_id":      "123456789012345678901",
		"token_uri":      "https://oauth2.googleapis.com/token",
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestDecode_UserManaged(t *testing.T) {
	in := buildSAJSON(t, "deploy@my-project-123.iam.gserviceaccount.com", saPrivKeyPEM)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProjectID != "my-project-123" {
		t.Errorf("ProjectID = %q", r.ProjectID)
	}
	if r.ClientEmail != "deploy@my-project-123.iam.gserviceaccount.com" {
		t.Errorf("ClientEmail = %q", r.ClientEmail)
	}
	if r.AccountKind != "user-managed" {
		t.Errorf("AccountKind = %q, want user-managed", r.AccountKind)
	}
	if !r.PrivateKeyValid || r.KeyAlgorithm != "RSA" || r.KeyBits != 2048 {
		t.Errorf("key: valid=%v alg=%q bits=%d, want true/RSA/2048", r.PrivateKeyValid, r.KeyAlgorithm, r.KeyBits)
	}
	if r.PublicKeySHA256 != wantPubSHA256 {
		t.Errorf("PublicKeySHA256 = %q, want %q", r.PublicKeySHA256, wantPubSHA256)
	}
	if r.ROCAVulnerable {
		t.Error("a normal openssl key must not be ROCA-flagged")
	}
}

func TestDecode_DefaultComputeSA(t *testing.T) {
	in := buildSAJSON(t, "123456789012-compute@developer.gserviceaccount.com", saPrivKeyPEM)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AccountKind != "default-compute" {
		t.Errorf("AccountKind = %q, want default-compute", r.AccountKind)
	}
}

func TestDecode_DefaultAppEngineSA(t *testing.T) {
	in := buildSAJSON(t, "my-project-123@appspot.gserviceaccount.com", saPrivKeyPEM)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AccountKind != "default-appengine" {
		t.Errorf("AccountKind = %q, want default-appengine", r.AccountKind)
	}
}

// A redacted / malformed private_key must downgrade gracefully — identity
// fields still surface, PrivateKeyValid is false, never asserted genuine.
func TestDecode_RedactedKey(t *testing.T) {
	in := buildSAJSON(t, "x@my-project-123.iam.gserviceaccount.com", "-----BEGIN PRIVATE KEY-----\nREDACTED\n-----END PRIVATE KEY-----\n")
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PrivateKeyValid {
		t.Error("redacted key must not be PrivateKeyValid")
	}
	if r.ProjectID != "my-project-123" {
		t.Errorf("identity should still surface, got ProjectID=%q", r.ProjectID)
	}
	if !strings.Contains(r.Note, "private_key") {
		t.Errorf("Note should explain the key problem: %q", r.Note)
	}
}

func TestDecode_Errors(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"not json":       "ASIAY34FZKBOKMUTVV7A",
		"wrong type":     `{"type":"authorized_user","client_id":"x"}`,
		"json but empty": `{}`,
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(buildSAJSONForFuzz())
	f.Add(`{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"}`)
	f.Add(`{}`)
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}

func buildSAJSONForFuzz() string {
	m := map[string]string{"type": "service_account", "project_id": "p", "private_key": saPrivKeyPEM, "client_email": "a@p.iam.gserviceaccount.com"}
	b, _ := json.Marshal(m)
	return string(b)
}
