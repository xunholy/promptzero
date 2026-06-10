package dockercfg

import (
	"testing"
)

// base64("user:pass") = dXNlcjpwYXNz ; base64("alice:s3cr3t!") = YWxpY2U6czNjcjN0IQ==
const modernCfg = `{
  "auths": {
    "registry.example.com": { "auth": "dXNlcjpwYXNz", "email": "u@example.com" },
    "https://index.docker.io/v1/": { "auth": "YWxpY2U6czNjcjN0IQ==" },
    "ghcr.io": { "identitytoken": "ghs_sometoken" }
  },
  "credHelpers": { "gcr.io": "gcloud" },
  "credsStore": "desktop"
}`

func find(t *testing.T, rs []Registry, reg string) Registry {
	t.Helper()
	for _, r := range rs {
		if r.Registry == reg {
			return r
		}
	}
	t.Fatalf("registry %q not found in %+v", reg, rs)
	return Registry{}
}

func TestDecode_Modern(t *testing.T) {
	r, err := Decode(modernCfg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "config.json" {
		t.Errorf("Format = %q", r.Format)
	}
	if r.CredsStore != "desktop" {
		t.Errorf("CredsStore = %q", r.CredsStore)
	}
	if !r.HasEmbeddedCredentials {
		t.Error("HasEmbeddedCredentials should be true")
	}

	ex := find(t, r.Registries, "registry.example.com")
	if ex.Username != "user" || !ex.HasPassword || ex.Malformed {
		t.Errorf("example.com = %+v, want user/hasPassword", ex)
	}
	dh := find(t, r.Registries, "https://index.docker.io/v1/")
	if dh.Username != "alice" || !dh.HasPassword {
		t.Errorf("dockerhub = %+v", dh)
	}
	gh := find(t, r.Registries, "ghcr.io")
	if !gh.IdentityToken || gh.HasPassword {
		t.Errorf("ghcr = %+v, want identity token, no password", gh)
	}
	// gcr.io comes only from credHelpers → external, no embedded credential.
	gcr := find(t, r.Registries, "gcr.io")
	if gcr.CredHelper != "gcloud" || gcr.HasPassword {
		t.Errorf("gcr = %+v, want credHelper gcloud", gcr)
	}
}

func TestDecode_Legacy(t *testing.T) {
	const legacy = `{"quay.io": {"auth": "dXNlcjpwYXNz", "email": "x@y.z"}}`
	r, err := Decode(legacy)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "dockercfg-legacy" {
		t.Errorf("Format = %q, want dockercfg-legacy", r.Format)
	}
	q := find(t, r.Registries, "quay.io")
	if q.Username != "user" || !q.HasPassword {
		t.Errorf("quay = %+v", q)
	}
}

// A creds-store-only config (Docker Desktop default) has no embedded credential.
func TestDecode_CredsStoreOnly(t *testing.T) {
	r, err := Decode(`{"auths":{},"credsStore":"desktop"}`)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.HasEmbeddedCredentials {
		t.Error("creds-store-only config must not report embedded credentials")
	}
}

// A malformed auth field is flagged, not silently treated as a credential.
func TestDecode_MalformedAuth(t *testing.T) {
	r, err := Decode(`{"auths":{"r.io":{"auth":"bm9jb2xvbg=="}}}`) // base64("nocolon")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	reg := find(t, r.Registries, "r.io")
	if !reg.Malformed || reg.HasPassword {
		t.Errorf("r.io = %+v, want malformed/no-password", reg)
	}
	if r.HasEmbeddedCredentials {
		t.Error("a malformed auth must not count as an embedded credential")
	}
}

func TestDecode_Errors(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"not json":       "ASIAY34FZKBOKMUTVV7A",
		"empty object":   `{}`,
		"unrelated json": `{"apiVersion":"v1","kind":"Pod"}`,
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(modernCfg)
	f.Add(`{"r":{"auth":"x"}}`)
	f.Add(`{}`)
	f.Add("")
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}
