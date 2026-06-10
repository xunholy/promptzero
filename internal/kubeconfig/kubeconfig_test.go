package kubeconfig

import (
	"testing"
)

// A realistic multi-cluster kubeconfig: one cluster with an embedded CA, one
// with TLS verification disabled; an admin with an embedded client key, a CI
// user with a bearer token, and a GKE user deferring to an exec plugin.
const sample = `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster:
    server: https://10.0.0.1:6443
    certificate-authority-data: QkFTRTY0Q0E=
- name: staging
  cluster:
    server: https://staging.example.com:6443
    insecure-skip-tls-verify: true
users:
- name: admin
  user:
    client-certificate-data: QkFTRTY0Q0VSVA==
    client-key-data: QkFTRTY0S0VZ
- name: ci
  user:
    token: deadbeef.bearer.token
- name: gke
  user:
    exec:
      command: gke-gcloud-auth-plugin
contexts:
- name: prod
  context:
    cluster: prod
    user: admin
    namespace: kube-system
- name: stg
  context:
    cluster: staging
    user: ci
`

func TestDecode_Sample(t *testing.T) {
	r, err := Decode(sample)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CurrentContext != "prod" {
		t.Errorf("CurrentContext = %q", r.CurrentContext)
	}
	if len(r.Clusters) != 2 || len(r.Users) != 3 || len(r.Contexts) != 2 {
		t.Fatalf("counts: clusters=%d users=%d contexts=%d", len(r.Clusters), len(r.Users), len(r.Contexts))
	}

	// staging has TLS verification disabled.
	if len(r.InsecureClusters) != 1 || r.InsecureClusters[0] != "staging" {
		t.Errorf("InsecureClusters = %v, want [staging]", r.InsecureClusters)
	}
	prod := r.Clusters[0]
	if prod.Name != "prod" || prod.Server != "https://10.0.0.1:6443" || !prod.HasCA || prod.InsecureSkipTLSVerify {
		t.Errorf("prod cluster = %+v", prod)
	}

	// admin: embedded client key → directly usable.
	admin := r.Users[0]
	if admin.Name != "admin" || !admin.EmbeddedCredential {
		t.Errorf("admin = %+v, want embedded credential", admin)
	}
	if !hasMethod(admin, "client-certificate") || !hasMethod(admin, "client-key") {
		t.Errorf("admin methods = %v", admin.AuthMethods)
	}
	// ci: bearer token → embedded.
	ci := r.Users[1]
	if !ci.EmbeddedCredential || !hasMethod(ci, "token") {
		t.Errorf("ci = %+v", ci)
	}
	// gke: exec plugin → NOT embedded (defers to operator's own cloud login).
	gke := r.Users[2]
	if gke.EmbeddedCredential {
		t.Errorf("gke must not be embedded: %+v", gke)
	}
	if !hasMethod(gke, "exec:gke-gcloud-auth-plugin") {
		t.Errorf("gke methods = %v", gke.AuthMethods)
	}

	if !r.HasEmbeddedCredentials {
		t.Error("HasEmbeddedCredentials should be true")
	}
	// current context flagged.
	if !r.Contexts[0].Current || r.Contexts[0].Namespace != "kube-system" || r.Contexts[1].Current {
		t.Errorf("contexts = %+v", r.Contexts)
	}
}

// An exec/auth-provider-only kubeconfig (the gcloud/aws pattern) carries no
// directly-usable credential.
func TestDecode_NoEmbeddedCredential(t *testing.T) {
	const cfg = `apiVersion: v1
kind: Config
current-context: c
clusters:
- name: c
  cluster:
    server: https://api:6443
    certificate-authority-data: Q0E=
users:
- name: u
  user:
    auth-provider:
      name: oidc
contexts:
- name: c
  context:
    cluster: c
    user: u
`
	r, err := Decode(cfg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.HasEmbeddedCredentials {
		t.Error("auth-provider-only kubeconfig must not report embedded credentials")
	}
	if !hasMethod(r.Users[0], "auth-provider:oidc") {
		t.Errorf("methods = %v", r.Users[0].AuthMethods)
	}
}

func TestDecode_Errors(t *testing.T) {
	cases := map[string]string{
		"empty":      "",
		"not yaml":   "\tthis: : : not yaml",
		"wrong kind": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n",
		"no kind":    "clusters: []\nusers: []\n",
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(sample)
	f.Add("kind: Config\n")
	f.Add("")
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}

func hasMethod(u User, m string) bool {
	for _, a := range u.AuthMethods {
		if a == m {
			return true
		}
	}
	return false
}
