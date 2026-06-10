// Package kubeconfig decodes a Kubernetes kubeconfig into the attack surface it
// exposes: which API servers it points at, the TLS-verification posture of
// each, and what kind of credential each user entry carries.
//
// A kubeconfig is one of the highest-value artifacts in a cluster pentest or
// incident — it bundles the API endpoint(s) and, frequently, a directly-usable
// credential (an embedded client key, a bearer token, or a basic-auth
// password). When one turns up in loot the questions are which clusters it
// reaches, whether any of them have certificate verification disabled
// (`insecure-skip-tls-verify`, a MITM foothold), and whether it carries a
// credential that works without a separate auth step (embedded key/token/
// password) vs. one that defers to an external helper (an `exec` plugin or
// `auth-provider`, which needs the operator's own cloud login).
//
// No confidently-wrong output: this reports the kubeconfig's *structure and
// credential shape only* — it does not contact any API server, never asserts a
// credential is live or what RBAC it grants, and does not emit the secret
// material itself (it flags presence, not values). Input that is not a
// `kind: Config` document is rejected rather than guessed at.
//
// Wrap-vs-native: native — gopkg.in/yaml.v3 (already a direct dependency) over
// the documented kubeconfig (clientcmd `api.v1.Config`) schema; no new go.mod
// dependency.
package kubeconfig

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Cluster is one cluster entry: its API server and TLS posture.
type Cluster struct {
	Name                  string `json:"name"`
	Server                string `json:"server,omitempty"`
	InsecureSkipTLSVerify bool   `json:"insecure_skip_tls_verify"`
	HasCA                 bool   `json:"has_ca"`
}

// User is one user entry, reduced to the credential kinds it carries (never the
// secret values). EmbeddedCredential is true when the entry alone is usable
// without an external auth step (client key / token / password), as opposed to
// an exec plugin or auth-provider that defers to the operator's own login.
type User struct {
	Name               string   `json:"name"`
	AuthMethods        []string `json:"auth_methods"`
	EmbeddedCredential bool     `json:"embedded_credential"`
}

// Context binds a cluster + user (+ namespace); Current marks the active one.
type Context struct {
	Name      string `json:"name"`
	Cluster   string `json:"cluster,omitempty"`
	User      string `json:"user,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Current   bool   `json:"current"`
}

// Result is the decoded kubeconfig.
type Result struct {
	CurrentContext string    `json:"current_context,omitempty"`
	Clusters       []Cluster `json:"clusters"`
	Users          []User    `json:"users"`
	Contexts       []Context `json:"contexts"`
	// InsecureClusters lists cluster names with certificate verification
	// disabled — a MITM foothold and a notable finding.
	InsecureClusters []string `json:"insecure_clusters,omitempty"`
	// HasEmbeddedCredentials is true when any user carries a directly-usable
	// credential (embedded key / token / password).
	HasEmbeddedCredentials bool   `json:"has_embedded_credentials"`
	Note                   string `json:"note"`
}

// raw mirrors the kubeconfig YAML schema (clientcmd api.v1.Config).
type raw struct {
	APIVersion     string `yaml:"apiVersion"`
	Kind           string `yaml:"kind"`
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificate     string `yaml:"client-certificate"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKey             string `yaml:"client-key"`
			ClientKeyData         string `yaml:"client-key-data"`
			Token                 string `yaml:"token"`
			TokenFile             string `yaml:"tokenFile"`
			Username              string `yaml:"username"`
			Password              string `yaml:"password"`
			Exec                  *struct {
				Command string `yaml:"command"`
			} `yaml:"exec"`
			AuthProvider *struct {
				Name string `yaml:"name"`
			} `yaml:"auth-provider"`
		} `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

// Decode parses a kubeconfig document. It returns an error for input that is
// not YAML or not a kubeconfig (`kind: Config`).
func Decode(input string) (*Result, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("kubeconfig: empty input")
	}
	var r raw
	if err := yaml.Unmarshal([]byte(input), &r); err != nil {
		return nil, fmt.Errorf("kubeconfig: not valid YAML: %w", err)
	}
	// Guard against confidently-wrong output: a kubeconfig declares kind Config.
	// (apiVersion alone is too generic — many k8s manifests use v1.)
	if !strings.EqualFold(r.Kind, "Config") {
		return nil, fmt.Errorf("kubeconfig: not a kubeconfig (kind=%q, want %q)", r.Kind, "Config")
	}

	res := &Result{
		CurrentContext: r.CurrentContext,
		Clusters:       make([]Cluster, 0, len(r.Clusters)),
		Users:          make([]User, 0, len(r.Users)),
		Contexts:       make([]Context, 0, len(r.Contexts)),
		Note: "Structure and credential shape only — no API server is contacted; a credential's " +
			"liveness and RBAC need a cluster call, and secret values are flagged, not emitted.",
	}

	for _, c := range r.Clusters {
		cl := Cluster{
			Name:                  c.Name,
			Server:                c.Cluster.Server,
			InsecureSkipTLSVerify: c.Cluster.InsecureSkipTLSVerify,
			HasCA:                 c.Cluster.CertificateAuthority != "" || c.Cluster.CertificateAuthorityData != "",
		}
		res.Clusters = append(res.Clusters, cl)
		if cl.InsecureSkipTLSVerify {
			res.InsecureClusters = append(res.InsecureClusters, cl.Name)
		}
	}

	for _, u := range r.Users {
		usr := User{Name: u.Name}
		uu := u.User
		if uu.ClientCertificate != "" || uu.ClientCertificateData != "" {
			usr.AuthMethods = append(usr.AuthMethods, "client-certificate")
		}
		if uu.ClientKey != "" || uu.ClientKeyData != "" {
			usr.AuthMethods = append(usr.AuthMethods, "client-key")
			if uu.ClientKeyData != "" {
				usr.EmbeddedCredential = true
			}
		}
		if uu.Token != "" {
			usr.AuthMethods = append(usr.AuthMethods, "token")
			usr.EmbeddedCredential = true
		}
		if uu.TokenFile != "" {
			usr.AuthMethods = append(usr.AuthMethods, "token-file")
		}
		if uu.Username != "" || uu.Password != "" {
			usr.AuthMethods = append(usr.AuthMethods, "basic-auth")
			if uu.Password != "" {
				usr.EmbeddedCredential = true
			}
		}
		if uu.Exec != nil {
			usr.AuthMethods = append(usr.AuthMethods, "exec:"+uu.Exec.Command)
		}
		if uu.AuthProvider != nil {
			usr.AuthMethods = append(usr.AuthMethods, "auth-provider:"+uu.AuthProvider.Name)
		}
		if usr.EmbeddedCredential {
			res.HasEmbeddedCredentials = true
		}
		res.Users = append(res.Users, usr)
	}

	for _, c := range r.Contexts {
		res.Contexts = append(res.Contexts, Context{
			Name:      c.Name,
			Cluster:   c.Context.Cluster,
			User:      c.Context.User,
			Namespace: c.Context.Namespace,
			Current:   c.Name == r.CurrentContext && r.CurrentContext != "",
		})
	}

	return res, nil
}
