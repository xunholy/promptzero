// htpasswd_decode.go — host-side Apache/nginx htpasswd classifier Spec,
// delegating to internal/htpasswd.
//
// Wrap-vs-native: native — a line + hash-prefix classifier, stdlib only, no new
// go.mod dep. Identifies each entry's hash scheme + hashcat mode + strength
// without cracking. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/htpasswd"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(htpasswdDecodeSpec)
}

var htpasswdDecodeSpec = Spec{
	Name: "htpasswd_decode",
	Description: "Classify the password hashes in an **Apache / nginx `htpasswd`** basic-auth file. An htpasswd file " +
		"is a list of `username:hash` lines, and each hash carries a **self-identifying prefix** that names its " +
		"scheme: **bcrypt** (`$2a/$2b/$2x/$2y$`), the **Apache iterated MD5** (`$apr1$`), the **crypt(3)** family " +
		"(`$1$` MD5 / `$5$` SHA-256 / `$6$` SHA-512 / `$7$`/`$y$` yescrypt), the **LDAP base64 digests** " +
		"(`{SHA}`, `{SSHA}`), the traditional **13-char DES crypt**, and unhashed **plaintext** (htpasswd `-p`). " +
		"After an operator recovers such a file the question is *which of these are weak / crackable, and with " +
		"what hashcat mode?* — this answers it. For each entry it surfaces the **username**, the **scheme**, the " +
		"matching **hashcat `-m` mode**, a **strength tier** (strong / weak / very weak / critical), and a note; " +
		"the summary lists the weak entries and **flags any plaintext**.\n\n" +
		"**No confidently-wrong output**: a scheme is named only from its unambiguous prefix (or, for DES crypt, " +
		"the exact 13-char crypt-alphabet shape); an unrecognised field is surfaced as `plaintext / unknown` with " +
		"a note, never guessed; the password is **never cracked**, only classified. No network, no device, " +
		"transmits nothing — Low risk. Pairs with the hashcat-mode tooling.\n\n" +
		"Provide the htpasswd file contents as text. Source: docs/catalog/gap-analysis.md (credential triage). " +
		"Wrap-vs-native: native — a line + prefix classifier, stdlib only, no new go.mod dep; anchored to real " +
		"openssl / bcrypt / hashcat-example vectors.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"htpasswd":{"type":"string","description":"The htpasswd file contents (one username:hash line per entry)."}
		},
		"required":["htpasswd"]
	}`),
	Required:  []string{"htpasswd"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   htpasswdDecodeHandler,
}

func htpasswdDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := str(p, "htpasswd")
	if strings.TrimSpace(in) == "" {
		return "", fmt.Errorf("htpasswd_decode: 'htpasswd' is required")
	}
	res, err := htpasswd.Decode([]byte(in))
	if err != nil {
		return "", fmt.Errorf("htpasswd_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
