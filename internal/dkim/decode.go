// Package dkim decodes a DKIM public-key DNS record (the
// `<selector>._domainkey.<domain>` TXT record, RFC 6376 §3.6.1, with Ed25519
// keys per RFC 8463) into a structured, forensic view.
//
// A DKIM record is the public half of an email-signing key, and it is real
// pentest / IR / anti-spoofing loot: the `p=` tag carries the signing key, so
// its **algorithm and size** are directly readable — and a short RSA key is a
// classic, exploitable finding (a 512/768-bit DKIM key can be factored and the
// domain's mail forged, the well-documented 2012 mass-disclosure class). This
// decoder extracts the key, reports its size, flags weak keys against the
// RFC 8301 minimum, and surfaces the RSA modulus so the key chains straight
// into roca_detect (a ROCA-vulnerable DKIM key is likewise forgeable).
//
// Wrap-vs-native: native — tag=value parsing + base64 + stdlib crypto/x509 to
// read the SubjectPublicKeyInfo. No new go.mod dependency. The key-size and
// modulus extraction are pinned against openssl-generated records and the
// RFC 8463 Ed25519 test vector.
package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Result is the decoded DKIM record.
type Result struct {
	// Version is the v= tag (should be "DKIM1" when present).
	Version string `json:"version,omitempty"`
	// KeyType is the k= tag: "rsa" (default) or "ed25519".
	KeyType string `json:"key_type"`
	// KeyBits is the RSA modulus bit length, or 256 for Ed25519.
	KeyBits int `json:"key_bits,omitempty"`
	// ModulusHex is the RSA modulus (hex) — surfaced for roca_detect chaining.
	ModulusHex string `json:"modulus_hex,omitempty"`
	// HashAlgs is the h= acceptable-hash list (e.g. ["sha256"]).
	HashAlgs []string `json:"hash_algs,omitempty"`
	// ServiceTypes is the s= service-type list (default ["*"]).
	ServiceTypes []string `json:"service_types,omitempty"`
	// Flags is the raw t= flag list.
	Flags []string `json:"flags,omitempty"`
	// Testing is t=y (the domain is testing DKIM; verifiers must not treat
	// signed/unsigned differently).
	Testing bool `json:"testing,omitempty"`
	// StrictDomain is t=s (no subdomain wildcarding of the signing domain).
	StrictDomain bool `json:"strict_domain,omitempty"`
	// Notes is the n= human-readable note.
	Notes string `json:"notes,omitempty"`
	// Revoked is true when p= is empty (the key has been revoked).
	Revoked bool `json:"revoked,omitempty"`
	// Warnings carries objective, RFC-anchored observations (weak key, etc.).
	Warnings []string `json:"warnings,omitempty"`
	// Note carries interpretation guidance.
	Note string `json:"note,omitempty"`
}

// Decode parses a DKIM public-key TXT record.
func Decode(record string) (*Result, error) {
	s := strings.TrimSpace(record)
	if s == "" {
		return nil, errors.New("empty record")
	}
	tags := parseTags(s)
	if _, ok := tags["p"]; !ok {
		return nil, errors.New("not a DKIM key record: no p= tag")
	}

	res := &Result{
		Version: tags["v"],
		KeyType: strings.ToLower(orDefault(tags["k"], "rsa")),
	}
	if res.Version != "" && res.Version != "DKIM1" {
		res.Warnings = append(res.Warnings, fmt.Sprintf("v= is %q, expected DKIM1", res.Version))
	}
	if h := tags["h"]; h != "" {
		res.HashAlgs = splitList(h)
	}
	res.ServiceTypes = splitList(orDefault(tags["s"], "*"))
	if t := tags["t"]; t != "" {
		res.Flags = splitList(t)
		for _, f := range res.Flags {
			switch f {
			case "y":
				res.Testing = true
			case "s":
				res.StrictDomain = true
			}
		}
	}
	res.Notes = tags["n"]

	pVal := stripWhitespace(tags["p"])
	if pVal == "" {
		res.Revoked = true
		res.Note = "DKIM key REVOKED (empty p=): the domain has withdrawn this selector's key."
		return res, nil
	}
	keyDER, err := base64.StdEncoding.DecodeString(pVal)
	if err != nil {
		return nil, fmt.Errorf("p= is not valid base64: %w", err)
	}

	switch res.KeyType {
	case "rsa":
		decodeRSA(keyDER, res)
	case "ed25519":
		if len(keyDER) == 32 {
			res.KeyBits = 256
		} else {
			res.Warnings = append(res.Warnings, fmt.Sprintf("ed25519 key is %d bytes, expected 32", len(keyDER)))
		}
	default:
		res.Warnings = append(res.Warnings, fmt.Sprintf("unrecognised key type %q; key surfaced but not parsed", res.KeyType))
	}

	if res.Note == "" {
		res.Note = "DKIM public-key record. Key size is read from the published key; a weak RSA key is " +
			"forgeable (factor the modulus → sign as the domain). For RSA, modulus_hex feeds roca_detect."
	}
	return res, nil
}

// decodeRSA parses the RSA public key (SPKI, falling back to PKCS#1), recording
// the size + modulus and flagging weak keys against RFC 8301.
func decodeRSA(der []byte, res *Result) {
	var pub *rsa.PublicKey
	if k, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rk, ok := k.(*rsa.PublicKey); ok {
			pub = rk
		}
	}
	if pub == nil {
		if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
			pub = rk
		}
	}
	if pub == nil {
		res.Warnings = append(res.Warnings, "p= did not parse as an RSA public key (SPKI or PKCS#1)")
		return
	}
	res.KeyBits = pub.N.BitLen()
	res.ModulusHex = hex.EncodeToString(pub.N.Bytes())
	switch {
	case res.KeyBits < 1024:
		res.Warnings = append(res.Warnings, fmt.Sprintf("WEAK: %d-bit RSA is below the RFC 8301 minimum (1024) — practically factorable, the domain's mail is forgeable", res.KeyBits))
	case res.KeyBits < 2048:
		res.Warnings = append(res.Warnings, fmt.Sprintf("advisory: %d-bit RSA meets the RFC 8301 minimum but 2048-bit is recommended", res.KeyBits))
	}
}

// parseTags splits a DKIM record into its tag=value map. Values may contain '='
// (base64 padding), so only the first '=' separates tag from value.
func parseTags(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		tag := strings.TrimSpace(part[:eq])
		val := strings.TrimSpace(part[eq+1:])
		if tag != "" {
			out[strings.ToLower(tag)] = val
		}
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ":") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func stripWhitespace(s string) string {
	return strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(s)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
