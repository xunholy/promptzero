// Package spf decodes and statically analyses an SPF (Sender Policy Framework)
// DNS record (the `v=spf1 …` TXT record, RFC 7208) — the third leg of the
// email-authentication triad alongside DKIM and DMARC.
//
// SPF declares which hosts may send mail for a domain, so it is a direct read
// on spoofability. The headline findings are objective and fall straight out of
// the record: the terminal `all` qualifier sets the default disposition
// (`+all` authorises the *entire internet* to send as the domain — critical;
// `?all` neutral — no protection; `~all` softfail; `-all` fail — strict), and
// the count of DNS-lookup-causing mechanisms feeds the RFC 7208 §4.6.4 limit of
// 10 (exceeding it is a permerror, which makes SPF fail open).
//
// Scope: this is OFFLINE static analysis of a single record. The DNS-lookup
// count reported is the number of lookup-causing terms *in this record*; the
// RFC limit applies across the fully *resolved* tree (each `include`/`redirect`
// pulls more records), which requires live DNS — so the reported count is a
// lower bound, stated as such. The `all` qualifier and mechanism structure are
// fully determined offline.
//
// Wrap-vs-native: native — RFC 7208 term tokenising, stdlib only, no new go.mod
// dependency. Pinned against live published records (google / paypal / github).
package spf

import (
	"errors"
	"fmt"
	"strings"
)

// Mechanism is one parsed SPF directive.
type Mechanism struct {
	// Qualifier is +, -, ~ or ? (default + when omitted).
	Qualifier string `json:"qualifier"`
	// Type is all / ip4 / ip6 / a / mx / ptr / exists / include.
	Type string `json:"type"`
	// Value is the part after ':' (domain / address / cidr), if any.
	Value string `json:"value,omitempty"`
	// CausesLookup is true for the mechanisms that count toward the RFC 7208
	// 10-DNS-lookup limit (a, mx, ptr, exists, include).
	CausesLookup bool `json:"causes_lookup,omitempty"`
}

// Result is the decoded SPF record.
type Result struct {
	// Version is "spf1".
	Version string `json:"version"`
	// Mechanisms is the ordered directive list.
	Mechanisms []Mechanism `json:"mechanisms"`
	// Redirect is the redirect= modifier target, if present.
	Redirect string `json:"redirect,omitempty"`
	// Exp is the exp= explanation modifier target, if present.
	Exp string `json:"exp,omitempty"`
	// AllQualifier is the qualifier on the terminal `all` mechanism (+/-/~/?),
	// or "" if the record has no `all`.
	AllQualifier string `json:"all_qualifier,omitempty"`
	// DirectLookups counts lookup-causing terms in THIS record (a/mx/ptr/
	// exists/include + redirect) — a lower bound on the resolved-tree total.
	DirectLookups int `json:"direct_lookups"`
	// Warnings carries objective, RFC-anchored observations.
	Warnings []string `json:"warnings,omitempty"`
	// Note carries interpretation guidance.
	Note string `json:"note,omitempty"`
}

var lookupMechs = map[string]bool{"a": true, "mx": true, "ptr": true, "exists": true, "include": true}
var knownMechs = map[string]bool{"all": true, "ip4": true, "ip6": true, "a": true, "mx": true, "ptr": true, "exists": true, "include": true}

// Decode parses and statically analyses an SPF record.
func Decode(record string) (*Result, error) {
	s := normalize(record)
	if s == "" {
		return nil, errors.New("empty record")
	}
	fields := strings.Fields(s)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		return nil, errors.New("not an SPF record: must begin with v=spf1")
	}

	res := &Result{Version: "spf1"}
	sawAll := false
	for _, term := range fields[1:] {
		// Modifiers are name=value (redirect=, exp=); mechanisms use ':'.
		if name, val, ok := modifier(term); ok {
			switch name {
			case "redirect":
				res.Redirect = val
				res.DirectLookups++
			case "exp":
				res.Exp = val
			default:
				res.Warnings = append(res.Warnings, fmt.Sprintf("unknown modifier %q", term))
			}
			continue
		}

		qual, typ, val := mechanism(term)
		if !knownMechs[typ] {
			res.Warnings = append(res.Warnings, fmt.Sprintf("unknown mechanism %q", term))
			continue
		}
		m := Mechanism{Qualifier: qual, Type: typ, Value: val, CausesLookup: lookupMechs[typ]}
		if m.CausesLookup {
			res.DirectLookups++
		}
		if typ == "ptr" {
			res.Warnings = append(res.Warnings, "ptr mechanism is deprecated (RFC 7208 §5.5: SHOULD NOT be used)")
		}
		if typ == "all" {
			if sawAll {
				res.Warnings = append(res.Warnings, "multiple `all` mechanisms; only the first is reached")
			} else {
				res.AllQualifier = qual
				sawAll = true
			}
		} else if sawAll {
			res.Warnings = append(res.Warnings, fmt.Sprintf("term %q appears after `all` and is unreachable", term))
		}
		res.Mechanisms = append(res.Mechanisms, m)
	}

	annotate(res, sawAll)
	return res, nil
}

// annotate fills in the objective interpretation note + structural warnings.
func annotate(res *Result, sawAll bool) {
	switch res.AllQualifier {
	case "+":
		res.Note = "+all: PASS-ALL — the record authorises the ENTIRE internet to send mail as this domain. " +
			"Critical misconfiguration; SPF provides no protection and effectively invites spoofing."
	case "?":
		res.Note = "?all: NEUTRAL — no SPF assertion for unmatched senders; provides no real anti-spoofing protection."
	case "~":
		res.Note = "~all: SOFTFAIL — unmatched mail is accepted but marked suspicious (the common posture)."
	case "-":
		res.Note = "-all: FAIL — unmatched senders are rejected (the strict, recommended terminal)."
	default:
		if res.Redirect != "" {
			res.Note = fmt.Sprintf("no terminal `all`; evaluation redirects to %q (its `all` governs the result).", res.Redirect)
		} else {
			res.Note = "no terminal `all` and no redirect: unmatched senders default to NEUTRAL — no protection."
			res.Warnings = append(res.Warnings, "missing a terminal `all` (or redirect=): the policy is effectively neutral")
		}
	}
	if res.DirectLookups >= 10 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d lookup-causing terms in this record alone meet/exceed the RFC 7208 limit of 10 — a permerror, which makes SPF fail open", res.DirectLookups))
	} else if res.DirectLookups > 0 {
		res.Note += fmt.Sprintf(" %d DNS-lookup term(s) in this record (a lower bound — each include/redirect resolves to more; the RFC 7208 limit of 10 is across the full resolved tree, which needs live DNS).", res.DirectLookups)
	}
}

// normalize reconstructs a record that may arrive as DNS multi-string output
// (dig prints `"part1" "part2"`, which TXT semantics concatenate with no
// separator). Surrounding quotes are stripped; `" "` joins are removed.
func normalize(record string) string {
	s := strings.TrimSpace(record)
	if strings.Contains(s, "\"") {
		s = strings.ReplaceAll(s, "\" \"", "")
		s = strings.ReplaceAll(s, "\"", "")
		s = strings.TrimSpace(s)
	}
	return s
}

// modifier reports whether term is a name=value modifier, returning the
// lowercased name and value.
func modifier(term string) (name, val string, ok bool) {
	eq := strings.IndexByte(term, '=')
	if eq <= 0 {
		return "", "", false
	}
	// A modifier name is all letters; a mechanism never contains '=' before ':'.
	name = strings.ToLower(term[:eq])
	for _, c := range name {
		if c < 'a' || c > 'z' {
			return "", "", false
		}
	}
	return name, term[eq+1:], true
}

// mechanism splits a mechanism term into its qualifier, lowercased type, and
// optional value (the part after ':').
func mechanism(term string) (qual, typ, val string) {
	qual = "+"
	switch term[0] {
	case '+', '-', '~', '?':
		qual = string(term[0])
		term = term[1:]
	}
	name := term
	if colon := strings.IndexByte(term, ':'); colon >= 0 {
		name, val = term[:colon], term[colon+1:]
	}
	// A /cidr suffix (a/24, mx/24) is part of the mechanism, not the type.
	if slash := strings.IndexByte(name, '/'); slash >= 0 {
		if val == "" {
			val = name[slash:]
		}
		name = name[:slash]
	}
	return qual, strings.ToLower(name), val
}
