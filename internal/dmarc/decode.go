// Package dmarc decodes a DMARC policy DNS record (the `_dmarc.<domain>` TXT
// record, RFC 7489 §6.3) into a structured, forensic view.
//
// DMARC is the enforcement policy that ties SPF and DKIM together and tells
// receivers what to do with mail that fails alignment — so it is the single
// best read on a domain's anti-spoofing posture. The headline finding is
// objective and falls straight out of the record: `p=none` means the domain is
// monitoring only and **does not block spoofed mail**, and `pct<100` means only
// part of failing mail is filtered. This decoder surfaces the requested policy,
// subdomain policy, sampling percent, alignment modes, and the aggregate /
// forensic report destinations (themselves useful OSINT).
//
// Wrap-vs-native: native — RFC 7489 tag=value parsing, stdlib only, no new
// go.mod dependency. The field extraction is pinned against live published
// records (google.com / paypal.com / github.com) and the RFC tag definitions.
package dmarc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Result is the decoded DMARC record.
type Result struct {
	// Version is the v= tag (must be "DMARC1").
	Version string `json:"version"`
	// Policy is the p= requested policy: none / quarantine / reject.
	Policy string `json:"policy"`
	// SubdomainPolicy is the sp= tag; empty means "inherits p".
	SubdomainPolicy string `json:"subdomain_policy,omitempty"`
	// Pct is the pct= sampling percent (default 100).
	Pct int `json:"pct"`
	// Enforcing is true when the policy actually blocks (quarantine or reject).
	Enforcing bool `json:"enforcing"`
	// AggregateReports is the rua= destination list.
	AggregateReports []string `json:"aggregate_reports,omitempty"`
	// ForensicReports is the ruf= destination list.
	ForensicReports []string `json:"forensic_reports,omitempty"`
	// DKIMAlignment is adkim=: "r" relaxed (default) or "s" strict.
	DKIMAlignment string `json:"dkim_alignment"`
	// SPFAlignment is aspf=: "r" relaxed (default) or "s" strict.
	SPFAlignment string `json:"spf_alignment"`
	// FailureOptions is the fo= failure-reporting option list (default ["0"]).
	FailureOptions []string `json:"failure_options,omitempty"`
	// ReportInterval is ri= aggregate-report interval seconds (default 86400).
	ReportInterval int `json:"report_interval"`
	// Warnings carries objective, RFC-anchored observations.
	Warnings []string `json:"warnings,omitempty"`
	// Note carries interpretation guidance.
	Note string `json:"note,omitempty"`
}

// Decode parses a DMARC policy TXT record.
func Decode(record string) (*Result, error) {
	s := strings.TrimSpace(record)
	if s == "" {
		return nil, errors.New("empty record")
	}
	tags, order := parseTags(s)

	// RFC 7489: a record whose first tag is not v=DMARC1 is not DMARC.
	if len(order) == 0 || order[0] != "v" {
		return nil, errors.New("not a DMARC record: must begin with v=")
	}
	if tags["v"] != "DMARC1" {
		return nil, fmt.Errorf("not a DMARC record: v=%q (expected DMARC1)", tags["v"])
	}

	res := &Result{
		Version:        "DMARC1",
		Pct:            100,
		DKIMAlignment:  orDefault(strings.ToLower(tags["adkim"]), "r"),
		SPFAlignment:   orDefault(strings.ToLower(tags["aspf"]), "r"),
		ReportInterval: 86400,
	}

	if p, ok := tags["p"]; ok {
		res.Policy = strings.ToLower(p)
	} else {
		res.Warnings = append(res.Warnings, "no p= tag: required by RFC 7489; the record is invalid and receivers will ignore it")
	}
	switch res.Policy {
	case "none":
		res.Note = "p=none: MONITORING ONLY — DMARC is not enforcing, so spoofed mail from this domain is NOT blocked (it is only reported). The most common DMARC misconfiguration."
	case "quarantine":
		res.Enforcing = true
		res.Note = "p=quarantine: failing mail is sent to spam/junk."
	case "reject":
		res.Enforcing = true
		res.Note = "p=reject: failing mail is rejected outright — the strongest posture."
	case "":
		// handled by the missing-p warning above
	default:
		res.Warnings = append(res.Warnings, fmt.Sprintf("unknown p= value %q (expected none/quarantine/reject)", res.Policy))
	}

	if sp, ok := tags["sp"]; ok {
		res.SubdomainPolicy = strings.ToLower(sp)
	}
	if pct, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(pct); err == nil && n >= 0 && n <= 100 {
			res.Pct = n
			if n < 100 && res.Enforcing {
				res.Warnings = append(res.Warnings, fmt.Sprintf("pct=%d: only %d%% of failing mail is subject to the policy; the rest is not enforced", n, n))
			}
		} else {
			res.Warnings = append(res.Warnings, fmt.Sprintf("invalid pct=%q (expected 0-100)", pct))
		}
	}
	res.AggregateReports = splitURIs(tags["rua"])
	res.ForensicReports = splitURIs(tags["ruf"])
	if fo, ok := tags["fo"]; ok {
		res.FailureOptions = splitList(fo, ':')
	}
	if ri, ok := tags["ri"]; ok {
		if n, err := strconv.Atoi(ri); err == nil && n >= 0 {
			res.ReportInterval = n
		} else {
			res.Warnings = append(res.Warnings, fmt.Sprintf("invalid ri=%q", ri))
		}
	}
	if res.Note == "" {
		res.Note = "DMARC policy record."
	}
	return res, nil
}

// parseTags splits a DMARC record into its tag=value map plus the tag order
// (the order matters: v must be first).
func parseTags(s string) (map[string]string, []string) {
	out := map[string]string{}
	var order []string
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		tag := strings.ToLower(strings.TrimSpace(part[:eq]))
		val := strings.TrimSpace(part[eq+1:])
		if tag != "" {
			if _, seen := out[tag]; !seen {
				order = append(order, tag)
			}
			out[tag] = val
		}
	}
	return out, order
}

// splitURIs splits a comma-separated rua/ruf URI list.
func splitURIs(s string) []string {
	return splitList(s, ',')
}

func splitList(s string, sep byte) []string {
	var out []string
	for _, p := range strings.Split(s, string(sep)) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
