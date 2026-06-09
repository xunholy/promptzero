// Package emailauth is the unified front-end for the email-authentication
// record decoders — the email-security analogue of the project's
// secret_identify / hash_identify routers. Paste any email-auth DNS TXT record
// (SPF, DKIM, or DMARC) and it detects the kind and dispatches to the matching
// in-tree decoder, so an operator (or an agent) pulling records from a bulk DNS
// dump / a config / a capture need not pre-classify them.
//
// Detection is by the record's `v=` version tag (the unambiguous discriminator
// that SPF and DMARC both require, and which DKIM uses when present); a DKIM
// key record that omits the optional `v=` is recognised by its `p=`/`k=` tags.
//
// Wrap-vs-native: native orchestration over the already-verified internal/spf,
// internal/dkim, and internal/dmarc decoders — no new go.mod dependency, no new
// parsing logic, no new external trust. Each underlying decoder is independently
// spec-/oracle-anchored and fuzzed.
package emailauth

import (
	"errors"
	"strings"

	"github.com/xunholy/promptzero/internal/dkim"
	"github.com/xunholy/promptzero/internal/dmarc"
	"github.com/xunholy/promptzero/internal/spf"
)

// Result is the routed decode: Kind names the detected record type and exactly
// one of the typed sub-results is populated.
type Result struct {
	// Kind is "spf", "dkim", or "dmarc".
	Kind string `json:"kind"`
	// SPF is populated when Kind == "spf".
	SPF *spf.Result `json:"spf,omitempty"`
	// DKIM is populated when Kind == "dkim".
	DKIM *dkim.Result `json:"dkim,omitempty"`
	// DMARC is populated when Kind == "dmarc".
	DMARC *dmarc.Result `json:"dmarc,omitempty"`
}

// Decode detects the email-auth record kind and dispatches to the matching
// decoder.
func Decode(record string) (*Result, error) {
	s := strings.TrimSpace(record)
	if s == "" {
		return nil, errors.New("empty record")
	}
	// Strip a leading quote (dig multi-string output) for prefix detection;
	// the underlying decoders handle their own normalisation.
	probe := strings.ToLower(strings.TrimLeft(s, "\""))
	probe = strings.TrimSpace(probe)

	switch {
	case strings.HasPrefix(probe, "v=spf1"):
		r, err := spf.Decode(s)
		if err != nil {
			return nil, err
		}
		return &Result{Kind: "spf", SPF: r}, nil
	case strings.HasPrefix(probe, "v=dmarc1"):
		r, err := dmarc.Decode(s)
		if err != nil {
			return nil, err
		}
		return &Result{Kind: "dmarc", DMARC: r}, nil
	case strings.HasPrefix(probe, "v=dkim1"):
		r, err := dkim.Decode(s)
		if err != nil {
			return nil, err
		}
		return &Result{Kind: "dkim", DKIM: r}, nil
	default:
		// DKIM is the only record whose v= tag is optional; recognise it by its
		// required p= (and usual k=) tags. SPF/DMARC always carry v=, so a
		// record reaching here without one is only a DKIM candidate.
		if hasTag(probe, "p") || hasTag(probe, "k") {
			r, err := dkim.Decode(s)
			if err != nil {
				return nil, err
			}
			return &Result{Kind: "dkim", DKIM: r}, nil
		}
		return nil, errors.New("unrecognised email-auth record: no v=spf1 / v=DMARC1 / v=DKIM1 prefix and no DKIM p=/k= tag")
	}
}

// hasTag reports whether a `;`-delimited tag=value record contains the given
// lowercased tag.
func hasTag(record, tag string) bool {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if eq := strings.IndexByte(part, '='); eq > 0 {
			if strings.TrimSpace(part[:eq]) == tag {
				return true
			}
		}
	}
	return false
}
