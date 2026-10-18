// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"testing"

	"github.com/xunholy/promptzero/internal/toolsearch"
)

// routingTopK is how far down the ranked tool_search results the agent is
// still considered to have "found" the right tool. tool_search surfaces 10
// by default and the agent reliably picks from the head of that list, so a
// top-5 landing is the bar: generous enough not to be brittle on near-ties,
// tight enough that a real relevance regression (the right tool sliding out
// of the shortlist) trips the test.
const routingTopK = 5

// registryDocs builds the search corpus from the live registry exactly the
// way the tool_search handler does (internal/tools/tool_search.go) and the
// web/CLI/agent fallbacks do — same fields, same source — so this eval
// measures the real routing path, not a hand-built fixture that can drift
// from it.
func registryDocs() []toolsearch.Doc {
	specs := All()
	docs := make([]toolsearch.Doc, 0, len(specs))
	for _, s := range specs {
		docs = append(docs, toolsearch.Doc{
			Name:        s.Name,
			Aliases:     s.Aliases,
			Group:       string(s.Group),
			Description: s.Description,
		})
	}
	return docs
}

// TestToolRouting is the regression guard for the core UX: with 700+ tools,
// what decides whether PromptZero works is whether a natural-language request
// reaches the right tool. Unit tests prove each tool is correct in isolation;
// this proves the *selector* still routes to it. Each case is a request
// phrased the way an operator would type it, paired with the one canonical
// tool that should answer it. The assertion is deliberately rank-based (top-K)
// rather than top-1 so legitimate near-neighbours (e.g. a sibling decoder)
// ranking alongside the target is fine — what fails the build is the target
// dropping out of the shortlist entirely, which is the regression that would
// silently break routing as the registry grows.
//
// Cases span the breadth of the registry (RF/device and host-side decoders)
// on purpose: a change that over-fits ranking to one family at the expense of
// another shows up here. When a decoder or device family is reworked, add a
// case for it rather than deleting one that newly fails — a failure here is
// the signal the selector regressed, not that the test is stale.
func TestToolRouting(t *testing.T) {
	docs := registryDocs()

	cases := []struct {
		query string
		want  string
	}{
		// RF / on-device
		{"decode a captured subghz signal into protocol and key", "subghz_decode"},
		{"read an nfc card and save it to a file", "nfc_read_save"},
		{"get flipper device information", "device_info"},
		{"scan for nearby wifi access points", "wifi_scan_ap"},
		// Host-side protocol / credential decoders
		{"decode a jwt token", "jwt_decode"},
		{"parse a kubeconfig file for credentials", "kubeconfig_decode"},
		{"identify what kind of hash this is", "hash_identify"},
		{"decode an aws access key id", "aws_key_decode"},
		{"compute a ja3 tls client fingerprint from a clienthello", "ja3_fingerprint"},
		// Radio / signal decoders (non-Flipper transports)
		{"decode an ads-b mode s frame from 1090 mhz", "adsb_mode_s_decode"},
		{"decode a wireguard vpn packet", "wireguard_packet_decode"},
		{"decode an ais maritime nmea sentence", "ais_nmea_decode"},
	}

	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			// Sanity: the expected target must be a real canonical tool, so a
			// typo in the table fails loudly here rather than masquerading as
			// a routing miss below.
			if spec, ok := Get(tc.want); !ok || spec.Name != tc.want {
				t.Fatalf("eval target %q is not a canonical registered tool — fix the table", tc.want)
			}

			results := toolsearch.Search(docs, tc.query, routingTopK)
			for _, r := range results {
				if r.Name == tc.want {
					return
				}
			}

			got := make([]string, len(results))
			for i, r := range results {
				got[i] = r.Name
			}
			t.Errorf("query %q did not surface %q in the top %d; got %v",
				tc.query, tc.want, routingTopK, got)
		})
	}
}
