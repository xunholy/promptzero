package pypitoken

import (
	"strings"
	"testing"
)

// These tokens were generated with the pypitoken reference library
// (Token.create(domain="pypi.org", key=...) + .restrict(...) + .dump()), so
// each is a real PyPI-format macaroon with a known scope. They are signed with
// a throwaway key and carry no live credential.
const (
	tokWide    = "pypi-" + "AgEIcHlwaS5vcmcCJGExYjJjM2Q0LTAwMDAtMTExMS0yMjIyLTMzMzM0NDQ0NTU1NQAABiAHDTZ5To_nbqcpj8ZXaDuSqPs1kwW7qq2gFvHjqUW2xQ"
	tokProj    = "pypi-" + "AgEIcHlwaS5vcmcCJGRlYWRiZWVmLTk5OTktODg4OC03Nzc3LTY2NjY1NTU1NDQ0NAACIVsxLCBbInByb21wdHplcm8iLCAiZXhhbXBsZXBrZyJdXQAABiDonMqDyv9TnOm5MzTAZK0H-pqd42XRT6hpAuqkv142lw"
	tokDate    = "pypi-" + "AgEIcHlwaS5vcmcCJDExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NQACG1swLCAxODAwMDAwMDAwLCAxNzAwMDAwMDAwXQAABiBD1Z5Px1GMQDuhIYvGXtJubwTmPrxJni8W13osF0C3tA"
	tokIDs     = "pypi-" + "AgEIcHlwaS5vcmcCJDIyMjIyMjIyLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NQACLVsyLCBbIjAwMDAwMDAwLWFhYWEtYmJiYi1jY2NjLTAwMDAwMDAwMDAwMSJdXQAABiA6-cZ9MOYFIyb6Nj6F1O-KizEBivTI1tT6RtfuMkhg9Q"
	tokUser    = "pypi-" + "AgEIcHlwaS5vcmcCJDMzMzMzMzMzLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NQACK1szLCAiOTk5OTk5OTktYWFhYS1iYmJiLWNjY2MtMDAwMDAwMDAwMDA5Il0AAAYgB76K1B08MAOvleBQtye-HgLTi2iL8YFs7-tTzgAbGAw"
	tokLegNoop = "pypi-" + "AgEIcHlwaS5vcmcCJDQ0NDQ0NDQ0LTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NQACJXsidmVyc2lvbiI6IDEsICJwZXJtaXNzaW9ucyI6ICJ1c2VyIn0AAAYgTNMva3lVfh7t1nykeWWERu3eXfbRb-eVdCzpNng7tuI"
	tokLegProj = "pypi-" + "AgEIcHlwaS5vcmcCJDU1NTU1NTU1LTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NQACOnsidmVyc2lvbiI6IDEsICJwZXJtaXNzaW9ucyI6IHsicHJvamVjdHMiOiBbImxlZ2FjeXBrZyJdfX0AAAYgirRaN40-F6Ph4ujWGHbGmzkSAaKa24zXAzF-8kAX0xI"
	tokLegDate = "pypi-" + "AgEIcHlwaS5vcmcCJDY2NjY2NjY2LTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NQACJnsibmJmIjogMTcwMDAwMDAwMCwgImV4cCI6IDE4MDAwMDAwMDB9AAAGIEgcyd8wtxvCQ-TfhIPyB8IuPSacElQ0IuAqgYT4J9a0"
	tokMulti   = "pypi-" + "AgEIcHlwaS5vcmcCJDc3Nzc3Nzc3LTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NQACD1sxLCBbInBrZ29uZSJdXQACG1swLCAxODAwMDAwMDAwLCAxNzAwMDAwMDAwXQAABiDsOCz0dd1zc1XThSWN7pMU1M0851_qvRFQxRSgPtn9gg"
)

func TestDecode_WellFormedAccountWide(t *testing.T) {
	r, err := Decode(tokWide)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Location != "pypi.org" || !r.WellFormed {
		t.Errorf("Location=%q WellFormed=%v, want pypi.org / true", r.Location, r.WellFormed)
	}
	if r.Identifier != "a1b2c3d4-0000-1111-2222-333344445555" {
		t.Errorf("Identifier = %q", r.Identifier)
	}
	if r.MacaroonVersion != 2 {
		t.Errorf("MacaroonVersion = %d, want 2", r.MacaroonVersion)
	}
	if len(r.Restrictions) != 0 {
		t.Errorf("Restrictions = %d, want 0", len(r.Restrictions))
	}
	if !strings.Contains(r.Scope, "account-wide") {
		t.Errorf("Scope = %q, want account-wide", r.Scope)
	}
}

func TestDecode_ProjectNames(t *testing.T) {
	r, err := Decode(tokProj)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Restrictions) != 1 {
		t.Fatalf("Restrictions = %d, want 1", len(r.Restrictions))
	}
	got := r.Restrictions[0]
	if got.Kind != "project_names" || got.Legacy {
		t.Errorf("kind=%q legacy=%v, want project_names/false", got.Kind, got.Legacy)
	}
	if strings.Join(got.Projects, ",") != "promptzero,examplepkg" {
		t.Errorf("Projects = %v", got.Projects)
	}
	if !strings.Contains(r.Scope, "promptzero") || strings.Contains(r.Scope, "account-wide") {
		t.Errorf("Scope = %q", r.Scope)
	}
}

func TestDecode_Date(t *testing.T) {
	r, err := Decode(tokDate)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := r.Restrictions[0]
	if got.Kind != "date" || got.Legacy {
		t.Errorf("kind=%q legacy=%v, want date/false", got.Kind, got.Legacy)
	}
	if got.NotBefore != 1700000000 || got.Expires != 1800000000 {
		t.Errorf("nbf=%d exp=%d, want 1700000000 / 1800000000", got.NotBefore, got.Expires)
	}
}

func TestDecode_ProjectIDs(t *testing.T) {
	r, err := Decode(tokIDs)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := r.Restrictions[0]
	if got.Kind != "project_ids" {
		t.Errorf("kind=%q, want project_ids", got.Kind)
	}
	if strings.Join(got.Projects, ",") != "00000000-aaaa-bbbb-cccc-000000000001" {
		t.Errorf("Projects = %v", got.Projects)
	}
}

func TestDecode_UserID(t *testing.T) {
	r, err := Decode(tokUser)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := r.Restrictions[0]
	if got.Kind != "user_id" || got.UserID != "99999999-aaaa-bbbb-cccc-000000000009" {
		t.Errorf("kind=%q user=%q", got.Kind, got.UserID)
	}
}

func TestDecode_LegacyNoop(t *testing.T) {
	r, err := Decode(tokLegNoop)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := r.Restrictions[0]
	if got.Kind != "noop" || !got.Legacy {
		t.Errorf("kind=%q legacy=%v, want noop/true", got.Kind, got.Legacy)
	}
	// A legacy noop does not narrow scope: still account-wide.
	if !strings.Contains(r.Scope, "account-wide") {
		t.Errorf("Scope = %q, want account-wide", r.Scope)
	}
}

func TestDecode_LegacyProjectNames(t *testing.T) {
	r, err := Decode(tokLegProj)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := r.Restrictions[0]
	if got.Kind != "project_names" || !got.Legacy {
		t.Errorf("kind=%q legacy=%v, want project_names/true", got.Kind, got.Legacy)
	}
	if strings.Join(got.Projects, ",") != "legacypkg" {
		t.Errorf("Projects = %v", got.Projects)
	}
}

func TestDecode_LegacyDate(t *testing.T) {
	r, err := Decode(tokLegDate)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := r.Restrictions[0]
	if got.Kind != "date" || !got.Legacy {
		t.Errorf("kind=%q legacy=%v, want date/true", got.Kind, got.Legacy)
	}
	if got.NotBefore != 1700000000 || got.Expires != 1800000000 {
		t.Errorf("nbf=%d exp=%d", got.NotBefore, got.Expires)
	}
}

func TestDecode_MultipleCaveats(t *testing.T) {
	r, err := Decode(tokMulti)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Restrictions) != 2 {
		t.Fatalf("Restrictions = %d, want 2", len(r.Restrictions))
	}
	if r.Restrictions[0].Kind != "project_names" || r.Restrictions[1].Kind != "date" {
		t.Errorf("kinds = %q,%q want project_names,date", r.Restrictions[0].Kind, r.Restrictions[1].Kind)
	}
	if !strings.Contains(r.Scope, "pkgone") || !strings.Contains(r.Scope, "exp=") {
		t.Errorf("Scope = %q", r.Scope)
	}
}

func TestDecode_Errors(t *testing.T) {
	cases := map[string]string{
		"no prefix":    "ghp_notapypitoken",
		"empty body":   "pypi-",
		"bad base64":   "pypi-@@@not-base64@@@",
		"not macaroon": "pypi-aGVsbG8gd29ybGQ", // "hello world", valid b64 but not a macaroon
	}
	for name, tok := range cases {
		if _, err := Decode(tok); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// A raw caveat that is neither a known array tag nor a known object form must be
// surfaced as "unknown" with its bytes, never silently dropped or guessed.
func TestParseCaveat_Unknown(t *testing.T) {
	r := parseCaveat([]byte(`[99, "mystery"]`))
	if r.Kind != "unknown" || r.Raw != `[99, "mystery"]` {
		t.Errorf("got kind=%q raw=%q, want unknown + raw preserved", r.Kind, r.Raw)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(tokWide)
	f.Add(tokMulti)
	f.Add("pypi-" + "not-base64-@@@")
	f.Add("pypi-")
	f.Add("")
	// A token whose macaroon body is a v2 macaroon with a bogus caveat shape.
	f.Add("pypi-" + "AgEIcHlwaS5vcmcCBHRlc3QAAAYgAAAA")
	f.Fuzz(func(_ *testing.T, tok string) {
		// Must never panic regardless of input.
		_, _ = Decode(tok)
	})
}
