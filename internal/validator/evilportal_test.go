package validator

import (
	"strings"
	"testing"
)

const goodPortal = `<!DOCTYPE html>
<html><body>
<form action="/get" method="GET">
  <input type="email" name="email">
  <input type="password" name="password">
  <button type="submit">Login</button>
</form>
</body></html>`

func TestValidateEvilPortal_Compliant(t *testing.T) {
	rep := ValidateEvilPortal("test.html", goodPortal)
	if rep.Severity != SeverityInfo {
		t.Errorf("compliant portal should score info/none, got %s with %d findings", rep.Severity, len(rep.Findings))
		for _, f := range rep.Findings {
			t.Logf("  - %s: %s", f.Rule, f.Message)
		}
	}
}

func TestValidateEvilPortal_MissingForm(t *testing.T) {
	rep := ValidateEvilPortal("nobody.html", "<html><body>hello</body></html>")
	if !rep.Has(SeverityCritical) {
		t.Error("missing form must trip critical")
	}
	var hit bool
	for _, f := range rep.Findings {
		if f.Rule == "ep_missing_form" {
			hit = true
		}
	}
	if !hit {
		t.Error("expected ep_missing_form finding")
	}
}

func TestValidateEvilPortal_WrongAction(t *testing.T) {
	bad := strings.Replace(goodPortal, `action="/get"`, `action="/login"`, 1)
	rep := ValidateEvilPortal("wrong_action.html", bad)
	if !rep.Has(SeverityCritical) {
		t.Error("wrong action must trip critical")
	}
}

func TestValidateEvilPortal_WrongMethod(t *testing.T) {
	bad := strings.Replace(goodPortal, `method="GET"`, `method="POST"`, 1)
	rep := ValidateEvilPortal("post.html", bad)
	if !rep.Has(SeverityCritical) {
		t.Error("POST method must trip critical")
	}
}

func TestValidateEvilPortal_WrongFieldName(t *testing.T) {
	cases := map[string]string{
		"username instead of email": strings.Replace(goodPortal, `name="email"`, `name="username"`, 1),
		"user instead of email":     strings.Replace(goodPortal, `name="email"`, `name="user"`, 1),
		"pass instead of password":  strings.Replace(goodPortal, `name="password"`, `name="pass"`, 1),
	}
	for name, html := range cases {
		rep := ValidateEvilPortal("field_"+name+".html", html)
		if !rep.Has(SeverityCritical) {
			t.Errorf("%s: should trip critical; findings=%v", name, rep.Findings)
		}
	}
}

func TestValidateEvilPortal_ExternalResource(t *testing.T) {
	bad := strings.Replace(goodPortal, `<body>`, `<body><img src="https://evil.com/beacon.png">`, 1)
	rep := ValidateEvilPortal("external.html", bad)
	if !rep.Has(SeverityCritical) {
		t.Error("external https:// resource must trip critical")
	}
}

func TestValidateEvilPortal_CDN(t *testing.T) {
	bad := strings.Replace(goodPortal, `<body>`, `<body><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.0/css/bootstrap.min.css">`, 1)
	rep := ValidateEvilPortal("cdn.html", bad)
	if !rep.Has(SeverityCritical) {
		t.Error("CDN reference must trip critical")
	}
}

func TestValidateEvilPortal_MarkdownFence(t *testing.T) {
	bad := "```html\n" + goodPortal + "\n```"
	rep := ValidateEvilPortal("fenced.html", bad)
	if !rep.Has(SeverityCritical) {
		t.Error("leaked markdown fence must trip at least warn")
	}
}

// Lock that ValidateEvilPortal produces deterministic Report shapes
// so the test ladder doesn't drift silently during future rule edits.
func TestValidateEvilPortal_FindingFieldsPopulated(t *testing.T) {
	bad := strings.Replace(goodPortal, `method="GET"`, `method="POST"`, 1)
	rep := ValidateEvilPortal("x.html", bad)
	if len(rep.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range rep.Findings {
		if f.Rule == "" || f.Message == "" {
			t.Errorf("finding missing rule or message: %+v", f)
		}
	}
}
