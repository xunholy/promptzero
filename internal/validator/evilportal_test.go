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

// TestValidateEvilPortal_MultipleForms covers the silent-failure mode
// where the LLM emits two forms (e.g. a header search bar + the
// credentials form). Marauder picks the first <form> it sees and
// either capture might miss its slot, depending on layout. Critical.
func TestValidateEvilPortal_MultipleForms(t *testing.T) {
	bad := `<!DOCTYPE html><html><body>
<form action="/search" method="GET"><input name="q"></form>
<form action="/get" method="GET">
  <input type="email" name="email">
  <input type="password" name="password">
</form>
</body></html>`
	rep := ValidateEvilPortal("two-forms.html", bad)
	if !rep.Has(SeverityCritical) {
		t.Errorf("two forms must trip critical, got %s", rep.Severity)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "ep_multiple_forms" {
			found = true
			if !strings.Contains(f.Message, "2 <form>") {
				t.Errorf("expected count in message, got %q", f.Message)
			}
		}
	}
	if !found {
		t.Errorf("expected ep_multiple_forms finding, got %+v", rep.Findings)
	}
}

// TestValidateEvilPortal_OnsubmitBlocker catches a silent-failure mode
// where the LLM bolts a JS handler onto the form that prevents default
// submission. Page renders, button looks normal, credentials never
// reach /get.
func TestValidateEvilPortal_OnsubmitBlocker(t *testing.T) {
	cases := []string{
		`onsubmit="return false"`,
		`onsubmit="event.preventDefault()"`,
	}
	for _, attr := range cases {
		t.Run(attr, func(t *testing.T) {
			bad := strings.Replace(goodPortal, `<form action="/get" method="GET">`,
				`<form action="/get" method="GET" `+attr+`>`, 1)
			rep := ValidateEvilPortal("blocker.html", bad)
			if !rep.Has(SeverityCritical) {
				t.Errorf("onsubmit blocker must trip critical, got %s", rep.Severity)
			}
			found := false
			for _, f := range rep.Findings {
				if f.Rule == "ep_form_onsubmit_blocker" {
					found = true
				}
			}
			if !found {
				t.Errorf("expected ep_form_onsubmit_blocker, got %+v", rep.Findings)
			}
		})
	}
}

// TestValidateEvilPortal_MultipartEnctype covers the
// enctype="multipart/form-data" trap — Marauder's /get handler only
// parses URL-encoded query strings.
func TestValidateEvilPortal_MultipartEnctype(t *testing.T) {
	bad := strings.Replace(goodPortal, `<form action="/get" method="GET">`,
		`<form action="/get" method="GET" enctype="multipart/form-data">`, 1)
	rep := ValidateEvilPortal("multi.html", bad)
	if !rep.Has(SeverityCritical) {
		t.Errorf("multipart enctype must trip critical, got %s", rep.Severity)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "ep_form_multipart" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ep_form_multipart, got %+v", rep.Findings)
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
