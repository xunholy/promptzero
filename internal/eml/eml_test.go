package eml

import (
	"strings"
	"testing"
)

const benignEML = `From: Alice <alice@example.com>
Reply-To: alice@example.com
To: bob@example.com
Subject: Lunch tomorrow
Date: Mon, 02 Jan 2006 15:04:05 -0700
Message-ID: <m1@example.com>
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass
Content-Type: text/plain

Hey Bob, lunch at noon? See https://example.com/cal
`

const phishEML = `From: "PayPal Service" <service@paypal.com>
Reply-To: attacker@evil.ru
Return-Path: <bounce@evil.ru>
To: victim@example.com
Subject: =?utf-8?B?WW91ciBJbnZvaWNl?=
Date: Mon, 02 Jan 2006 15:04:05 -0700
Message-ID: <x1@evil.ru>
Received: from a.evil.ru by mx.example.com
Received: from b.evil.ru by a.evil.ru
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=evil.ru; dkim=fail header.i=@evil.ru; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND1"

--BOUND1
Content-Type: text/plain

Please review the invoice at http://1.2.3.4/login immediately.
--BOUND1
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAA=
--BOUND1--
`

func TestDecode_Benign(t *testing.T) {
	r, err := Decode([]byte(benignEML))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.FromDomain != "example.com" || r.ReplyToDomain != "example.com" {
		t.Errorf("domains: from=%q reply=%q", r.FromDomain, r.ReplyToDomain)
	}
	if r.Suspicious || r.ReplyToMismatch || len(r.Attachments) != 0 {
		t.Errorf("benign flagged: %+v", r)
	}
	if r.Auth.SPF != "pass" || r.Auth.DKIM != "pass" || r.Auth.DMARC != "pass" {
		t.Errorf("auth = %+v, want all pass", r.Auth)
	}
	if len(r.URLs) != 1 || r.URLs[0] != "https://example.com/cal" {
		t.Errorf("urls = %v", r.URLs)
	}
}

func TestDecode_Phish(t *testing.T) {
	r, err := Decode([]byte(phishEML))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Subject != "Your Invoice" {
		t.Errorf("subject = %q (RFC2047 not decoded)", r.Subject)
	}
	if r.FromDomain != "paypal.com" || r.ReplyToDomain != "evil.ru" {
		t.Errorf("domains: from=%q reply=%q", r.FromDomain, r.ReplyToDomain)
	}
	if !r.ReplyToMismatch || !r.ReturnPathMismatch {
		t.Errorf("expected reply-to + return-path mismatch: %+v", r)
	}
	if r.Auth.SPF != "fail" || r.Auth.DKIM != "fail" || r.Auth.DMARC != "fail" {
		t.Errorf("auth = %+v, want all fail", r.Auth)
	}
	if r.ReceivedHops != 2 {
		t.Errorf("received_hops = %d, want 2", r.ReceivedHops)
	}
	if len(r.Attachments) != 1 {
		t.Fatalf("attachments = %+v, want 1", r.Attachments)
	}
	a := r.Attachments[0]
	if a.Filename != "invoice.pdf.exe" || !a.Dangerous || !strings.Contains(a.DangerReason, "double extension") {
		t.Errorf("attachment = %+v", a)
	}
	if a.Bytes != 20 { // decoded length of the base64 body
		t.Errorf("decoded bytes = %d, want 20", a.Bytes)
	}
	if len(r.URLs) != 1 || r.URLs[0] != "http://1.2.3.4/login" {
		t.Errorf("urls = %v", r.URLs)
	}
	if !r.Suspicious {
		t.Fatal("expected suspicious")
	}
	for _, want := range []string{"reply-to domain", "SPF=fail", "DMARC=fail", "double extension", "IP-literal URL"} {
		if !anyContains(r.SuspiciousReasons, want) {
			t.Errorf("reasons %v missing %q", r.SuspiciousReasons, want)
		}
	}
}

func TestClassifyAttachment(t *testing.T) {
	cases := []struct {
		name      string
		dangerous bool
		reason    string
	}{
		{"report.pdf", false, ""},
		{"setup.exe", true, "executable"},
		{"invoice.pdf.exe", true, "double extension"},
		{"shortcut.lnk", true, "executable"},
		{"payload.zip", true, "archive"},
		{"photo.jpg", false, ""},
	}
	for _, c := range cases {
		d, reason := classifyAttachment(c.name)
		if d != c.dangerous || (c.reason != "" && !strings.Contains(reason, c.reason)) {
			t.Errorf("%s: dangerous=%v reason=%q, want %v/%q", c.name, d, reason, c.dangerous, c.reason)
		}
	}
}

func TestDecode_Errors(t *testing.T) {
	if _, err := Decode([]byte("")); err == nil {
		t.Error("empty should error")
	}
}

func anyContains(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(benignEML))
	f.Add([]byte(phishEML))
	f.Add([]byte("From: a@b\n\nbody"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Decode(in)
	})
}
