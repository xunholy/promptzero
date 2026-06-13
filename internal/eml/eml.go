// Package eml triages a raw email message (.eml / RFC 5322) for phishing
// indicators.
//
// The email is the delivery envelope for the payloads the other malware-triage
// tools decode (a .lnk / weaponised PDF / macro doc arrives as an attachment).
// This parses the message with the Go stdlib (net/mail headers + mime/multipart
// body) and layers the analyst triage on top: the From / Reply-To / Return-Path
// identities and their domains, the SPF / DKIM / DMARC results from
// Authentication-Results, the Received-hop count, every attachment (filename,
// type, size) with a danger flag for executable / script / double-extension /
// archive files, and the URLs in the body (IP-literal and punycode called out).
//
// No confidently-wrong output: parsing uses the stdlib RFC 5322 / MIME parsers;
// fields absent from the message are left empty, never guessed; the suspicious
// verdict is a labelled heuristic (a From↔Reply-To domain mismatch, an auth
// failure, or a dangerous attachment) — a clean result is not a guarantee of
// safety; attachment bytes are size-capped and never executed.
//
// Wrap-vs-native: native — Go stdlib net/mail + mime + mime/multipart, no new
// go.mod dependency. Deeply nested multipart and S/MIME-encrypted bodies are
// walked best-effort (encrypted parts are surfaced, not decrypted).
package eml

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"sort"
	"strings"
)

const (
	maxAttachmentBytes = 8 << 20 // cap per-attachment decode
	maxDepth           = 8       // multipart recursion guard
)

// Attachment is one decoded MIME attachment.
type Attachment struct {
	Filename     string `json:"filename"`
	ContentType  string `json:"content_type"`
	Disposition  string `json:"disposition,omitempty"`
	Bytes        int    `json:"bytes"`
	Dangerous    bool   `json:"dangerous,omitempty"`
	DangerReason string `json:"danger_reason,omitempty"`
}

// Auth holds the SPF / DKIM / DMARC results from Authentication-Results.
type Auth struct {
	SPF   string `json:"spf,omitempty"`
	DKIM  string `json:"dkim,omitempty"`
	DMARC string `json:"dmarc,omitempty"`
}

// Result is the email triage.
type Result struct {
	Format string `json:"format"`

	From          string `json:"from,omitempty"`
	FromAddr      string `json:"from_address,omitempty"`
	FromDomain    string `json:"from_domain,omitempty"`
	To            string `json:"to,omitempty"`
	Subject       string `json:"subject,omitempty"`
	Date          string `json:"date,omitempty"`
	MessageID     string `json:"message_id,omitempty"`
	ReplyTo       string `json:"reply_to,omitempty"`
	ReplyToDomain string `json:"reply_to_domain,omitempty"`
	ReturnPath    string `json:"return_path,omitempty"`
	XMailer       string `json:"x_mailer,omitempty"`
	ReceivedHops  int    `json:"received_hops"`

	Auth        Auth         `json:"auth"`
	Attachments []Attachment `json:"attachments,omitempty"`
	URLs        []string     `json:"urls,omitempty"`

	ReplyToMismatch    bool     `json:"reply_to_mismatch"`
	ReturnPathMismatch bool     `json:"return_path_mismatch"`
	Suspicious         bool     `json:"suspicious"`
	SuspiciousReasons  []string `json:"suspicious_reasons,omitempty"`
	Note               string   `json:"note"`
}

// Decode triages a raw email message.
func Decode(raw []byte) (*Result, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	h := msg.Header
	res := &Result{
		Format:       "email",
		From:         decodeWord(h.Get("From")),
		To:           decodeWord(h.Get("To")),
		Subject:      decodeWord(h.Get("Subject")),
		Date:         h.Get("Date"),
		MessageID:    strings.Trim(h.Get("Message-ID"), "<>"),
		ReplyTo:      decodeWord(h.Get("Reply-To")),
		ReturnPath:   strings.Trim(h.Get("Return-Path"), "<>"),
		XMailer:      h.Get("X-Mailer"),
		ReceivedHops: len(h["Received"]),
	}
	res.FromAddr, res.FromDomain = addrDomain(h.Get("From"))
	_, res.ReplyToDomain = addrDomain(h.Get("Reply-To"))
	res.Auth = parseAuth(h.Get("Authentication-Results"))

	// Body walk.
	collectBody(msg.Header.Get("Content-Type"), msg.Body, res, 0)
	res.URLs = uniqueSorted(res.URLs)

	res.evaluate()
	return res, nil
}

// collectBody walks a (possibly multipart) body, collecting attachments and URLs.
func collectBody(contentType string, body io.Reader, res *Result, depth int) {
	if depth > maxDepth {
		return
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "text/plain"
	}
	if strings.HasPrefix(mediaType, "multipart/") && params["boundary"] != "" {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			handlePart(part, res, depth)
		}
	}
	// Single text part: scan for URLs.
	if strings.HasPrefix(mediaType, "text/") {
		data, _ := io.ReadAll(io.LimitReader(body, maxAttachmentBytes))
		res.URLs = append(res.URLs, extractURLs(string(data))...)
	}
}

// handlePart processes one MIME part: recurse into nested multiparts, record
// attachments, scan text for URLs.
func handlePart(part *multipart.Part, res *Result, depth int) {
	ct := part.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(ct)
	disp := part.Header.Get("Content-Disposition")
	dispType, _, _ := mime.ParseMediaType(disp)
	filename := part.FileName()

	if strings.HasPrefix(mediaType, "multipart/") {
		collectBody(ct, part, res, depth+1)
		return
	}
	if filename != "" || dispType == "attachment" {
		data, _ := io.ReadAll(io.LimitReader(decodeCTE(part, part.Header.Get("Content-Transfer-Encoding")), maxAttachmentBytes))
		att := Attachment{
			Filename:    decodeWord(filename),
			ContentType: mediaType,
			Disposition: dispType,
			Bytes:       len(data),
		}
		att.Dangerous, att.DangerReason = classifyAttachment(att.Filename)
		res.Attachments = append(res.Attachments, att)
		return
	}
	if strings.HasPrefix(mediaType, "text/") || mediaType == "" {
		data, _ := io.ReadAll(io.LimitReader(part, maxAttachmentBytes))
		res.URLs = append(res.URLs, extractURLs(string(data))...)
	}
}

// dangerExts are executable / script extensions that should never be an email
// attachment from an untrusted sender.
var dangerExts = map[string]bool{ //nolint:gochecknoglobals
	"exe": true, "com": true, "scr": true, "pif": true, "cpl": true, "dll": true,
	"cmd": true, "bat": true, "ps1": true, "vbs": true, "vbe": true, "js": true,
	"jse": true, "wsf": true, "wsh": true, "hta": true, "msi": true, "jar": true,
	"lnk": true, "iso": true, "img": true, "vhd": true,
}

// archiveExts are containers worth inspecting (often wrap the real payload).
var archiveExts = map[string]bool{ //nolint:gochecknoglobals
	"zip": true, "rar": true, "7z": true, "cab": true, "ace": true, "gz": true, "tar": true,
}

var docExts = map[string]bool{ //nolint:gochecknoglobals
	"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true,
	"pptx": true, "txt": true, "jpg": true, "jpeg": true, "png": true, "gif": true, "csv": true,
}

// classifyAttachment flags a dangerous attachment by extension, double-extension,
// or archive container.
func classifyAttachment(name string) (bool, string) {
	parts := strings.Split(strings.ToLower(name), ".")
	if len(parts) < 2 {
		return false, ""
	}
	last := parts[len(parts)-1]
	switch {
	case dangerExts[last]:
		// A decoy document extension before the executable one is the classic ruse.
		if len(parts) >= 3 && docExts[parts[len(parts)-2]] {
			return true, "double extension (." + parts[len(parts)-2] + "." + last + ") — executable disguised as a document"
		}
		return true, "executable / script attachment (." + last + ")"
	case archiveExts[last]:
		return true, "archive (." + last + ") — inspect the contents"
	default:
		return false, ""
	}
}

var urlRE = regexp.MustCompile(`(?i)https?://[^\s"'<>)\]}]+`)
var ipURLRE = regexp.MustCompile(`(?i)^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

func extractURLs(s string) []string {
	return urlRE.FindAllString(s, -1)
}

// authTokenRE pulls "spf=pass", "dkim=fail", "dmarc=none" tokens.
var authTokenRE = regexp.MustCompile(`(?i)\b(spf|dkim|dmarc)\s*=\s*([a-z]+)`)

func parseAuth(s string) Auth {
	var a Auth
	for _, m := range authTokenRE.FindAllStringSubmatch(s, -1) {
		v := strings.ToLower(m[2])
		switch strings.ToLower(m[1]) {
		case "spf":
			a.SPF = v
		case "dkim":
			a.DKIM = v
		case "dmarc":
			a.DMARC = v
		}
	}
	return a
}

// evaluate fills the mismatch / suspicious fields.
func (res *Result) evaluate() {
	var reasons []string
	if res.FromDomain != "" && res.ReplyToDomain != "" && !strings.EqualFold(res.FromDomain, res.ReplyToDomain) {
		res.ReplyToMismatch = true
		reasons = append(reasons, "reply-to domain ("+res.ReplyToDomain+") differs from from domain ("+res.FromDomain+")")
	}
	if res.ReturnPath != "" && res.FromAddr != "" && !strings.EqualFold(domainOf(res.ReturnPath), res.FromDomain) && res.FromDomain != "" {
		res.ReturnPathMismatch = true
		reasons = append(reasons, "return-path domain differs from from domain")
	}
	for _, name := range []struct{ proto, v string }{{"SPF", res.Auth.SPF}, {"DKIM", res.Auth.DKIM}, {"DMARC", res.Auth.DMARC}} {
		if isAuthFail(name.v) {
			reasons = append(reasons, name.proto+"="+name.v)
		}
	}
	for _, a := range res.Attachments {
		if a.Dangerous {
			reasons = append(reasons, "attachment "+a.Filename+": "+a.DangerReason)
		}
	}
	for _, u := range res.URLs {
		if ipURLRE.MatchString(u) {
			reasons = append(reasons, "IP-literal URL: "+u)
		} else if strings.Contains(u, "xn--") {
			reasons = append(reasons, "punycode/IDN URL: "+u)
		}
	}
	if len(reasons) > 0 {
		res.Suspicious = true
		res.SuspiciousReasons = reasons
	}
	res.Note = noteFor(res)
}

func isAuthFail(v string) bool {
	switch strings.ToLower(v) {
	case "fail", "softfail", "permerror", "temperror":
		return true
	default:
		return false
	}
}

func noteFor(res *Result) string {
	base := "Header + MIME triage only — no attachment was opened or executed. "
	if res.Suspicious {
		return base + "SUSPICIOUS phishing indicators: " + strings.Join(res.SuspiciousReasons, "; ") +
			". Decode any attachment further with lnk_decode / pdf_malware_scan / pickle_decode."
	}
	return base + "No strong phishing indicator found — not a guarantee of safety; verify the sender and any links/attachments."
}

// --- helpers --------------------------------------------------------------

// decodeCTE wraps a part reader to undo its Content-Transfer-Encoding so the
// reported byte count is the real decoded size.
func decodeCTE(r io.Reader, enc string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}

func addrDomain(header string) (addr, domain string) {
	a, err := mail.ParseAddress(header)
	if err != nil {
		return "", ""
	}
	return a.Address, domainOf(a.Address)
}

func domainOf(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	return ""
}

func decodeWord(s string) string {
	d := mime.WordDecoder{}
	out, err := d.DecodeHeader(s)
	if err != nil {
		return s
	}
	return out
}

func uniqueSorted(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
